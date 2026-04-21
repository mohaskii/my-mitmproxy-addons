"""
flow.actions — A generic, YAML-driven flow manipulation engine for mitmproxy.

Usage:
    flow.actions @all ./rules.yaml
    flow.actions @focus ./rules.yaml

    flow.actions.watch "~u example.com" ./rules.yaml   # auto-apply on matching flows
    flow.actions.stop                                   # stop watching

YAML schema:
    name: "rule-name"
    description: "..."
    vars:
      payload_a: "<script>alert(1)</script>"
      canary: "lolo"
    action-groups:
      - duplicate: true
        replace_params:
          fallback_payload:
            value: { var: payload_a }
            all: true
          param1: { var: canary }
          user_id: "literal_string"
        add_params:
          new_key: { var: payload_a }
        replay: true
        search:
          value: { var: [payload_a, canary] }
          condition: "OR"
          in: "body"
          found_mark: ":syringe:"
        find_important_headers_cookies:
          scope: "both"          # "headers" | "cookies" | "both"
          output: "./important_headers_cookies.json"
        only_ids: ["..."]
        exclude_ids: ["..."]
"""

import json
import logging
import uuid
import asyncio
from collections.abc import Sequence
from typing import Any

import yaml

from mitmproxy import command, ctx, flow, http, types, hooks
from mitmproxy.log import ALERT
from mitmproxy.addons.clientplayback import ReplayHandler


# ---------------------------------------------------------------------------
# Execution order for actions within a group.
# replay is now a standalone action, search runs after replay,
# find_important_headers_cookies is a terminal action.
# ---------------------------------------------------------------------------
ORDERED_ACTIONS = [
    "replace_params",
    "add_params",
]

# Terminal actions that run after ORDERED_ACTIONS + replay, in this order:
TERMINAL_ACTIONS = ["search", "find_important_headers_cookies"]

# Keys that are NOT regular actions (metadata / filter / terminal keys)
META_KEYS = {
    "duplicate", "only_ids", "exclude_ids",
    "replay", "search", "find_important_headers_cookies",
    *ORDERED_ACTIONS,
}


class FlowActions:
    """mitmproxy addon: applies YAML-defined action-groups to selected flows."""

    FAIL_MARKER = ":x:"

    def __init__(self):
        self._watch_filter: str | None = None
        self._watch_config: dict | None = None
        self._watch_active: bool = False

    # ------------------------------------------------------------------
    # Variable resolver
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve(value: Any, vars_dict: dict[str, str]) -> list[str]:
        """
        Resolve a value to a list of strings.

        Handles:
            "literal"             → ["literal"]
            { var: "name" }       → [vars_dict["name"]]
            { var: ["a", "b"] }   → [vars_dict["a"], vars_dict["b"]]
        """
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict) and "var" in value:
            ref = value["var"]
            if isinstance(ref, list):
                resolved = []
                for v in ref:
                    if v not in vars_dict:
                        raise KeyError(f"Variable '{v}' not found in vars")
                    resolved.append(vars_dict[v])
                return resolved
            if ref not in vars_dict:
                raise KeyError(f"Variable '{ref}' not found in vars")
            return [vars_dict[ref]]
        # Fallback: coerce to string
        return [str(value)]

    @staticmethod
    def _resolve_single(value: Any, vars_dict: dict[str, str]) -> str:
        """Convenience: resolve to a single string (takes the first value)."""
        return FlowActions._resolve(value, vars_dict)[0]

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------
    @staticmethod
    def _should_run(flow_id: str, group: dict) -> bool:
        """
        Check only_ids / exclude_ids filters.
        If only_ids is set, exclude_ids is ignored.
        """
        only_ids = group.get("only_ids")
        if only_ids is not None:
            return flow_id in only_ids

        exclude_ids = group.get("exclude_ids")
        if exclude_ids is not None:
            return flow_id not in exclude_ids

        return True

    # ------------------------------------------------------------------
    # Flow duplication
    # ------------------------------------------------------------------
    @staticmethod
    def _duplicate_flow(original: http.HTTPFlow) -> http.HTTPFlow:
        """Create a copy of the flow with a fresh UUID."""
        dup = original.copy()
        dup.id = str(uuid.uuid4())
        dup.is_replay = "request"
        return dup

    # ------------------------------------------------------------------
    # Action: replace_params
    # ------------------------------------------------------------------
    def _action_replace_params(
        self,
        target: http.HTTPFlow,
        config: dict,
        vars_dict: dict[str, str],
    ) -> None:
        """
        Replace existing parameter values in query string and form data.

        Config keys:
            fallback_payload:
                value: <var-ref or literal>
                all: true|false (default false)
            <param_name>: <var-ref or literal>
        """
        fallback_cfg = config.get("fallback_payload")
        fallback_value: str | None = None
        replace_all = False

        if fallback_cfg is not None and isinstance(fallback_cfg, dict):
            fb_val = fallback_cfg.get("value")
            if fb_val is not None:
                fallback_value = self._resolve_single(fb_val, vars_dict)
            replace_all = fallback_cfg.get("all", False)

        # Build a map of explicitly named params → resolved values
        explicit: dict[str, str] = {}
        for key, val in config.items():
            if key == "fallback_payload":
                continue
            explicit[key] = self._resolve_single(val, vars_dict)

        # --- Apply to query params ---
        self._replace_in_multidict(
            target, "query", explicit, fallback_value, replace_all,
        )

        # --- Apply to form data ---
        if (
            target.request.method == "POST"
            and "application/x-www-form-urlencoded"
            in target.request.headers.get("content-type", "")
        ):
            self._replace_in_multidict(
                target, "form", explicit, fallback_value, replace_all,
            )

    def _replace_in_multidict(
        self,
        target: http.HTTPFlow,
        source: str,  # "query" or "form"
        explicit: dict[str, str],
        fallback_value: str | None,
        replace_all: bool,
    ) -> None:
        """
        Shared logic for replacing params in query or form data.
        """
        if source == "query":
            params = target.request.query
        else:
            params = target.request.urlencoded_form

        if not params:
            return

        fallback_applied = False

        for key in list(params.keys()):
            if key in explicit:
                params[key] = explicit[key]
            elif fallback_value is not None:
                if replace_all or not fallback_applied:
                    params[key] = fallback_value
                    fallback_applied = True

        # Write back
        if source == "query":
            target.request.query = params
        else:
            target.request.urlencoded_form = params

    # ------------------------------------------------------------------
    # Action: add_params
    # ------------------------------------------------------------------
    def _action_add_params(
        self,
        target: http.HTTPFlow,
        config: dict,
        vars_dict: dict[str, str],
    ) -> None:
        """
        Add new key-value pairs to the request parameters.

        Config:
            <key>: <var-ref or literal>
        """
        has_query = bool(target.request.query)
        has_form = (
            target.request.method == "POST"
            and "application/x-www-form-urlencoded"
            in target.request.headers.get("content-type", "")
        )

        for key, val in config.items():
            resolved = self._resolve_single(val, vars_dict)

            if has_query:
                query = target.request.query
                query.add(key, resolved)
                target.request.query = query

            if has_form:
                form = target.request.urlencoded_form
                form.add(key, resolved)
                target.request.urlencoded_form = form

            # If the request has neither, add to query string by default
            if not has_query and not has_form:
                query = target.request.query
                query.add(key, resolved)
                target.request.query = query

    # ------------------------------------------------------------------
    # Action: replay (standalone replay, no search)
    # ------------------------------------------------------------------
    async def _action_replay(
        self,
        target: http.HTTPFlow,
    ) -> None:
        """
        Replay the flow request. This is a standalone action that just
        replays and waits for the response. Search can run after.
        """
        try:
            handler = ReplayHandler(target, ctx.options)
            await handler.replay()
            logging.info(
                f"[flow.actions] Replayed flow {target.id} — "
                f"status {target.response.status_code if target.response else 'N/A'}"
            )
        except Exception as e:
            logging.error(f"[flow.actions] Replay error for flow {target.id}: {e}")
            target.marked = self.FAIL_MARKER
            target.comment = f"[flow.actions] Replay error: {e}"
            raise  # Propagate so callers can abort

    # ------------------------------------------------------------------
    # Action: search (post-replay response search)
    # ------------------------------------------------------------------
    def _action_search(
        self,
        target: http.HTTPFlow,
        config: dict,
        vars_dict: dict[str, str],
    ) -> None:
        """
        Search the response for specific strings. Runs AFTER replay.

        Config:
            value: <var-ref, literal, or array-ref>
            condition: "OR" (default) | "AND"
            in: "body" | "header"
            found_mark: ":syringe:"
        """
        search_values = self._resolve(config.get("value", ""), vars_dict)
        condition = config.get("condition", "OR").upper()
        search_in = config.get("in", "body").lower()
        found_mark = config.get("found_mark", ":syringe:")

        # Determine where to search
        haystack = b""
        if search_in == "body":
            if target.response and target.response.content:
                haystack = target.response.content
        elif search_in == "header":
            if target.response:
                haystack = b"\r\n".join(
                    f"{k}: {v}".encode()
                    for k, v in target.response.headers.items()
                )

        # Check matches
        results = [sv.encode() in haystack for sv in search_values]

        if condition == "AND":
            matched = all(results) and len(results) > 0
        else:  # OR (default)
            matched = any(results)

        if matched:
            target.marked = found_mark
            target.comment = (
                f"[flow.actions] Match found ({condition}: "
                f"{', '.join(repr(v) for v in search_values)})"
            )
            logging.log(
                ALERT,
                f"[flow.actions] ✓ Match in flow {target.id} "
                f"({condition}: {search_values})",
            )
        else:
            target.marked = self.FAIL_MARKER
            target.comment = (
                f"[flow.actions] No match ({condition}: "
                f"{', '.join(repr(v) for v in search_values)})"
            )
            logging.info(
                f"[flow.actions] ✗ No match in flow {target.id} "
                f"({condition}: {search_values})",
            )

    # ------------------------------------------------------------------
    # Action: find_important_headers_cookies
    # ------------------------------------------------------------------
    async def _action_find_important_headers_cookies(
        self,
        target: http.HTTPFlow,
        config: dict,
        vars_dict: dict[str, str],
    ) -> None:
        """
        Identify which headers and cookies are essential for the request.

        For each header/cookie:
          1. Copy the flow
          2. Remove that single header or cookie
          3. Replay the request
          4. Compare response status & body to the original
          5. If different → the header/cookie is important

        Config:
            scope: "headers" | "cookies" | "both" (default: "both")
            output: "./important_results.json"  (optional, logs if omitted)
        """
        scope = config.get("scope", "both").lower()
        output_path = config.get("output")

        # We need a baseline response — replay the original first if needed
        if target.response is None:
            try:
                await self._action_replay(target)
            except Exception:
                return

        if target.response is None:
            logging.error(
                f"[flow.actions] Cannot find important headers/cookies: "
                f"no response for flow {target.id}"
            )
            return

        baseline_status = target.response.status_code
        baseline_body = target.response.content or b""

        important_headers: list[str] = []
        important_cookies: list[str] = []
        unimportant_headers: list[str] = []
        unimportant_cookies: list[str] = []

        # --- Check headers ---
        if scope in ("headers", "both"):
            # Collect all request headers (skip pseudo-headers and host)
            skip_headers = {"host", "content-length", "transfer-encoding"}
            headers_to_test = [
                (k, v) for k, v in target.request.headers.items()
                if k.lower() not in skip_headers
            ]

            for header_name, header_value in headers_to_test:
                probe = self._duplicate_flow(target)
                # Remove this specific header
                if header_name in probe.request.headers:
                    del probe.request.headers[header_name]

                try:
                    handler = ReplayHandler(probe, ctx.options)
                    await handler.replay()
                except Exception as e:
                    logging.warning(
                        f"[flow.actions] Replay failed without header "
                        f"'{header_name}': {e}"
                    )
                    important_headers.append(header_name)
                    continue

                probe_status = probe.response.status_code if probe.response else None
                probe_body = (probe.response.content or b"") if probe.response else b""

                if probe_status != baseline_status or probe_body != baseline_body:
                    important_headers.append(header_name)
                    logging.info(
                        f"[flow.actions] ★ Header '{header_name}' is IMPORTANT "
                        f"(status: {baseline_status}→{probe_status})"
                    )
                else:
                    unimportant_headers.append(header_name)
                    logging.info(
                        f"[flow.actions] · Header '{header_name}' is not important"
                    )

        # --- Check cookies ---
        if scope in ("cookies", "both"):
            cookie_header = target.request.headers.get("cookie", "")
            cookies = {}
            if cookie_header:
                for part in cookie_header.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        cookies[k.strip()] = v.strip()

            for cookie_name in list(cookies.keys()):
                probe = self._duplicate_flow(target)
                # Rebuild cookie header without this cookie
                remaining = {
                    k: v for k, v in cookies.items() if k != cookie_name
                }
                if remaining:
                    probe.request.headers["cookie"] = "; ".join(
                        f"{k}={v}" for k, v in remaining.items()
                    )
                else:
                    if "cookie" in probe.request.headers:
                        del probe.request.headers["cookie"]

                try:
                    handler = ReplayHandler(probe, ctx.options)
                    await handler.replay()
                except Exception as e:
                    logging.warning(
                        f"[flow.actions] Replay failed without cookie "
                        f"'{cookie_name}': {e}"
                    )
                    important_cookies.append(cookie_name)
                    continue

                probe_status = probe.response.status_code if probe.response else None
                probe_body = (probe.response.content or b"") if probe.response else b""

                if probe_status != baseline_status or probe_body != baseline_body:
                    important_cookies.append(cookie_name)
                    logging.info(
                        f"[flow.actions] ★ Cookie '{cookie_name}' is IMPORTANT "
                        f"(status: {baseline_status}→{probe_status})"
                    )
                else:
                    unimportant_cookies.append(cookie_name)
                    logging.info(
                        f"[flow.actions] · Cookie '{cookie_name}' is not important"
                    )

        # --- Build results ---
        results = {
            "flow_id": target.id,
            "url": target.request.pretty_url,
            "baseline_status": baseline_status,
            "important_headers": important_headers,
            "unimportant_headers": unimportant_headers,
            "important_cookies": important_cookies,
            "unimportant_cookies": unimportant_cookies,
        }

        # --- Output ---
        summary = (
            f"[flow.actions] Important headers/cookies for {target.request.pretty_url}:\n"
            f"  Headers: {important_headers or '(none)'}\n"
            f"  Cookies: {important_cookies or '(none)'}"
        )
        logging.log(ALERT, summary)

        target.comment = (
            f"[flow.actions] Important — "
            f"H: {important_headers}, C: {important_cookies}"
        )

        if output_path:
            try:
                with open(output_path, "w") as f:
                    json.dump(results, f, indent=2)
                logging.log(
                    ALERT,
                    f"[flow.actions] Results saved to {output_path}",
                )
            except Exception as e:
                logging.error(
                    f"[flow.actions] Failed to write results to "
                    f"{output_path}: {e}"
                )

    # ------------------------------------------------------------------
    # Action registry
    # ------------------------------------------------------------------
    def _get_action_handler(self, action_name: str):
        """Look up the handler for a given action name."""
        registry = {
            "replace_params": self._action_replace_params,
            "add_params": self._action_add_params,
            # replay, search, and find_important_headers_cookies
            # are handled separately in the pipeline
        }
        return registry.get(action_name)

    # ------------------------------------------------------------------
    # Core: apply a single action-group to a single flow
    # ------------------------------------------------------------------
    async def _apply_action_group(
        self,
        original: http.HTTPFlow,
        group: dict,
        vars_dict: dict[str, str],
    ) -> None:
        """Execute all actions in a group against a single flow."""
        # 1. Filter check
        if not self._should_run(original.id, group):
            return

        # 2. Duplicate check
        if group.get("duplicate", False):
            target = self._duplicate_flow(original)
            logging.info(
                f"[flow.actions] Duplicated flow {original.id} → {target.id}"
            )
        else:
            target = original

        # 3. Execute ordered (synchronous) actions
        for action_name in ORDERED_ACTIONS:
            if action_name not in group:
                continue
            handler = self._get_action_handler(action_name)
            if handler is None:
                logging.warning(
                    f"[flow.actions] Unknown action '{action_name}', skipping."
                )
                continue
            try:
                handler(target, group[action_name], vars_dict)
                logging.info(
                    f"[flow.actions] Applied '{action_name}' to flow {target.id}"
                )
            except Exception as e:
                logging.error(
                    f"[flow.actions] Error in '{action_name}' for flow "
                    f"{target.id}: {e}"
                )
                target.marked = self.FAIL_MARKER
                target.comment = f"[flow.actions] {action_name} error: {e}"
                ctx.master.addons.trigger(hooks.UpdateHook([target]))
                return  # Abort this group for this flow

        # Show the modified flow in the UI before replay
        ctx.master.addons.trigger(hooks.UpdateHook([target]))

        # 4. Replay (if requested) — runs after all param actions
        if group.get("replay", False):
            try:
                await self._action_replay(target)
            except Exception:
                ctx.master.addons.trigger(hooks.UpdateHook([target]))
                return  # Abort on replay failure

            ctx.master.addons.trigger(hooks.UpdateHook([target]))

        # 5. Search (runs after replay, only searches — no replay)
        if "search" in group:
            self._action_search(target, group["search"], vars_dict)
            ctx.master.addons.trigger(hooks.UpdateHook([target]))

        # 6. find_important_headers_cookies (terminal, does its own replays)
        if "find_important_headers_cookies" in group:
            await self._action_find_important_headers_cookies(
                target, group["find_important_headers_cookies"], vars_dict,
            )
            ctx.master.addons.trigger(hooks.UpdateHook([target]))

    # ------------------------------------------------------------------
    # Core: process all flows × all action-groups
    # ------------------------------------------------------------------
    async def _run_all(
        self,
        flows: list[http.HTTPFlow],
        config: dict,
    ) -> None:
        """Iterate flows × action-groups and apply each group."""
        vars_dict = config.get("vars", {})
        groups = config.get("action-groups", [])

        if not groups:
            logging.log(ALERT, "[flow.actions] No action-groups defined in config.")
            return

        total_groups = len(groups)
        total_flows = len(flows)

        logging.log(
            ALERT,
            f"[flow.actions] Running {total_groups} action-group(s) "
            f"on {total_flows} flow(s)...",
        )

        for flow_obj in flows:
            for group_idx, group in enumerate(groups):
                try:
                    await self._apply_action_group(flow_obj, group, vars_dict)
                except Exception as e:
                    logging.error(
                        f"[flow.actions] Unexpected error in group #{group_idx} "
                        f"for flow {flow_obj.id}: {e}"
                    )

        logging.log(
            ALERT,
            f"[flow.actions] Complete — processed {total_flows} flow(s) "
            f"across {total_groups} group(s).",
        )

    # ------------------------------------------------------------------
    # YAML loader
    # ------------------------------------------------------------------
    @staticmethod
    def _load_config(yaml_path: str) -> dict | None:
        """Load and validate a YAML configuration file."""
        try:
            with open(yaml_path, "r") as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            logging.error(f"[flow.actions] Config file not found: {yaml_path}")
            return None
        except yaml.YAMLError as e:
            logging.error(f"[flow.actions] Invalid YAML in {yaml_path}: {e}")
            return None

        if not isinstance(config, dict):
            logging.error("[flow.actions] Config must be a YAML mapping (dict).")
            return None

        if "action-groups" not in config:
            logging.error("[flow.actions] Config missing required 'action-groups' key.")
            return None

        if not isinstance(config["action-groups"], list):
            logging.error("[flow.actions] 'action-groups' must be a list.")
            return None

        return config

    # ------------------------------------------------------------------
    # mitmproxy command: flow.actions (manual, flow-based)
    # ------------------------------------------------------------------
    @command.command("flow.actions")
    @command.argument("flows", type=Sequence[flow.Flow])
    @command.argument("yaml_path", type=types.Path)
    def flow_actions_command(
        self,
        flows: Sequence[flow.Flow],
        yaml_path: types.Path,
    ) -> None:
        """
        Apply YAML-defined action-groups to selected flows.

        Usage:
            flow.actions @all ./rules.yaml
            flow.actions @focus ./rules.yaml
        """
        if not flows:
            logging.log(ALERT, "[flow.actions] No flows selected.")
            return

        config = self._load_config(str(yaml_path))
        if config is None:
            return

        rule_name = config.get("name", "<unnamed>")
        logging.log(
            ALERT,
            f"[flow.actions] Loading rule '{rule_name}' "
            f"for {len(flows)} flow(s)...",
        )

        # Filter to HTTP flows only
        http_flows: list[http.HTTPFlow] = []
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                http_flows.append(f)
            else:
                logging.warning(
                    f"[flow.actions] Skipping non-HTTP flow {f.id}"
                )

        if not http_flows:
            logging.log(ALERT, "[flow.actions] No HTTP flows to process.")
            return

        # Schedule the async pipeline
        asyncio.ensure_future(self._run_all(http_flows, config))

        logging.log(
            ALERT,
            "[flow.actions] Pipeline initiated. "
            "Results will appear as actions complete.",
        )

    # ------------------------------------------------------------------
    # mitmproxy command: flow.actions.watch (auto-apply on incoming flows)
    # ------------------------------------------------------------------
    @command.command("flow.actions.watch")
    @command.argument("filter_expr", type=str)
    @command.argument("yaml_path", type=types.Path)
    def flow_actions_watch_command(
        self,
        filter_expr: str,
        yaml_path: types.Path,
    ) -> None:
        """
        Watch incoming flows matching filter and auto-apply YAML rules.

        Usage:
            flow.actions.watch "~u example.com" ./rules.yaml
            flow.actions.watch "~m POST & ~u /api" ./rules.yaml
        """
        config = self._load_config(str(yaml_path))
        if config is None:
            return

        # Validate the filter expression
        from mitmproxy import flowfilter
        compiled = flowfilter.parse(filter_expr)
        if compiled is None:
            logging.log(
                ALERT,
                f"[flow.actions.watch] Invalid filter expression: {filter_expr}",
            )
            return

        self._watch_filter = filter_expr
        self._watch_config = config
        self._watch_active = True

        rule_name = config.get("name", "<unnamed>")
        logging.log(
            ALERT,
            f"[flow.actions.watch] ▶ Watching — filter='{filter_expr}', "
            f"rule='{rule_name}'. Use flow.actions.stop to disable.",
        )

    @command.command("flow.actions.stop")
    def flow_actions_stop_command(self) -> None:
        """
        Stop watching for incoming flows.

        Usage:
            flow.actions.stop
        """
        if not self._watch_active:
            logging.log(ALERT, "[flow.actions.stop] No active watch to stop.")
            return

        old_filter = self._watch_filter
        self._watch_filter = None
        self._watch_config = None
        self._watch_active = False

        logging.log(
            ALERT,
            f"[flow.actions.stop] ■ Stopped watching (was: '{old_filter}').",
        )

    # ------------------------------------------------------------------
    # Hook: request — auto-apply rules on matching incoming flows
    # ------------------------------------------------------------------
    def request(self, flow_obj: http.HTTPFlow) -> None:
        """
        mitmproxy hook: called for every incoming request.
        If watch is active and the flow matches the filter, apply the rules.
        """
        if not self._watch_active or self._watch_config is None:
            return

        # Skip replayed flows to avoid infinite loops
        if flow_obj.is_replay:
            return

        from mitmproxy import flowfilter
        compiled = flowfilter.parse(self._watch_filter)
        if compiled is None:
            return

        if not compiled(flow_obj):
            return

        rule_name = self._watch_config.get("name", "<unnamed>")
        logging.info(
            f"[flow.actions.watch] Auto-applying rule '{rule_name}' "
            f"to flow {flow_obj.id} ({flow_obj.request.pretty_url})"
        )

        asyncio.ensure_future(
            self._run_all([flow_obj], self._watch_config)
        )


addons = [FlowActions()]
