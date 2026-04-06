"""
flow.actions — A generic, YAML-driven flow manipulation engine for mitmproxy.

Usage:
    flow.actions @all ./rules.yaml
    flow.actions @focus ./rules.yaml

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
        replay_search:
          value: { var: [payload_a, canary] }
          condition: "OR"
          in: "body"
          found_mark: ":syringe:"
        only_ids: ["..."]
        exclude_ids: ["..."]
"""

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
# replay_search is intentionally excluded — it always runs last.
# ---------------------------------------------------------------------------
ORDERED_ACTIONS = [
    "replace_params",
    "add_params",
]

# Keys that are NOT actions (metadata / filter keys on the action-group dict)
META_KEYS = {"duplicate", "only_ids", "exclude_ids", "replay_search", *ORDERED_ACTIONS}


class FlowActions:
    """mitmproxy addon: applies YAML-defined action-groups to selected flows."""

    FAIL_MARKER = ":x:"

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
    # Action: replay_search (async — always last)
    # ------------------------------------------------------------------
    async def _action_replay_search(
        self,
        target: http.HTTPFlow,
        config: dict,
        vars_dict: dict[str, str],
    ) -> None:
        """
        Replay the flow and search the response for specific strings.

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

        try:
            handler = ReplayHandler(target, ctx.options)
            await handler.replay()

            # Determine where to search
            haystack = b""
            if search_in == "body":
                if target.response and target.response.content:
                    haystack = target.response.content
            elif search_in == "header":
                if target.response:
                    # Concatenate all header values
                    haystack = b"\r\n".join(
                        f"{k}: {v}".encode()
                        for k, v in target.response.headers.items()
                    )

            # Check matches
            results = [
                sv.encode() in haystack for sv in search_values
            ]

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

        except Exception as e:
            logging.error(f"[flow.actions] Replay error for flow {target.id}: {e}")
            target.marked = self.FAIL_MARKER
            target.comment = f"[flow.actions] Replay error: {e}"

        # Push updated flow to the UI
        ctx.master.addons.trigger(hooks.UpdateHook([target]))

    # ------------------------------------------------------------------
    # Action registry
    # ------------------------------------------------------------------
    def _get_action_handler(self, action_name: str):
        """Look up the handler for a given action name."""
        registry = {
            "replace_params": self._action_replace_params,
            "add_params": self._action_add_params,
            # replay_search is handled separately (async, always last)
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

        # 4. Terminal action: replay_search (always last)
        if "replay_search" in group:
            await self._action_replay_search(
                target, group["replay_search"], vars_dict,
            )

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
    # mitmproxy command
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


addons = [FlowActions()]
