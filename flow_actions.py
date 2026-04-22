"""
flow.actions — A generic, YAML-driven flow manipulation engine for mitmproxy.

Usage:
    flow.actions @all ./rules.yaml
    flow.actions @focus ./rules.yaml

    flow.actions.watch "~u example.com" ./rules.yaml   # auto-apply on matching flows
    flow.actions.stop                                   # stop watching
"""

import asyncio
import logging
from collections.abc import Sequence

import yaml
from mitmproxy import command, ctx, flow, http, types, hooks
from mitmproxy.log import ALERT

from flow_actions_lib.actions import (
    action_replace_params,
    action_add_params,
    action_remove_headers_cookies,
    action_set_headers_cookies,
    action_replay,
    action_search,
    action_find_important_headers_cookies,
    duplicate_flow,
)

ORDERED_ACTIONS = [
    "replace_params",
    "add_params",
    "remove_headers_cookies",
    "set_headers_cookies",
]

FAIL_MARKER = ":x:"


class FlowActions:
    """mitmproxy addon: applies YAML-defined action-groups to selected flows."""

    def __init__(self):
        self._watch_filter: str | None = None
        self._watch_config: dict | None = None
        self._watch_active: bool = False

    @staticmethod
    def _should_run(flow_id: str, group: dict) -> bool:
        only_ids = group.get("only_ids")
        if only_ids is not None:
            return flow_id in only_ids

        exclude_ids = group.get("exclude_ids")
        if exclude_ids is not None:
            return flow_id not in exclude_ids

        return True

    def _get_action_handler(self, action_name: str):
        registry = {
            "replace_params": action_replace_params,
            "add_params": action_add_params,
            "remove_headers_cookies": action_remove_headers_cookies,
            "set_headers_cookies": action_set_headers_cookies,
        }
        return registry.get(action_name)

    async def _apply_action_group(
        self,
        original: http.HTTPFlow,
        group: dict,
        vars_dict: dict[str, str],
    ) -> None:
        if not self._should_run(original.id, group):
            return

        if group.get("duplicate", False):
            target = duplicate_flow(original)
            logging.info(f"[flow.actions] Duplicated flow {original.id} → {target.id}")
        else:
            target = original

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
                    f"[flow.actions] Error in '{action_name}' for flow {target.id}: {e}"
                )
                target.marked = FAIL_MARKER
                target.comment = f"[flow.actions] {action_name} error: {e}"
                ctx.master.addons.trigger(hooks.UpdateHook([target]))
                return

        ctx.master.addons.trigger(hooks.UpdateHook([target]))

        if group.get("replay", False):
            try:
                await action_replay(target)
            except Exception:
                ctx.master.addons.trigger(hooks.UpdateHook([target]))
                return

            ctx.master.addons.trigger(hooks.UpdateHook([target]))

        if "search" in group:
            action_search(target, group["search"], vars_dict)
            ctx.master.addons.trigger(hooks.UpdateHook([target]))

        if "find_important_headers_cookies" in group:
            await action_find_important_headers_cookies(
                target,
                group["find_important_headers_cookies"],
                vars_dict,
            )
            ctx.master.addons.trigger(hooks.UpdateHook([target]))

    async def _run_all(
        self,
        flows: list[http.HTTPFlow],
        config: dict,
    ) -> None:
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

    @staticmethod
    def _load_config(yaml_path: str) -> dict | None:
        try:
            with open(yaml_path, "r") as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logging.error(f"[flow.actions] Failed to load config: {e}")
            return None

        if not isinstance(config, dict) or "action-groups" not in config:
            logging.error("[flow.actions] Invalid config format.")
            return None
        return config

    @command.command("flow.actions")
    @command.argument("flows", type=Sequence[flow.Flow])
    @command.argument("yaml_path", type=types.Path)
    def flow_actions_command(
        self,
        flows: Sequence[flow.Flow],
        yaml_path: types.Path,
    ) -> None:
        if not flows:
            return

        config = self._load_config(str(yaml_path))
        if config is None:
            return

        rule_name = config.get("name", "<unnamed>")
        logging.log(ALERT, f"[flow.actions] Loading rule '{rule_name}'...")

        http_flows = [f for f in flows if isinstance(f, http.HTTPFlow)]
        if not http_flows:
            return

        asyncio.ensure_future(self._run_all(http_flows, config))

    @command.command("flow.actions.watch")
    @command.argument("filter_expr", type=str)
    @command.argument("yaml_path", type=types.Path)
    def flow_actions_watch_command(
        self,
        filter_expr: str,
        yaml_path: types.Path,
    ) -> None:
        config = self._load_config(str(yaml_path))
        if config is None:
            return

        from mitmproxy import flowfilter
        if not flowfilter.parse(filter_expr):
            logging.log(ALERT, f"[flow.actions.watch] Invalid filter: {filter_expr}")
            return

        self._watch_filter = filter_expr
        self._watch_config = config
        self._watch_active = True
        logging.log(ALERT, f"[flow.actions.watch] \u25b6 Watching: {filter_expr}")

    @command.command("flow.actions.stop")
    def flow_actions_stop_command(self) -> None:
        self._watch_active = False
        logging.log(ALERT, "[flow.actions.stop] \u25a0 Stopped watching.")

    def request(self, flow_obj: http.HTTPFlow) -> None:
        if not self._watch_active or not self._watch_config or not self._watch_filter:
            return
        if flow_obj.is_replay:
            return

        from mitmproxy import flowfilter
        compiled = flowfilter.parse(self._watch_filter)
        if compiled and compiled(flow_obj):
            asyncio.ensure_future(self._run_all([flow_obj], self._watch_config))

