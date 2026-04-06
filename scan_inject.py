import logging
import re
import os.path
import uuid
import asyncio
from collections.abc import Sequence
from typing import List, Optional, Tuple, Dict, Union

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy import http
from mitmproxy import types
from mitmproxy import hooks
from mitmproxy.log import ALERT
from mitmproxy.addons.clientplayback import ReplayHandler


class ScanInject:
    XSS_MARKER = ":syringe:"
    FAIL_MARKER = ":x:"

    def __init__(self):
        self.replayed_flows_data: List[Tuple[str, bool, Optional[str]]] = []

    def _parse_param_value_payload(self, payload_input: str) -> Dict[str, str]:
        """Parses "default=val1 param1=val2" → dict."""
        parts = re.split(r"\s+|\n", payload_input)
        parsed_data = {}
        for part in parts:
            if not part:
                continue
            if "=" in part:
                key, value = part.split("=", 1)
                parsed_data[key.strip()] = value.strip()
            else:
                raise ValueError(f"Invalid parameter=value format: {part}")
        return parsed_data

    def _inject_xss_payload(
        self, flow: http.HTTPFlow, payload: Union[str, Dict[str, str]]
    ) -> None:
        has_query_params = bool(flow.request.query)
        has_form_data = (
            flow.request.method == "POST"
            and "application/x-www-form-urlencoded" in flow.request.headers.get("content-type", "")
        )

        if not has_query_params and not has_form_data:
            raise ValueError(
                f"Flow {flow.id} has no query parameters or form data for XSS injection."
            )

        if isinstance(payload, str):
            # Inject into query parameters
            if has_query_params:
                first_param = next(iter(flow.request.query.keys()), None)
                if first_param:
                    flow.request.query[first_param] = payload
                logging.info(f"Injected '{payload}' into query params of {flow.id}")

            # Inject into form data
            if has_form_data:
                form_data = flow.request.urlencoded_form
                first_form_param = next(iter(form_data.keys()), None)
                if first_form_param:
                    form_data[first_form_param] = payload
                    flow.request.urlencoded_form = form_data
                logging.info(f"Injected '{payload}' into form data of {flow.id}")

        elif isinstance(payload, dict):
            # Inject into query parameters
            if has_query_params:
                for param_name in list(flow.request.query.keys()):
                    if param_name in payload:
                        flow.request.query[param_name] = payload[param_name]
                logging.info(f"Injected custom XSS payload into query params of {flow.id}")

            # Inject into form data
            if has_form_data:
                form_data = flow.request.urlencoded_form
                for param_name in list(form_data.keys()):
                    if param_name in payload:
                        form_data[param_name] = payload[param_name]
                flow.request.urlencoded_form = form_data
                logging.info(f"Injected custom XSS payload into form data of {flow.id}")


    def _resolve_payload(
        self, payload_input: types.Path
    ) -> Optional[Union[str, Dict[str, str]]]:
        if os.path.isfile(payload_input):
            try:
                with open(payload_input, "r") as f:
                    payload_content = f.read()
                logging.info(f"Loaded payload from file: {payload_input}")
            except OSError as e:
                logging.error(f"Could not read payload file {payload_input}: {e}")
                return None
        else:
            payload_content = str(payload_input)

        if "=" in payload_content:
            try:
                return self._parse_param_value_payload(payload_content)
            except ValueError as e:
                logging.error(f"Invalid multi-parameter payload format: {e}")
                return None

        return payload_content

    async def _replay_and_check(self, duplicated_flow: http.HTTPFlow) -> None:
        """
        Replay a single prepared flow via ReplayHandler, then immediately
        inspect the response for the XSS check string.
        No response hook needed — we wait right here.
        """
        check_string = ctx.options.scaninject_xss_check_string.encode()

        try:
            handler = ReplayHandler(duplicated_flow, ctx.options)
            await handler.replay()  # ← blocks until response arrives

            content_len = (
                len(duplicated_flow.response.content)
                if duplicated_flow.response and duplicated_flow.response.content
                else 0
            )
            logging.info(
                f"Response content length for {duplicated_flow.id}: {content_len}"
            )

            if (
                duplicated_flow.response
                and duplicated_flow.response.content
                and check_string in duplicated_flow.response.content
            ):
                duplicated_flow.marked = self.XSS_MARKER
                duplicated_flow.comment = "Potential XSS detected!"
                logging.log(
                    ALERT,
                    f"Potential XSS detected in replayed flow {duplicated_flow.id}!",
                )
            else:
                duplicated_flow.marked = self.FAIL_MARKER
                duplicated_flow.comment = "No XSS found with current check string."
                logging.info(f"No XSS detected in replayed flow {duplicated_flow.id}.")

        except Exception as e:
            logging.error(f"Replay error for flow {duplicated_flow.id}: {e}")
            duplicated_flow.marked = self.FAIL_MARKER
            duplicated_flow.comment = f"Replay error: {e}"

        # Push updated flow to the UI regardless of outcome
        ctx.master.addons.trigger(hooks.UpdateHook([duplicated_flow]))

    async def _replay_all(self, flows_to_replay: List[http.HTTPFlow]) -> None:
        """
        Fire off all replays concurrently and wait for every one to finish.
        Exceptions inside individual tasks are caught in _replay_and_check,
        but return_exceptions=True is a safety net so one failure can't cancel others.
        """
        await asyncio.gather(
            *(self._replay_and_check(f) for f in flows_to_replay),
            return_exceptions=True,
        )
        logging.log(
            ALERT,
            f"Scan complete — {len(flows_to_replay)} flow(s) processed.",
        )

    def load(self, loader):
        loader.add_option(
            name="scaninject_xss_check_string",
            typespec=str,
            default="alert(1)",
            help="String to look for in response bodies to confirm XSS payload execution.",
        )

    @command.command("scan.inject.types")
    def injection_types(self) -> Sequence[str]:
        return ["xss", "open-redirect", "crlf"]

    @command.command("scan.inject")
    @command.argument("flows", type=Sequence[flow.Flow])
    @command.argument("injection_type", type=types.Choice("scan.inject.types"))
    @command.argument("payload_input", type=types.Path)
    def scan_inject_command(
        self,
        flows: Sequence[flow.Flow],
        injection_type: str,
        payload_input: types.Path,
    ) -> None:
        """
        Scans and injects payloads into selected flows.

        Usage: scan.inject @all xss "alert(1)"
               scan.inject @focus xss "default=evil_value param1=payload_for_param1"
               scan.inject @url:example.com crlf "new_header: injected_value"
               scan.inject @all xss ./xss_payload.txt
        """
        if not flows:
            logging.log(ALERT, "No flows selected for injection.")
            return

        payload = self._resolve_payload(payload_input)
        if payload is None:
            return

        logging.log(
            ALERT,
            f"Starting {injection_type.upper()} injection scan on {len(flows)} flow(s)...",
        )

        flows_to_replay: List[http.HTTPFlow] = []

        for original_flow in flows:
            if not isinstance(original_flow, http.HTTPFlow):
                logging.warning(
                    f"Skipping non-HTTP flow {original_flow.id} for injection."
                )
                continue

            duplicated_flow = original_flow.copy()
            duplicated_flow.id = str(uuid.uuid4())
            duplicated_flow.is_replay = "request"

            try:
                if injection_type == "xss":
                    self._inject_xss_payload(duplicated_flow, payload)
                else:
                    logging.error(f"Unsupported injection type: {injection_type}")
                    continue

                flows_to_replay.append(duplicated_flow)
                # Show the prepared (not-yet-replayed) flow in the UI immediately
                ctx.master.addons.trigger(hooks.UpdateHook([duplicated_flow]))

            except Exception as e:
                logging.error(
                    f"Error preparing flow {original_flow.id} for injection: {e}"
                )
                original_flow.marked = self.FAIL_MARKER
                original_flow.comment = f"Scan failed during preparation: {e}"
                ctx.master.addons.trigger(hooks.UpdateHook([original_flow]))

        if flows_to_replay:
            # Schedule async work on the running event loop without blocking
            # the command handler.  Results arrive as _replay_and_check finishes.
            asyncio.ensure_future(self._replay_all(flows_to_replay))

        logging.log(
            ALERT,
            "Injection process initiated. Results will be marked as responses come in.",
        )


addons = [ScanInject()]
