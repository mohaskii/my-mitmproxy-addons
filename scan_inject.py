import logging
import re
import os.path
import uuid
from collections.abc import Sequence
from typing import List, Optional, Tuple, Dict, Union, cast
import time

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy import http
from mitmproxy import types
from mitmproxy import hooks
from mitmproxy.log import ALERT
from mitmproxy.utils import emoji

from mitmproxy.tools.web.master import WebMaster


class ScanInject:
    XSS_MARKER = ":syringe:"
    FAIL_MARKER = ":x:"
    flows_to_replay: list[http.HTTPFlow] = []

    def __init__(self):
        self.replayed_flows_data: List[Tuple[str, bool, Optional[str]]] = []

    def _parse_param_value_payload(self, payload_input: str) -> Dict[str, str]:
        """Parses a string like "default=val1 param1=val2" into a dictionary."""
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
    ):
        """
        Injects the XSS payload into the flow's query parameters.
        Raises an error if the flow has no query parameters.
        """
        if not flow.request.query:
            raise ValueError(
                f"Flow {flow.id} has no query parameters for XSS injection."
            )

        if isinstance(payload, str):
            for param_name in flow.request.query.keys():
                flow.request.query[param_name] = payload
            logging.info(f"Injected '{payload}' into all query params of {flow.id}")
        elif isinstance(payload, dict):
            for param_name in list(flow.request.query.keys()):
                if param_name in payload:
                    flow.request.query[param_name] = payload[param_name]
            logging.info(f"Injected custom XSS payload into query params of {flow.id}")

    def _resolve_payload(
        self, payload_input: types.Path
    ) -> Optional[Union[str, Dict[str, str]]]:
        """
        Resolves a payload from either a file path or a raw string input.
        If the content contains '=' assignments, it is parsed into a dict.
        Returns None on error.
        """
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

    def response(self, flow: http.HTTPFlow):
        """
        This hook is triggered when a response for a flow is received.
        We use it to check the replayed flows for XSS confirmation.
        """
        if flow.is_replay == "request":
            check_string = ctx.options.scaninject_xss_check_string.encode()
            logging.log(ALERT, f"Potential XSS detected in replayed flow {flow.id}!")
            logging.info(
                f"Response content length: {len(flow.response.content) if flow.response and flow.response.content else 0}"
            )
            if (
                flow.response
                and flow.response.content
                and check_string in flow.response.content
            ):
                flow.marked = self.XSS_MARKER
                flow.comment = "Potential XSS detected!"
                logging.log(
                    ALERT, f"Potential XSS detected in replayed flow {flow.id}!"
                )
            else:
                flow.marked = self.FAIL_MARKER
                flow.comment = "No XSS found with current check string."
                logging.info(f"No XSS detected in replayed flow {flow.id}.")
                # ctx.master.addons.trigger(hooks.UpdateHook([flow]))

            if len(self.flows_to_replay):
                # proces the next replay
                slep
                ctx.master.commands.call("replay.client", [self.flows_to_replay.pop()])

    def load(self, loader):
        loader.add_option(
            name="scaninject_xss_check_string",
            typespec=str,
            default="alert(1)",
            help="String to look for in response bodies to confirm XSS payload execution.",
        )

    @command.command("scan.inject.types")
    def injection_types(self) -> Sequence[str]:
        return ["xss", "open-redirect", "crlf"]  # Extend as you implement more

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
        The payload can be a string or a path to a file containing the payload.

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
            f"Starting {injection_type.upper()} injection scan on {len(flows)} flows...",
        )

        replayed_flow_ids = []
        original_flow_ids = []

        for original_flow in flows:
            original_flow_ids.append(original_flow.id)

            if not isinstance(original_flow, http.HTTPFlow):
                logging.warning(
                    f"Skipping non-HTTP flow {original_flow.id} for injection."
                )
                continue

            duplicated_flow = original_flow.copy()

            duplicated_flow.id = str(uuid.uuid4())
            duplicated_flow.is_replay = "request"

            ctx.master.addons.trigger(hooks.UpdateHook([duplicated_flow]))

            replayed_flow_ids.append(duplicated_flow.id)

            try:
                if injection_type == "xss":
                    self._inject_xss_payload(duplicated_flow, payload)

                else:
                    logging.error(f"Unsupported injection type: {injection_type}")
                    continue

                self.flows_to_replay.append(duplicated_flow)

            except Exception as e:
                logging.error(
                    f"Error preparing flow {original_flow.id} for injection: {e}"
                )

                original_flow.marked = self.FAIL_MARKER
                original_flow.comment = f"Scan failed during preparation: {e}"
                ctx.master.addons.trigger(hooks.UpdateHook([original_flow]))
                replayed_flow_ids.pop()

        if len(self.flows_to_replay):
            time.sleep(0.5)
            ctx.master.commands.call("replay.client", [self.flows_to_replay.pop()])

        # all_flow_ids_to_show = original_flow_ids + replayed_flow_ids
        # if all_flow_ids_to_show:
        #     filter_expression = "@" + ",".join(all_flow_ids_to_show)
        #     ctx.master.commands.call("view.filter.set", filter_expression)
        # else:
        #     ctx.master.commands.call("view.filter.set", "")

        logging.log(
            ALERT,
            f"Injection process initiated. Results will be marked as responses come in.",
        )


addons = [ScanInject()]
