from mitmproxy import ctx, http, command, addonmanager
from typing import Optional, cast

from mitmproxy.tcp import TCPFlow
from mitmproxy.addons import view
from mitmproxy.tools.web.master import WebMaster # Import WebMaster for type hinting

class BodyFilter:
    def __init__(self):
        self.pattern: Optional[bytes] = None
        self.enabled: bool = False
        self.matches: list[str] = []

    def load(self, loader: addonmanager.Loader):
        loader.add_option(
            name="body_filter",
            typespec=str,
            default="",
            help="Pattern to search for in request/response bodies",
        )
        loader.add_option(
            name="bf",
            typespec=bool,
            default=False,
            help="Enable or disable body filtering",
        )

    def configure(self, updated: set[str]):
        if "body_filter" in updated:
            raw = ctx.options.body_filter
            self.pattern = raw.encode() if raw else None
        if "bf" in updated:
            self.enabled = ctx.options.bf

    def _check_match(self, content: bytes) -> bool:
        if not self.pattern:
            return False
        return self.pattern in content

    def _mark_flow(self, flow: http.HTTPFlow, reason: str):
        if flow.id not in self.matches:
            self.matches.append(flow.id)
            flow.marked = ":pushpin:"
            ctx.log.info(f"[BodyFilter] {reason} matched pattern: {flow.request.url}")
    
    
    @command.command("bf.enable")
    def enable_filter(self) -> None:
        """Enable body filtering"""
        ctx.options.bf = True

    @command.command("bf.disable")
    def disable_filter(self) -> None:
        """Disable body filtering"""
        ctx.options.bf = False

    @command.command("bf.toggle")
    def toggle_filter(self) -> None:
        """Toggle body filtering on/off"""
        ctx.options.bf = not ctx.options.bf

    @command.command("bf.status")
    def filter_status(self) -> str:
        """Show current body filter status"""
        status = "enabled" if self.enabled else "disabled"
        pattern = self.pattern.decode() if self.pattern else "none"
        return f"Body filtering is {status}, pattern: {pattern}"

    @command.command("bf.apply")
    def apply_filter(self) -> str:
        """Apply the current filter to all stored flows"""
        if not self.pattern:
            return "No pattern set. Use set body_filter <pattern> first."

        self.matches = []
        match_count = 0
        flow_count = 0
        
        # Use typing.cast to inform the type checker that ctx.master is a WebMaster
        # (or ConsoleMaster, depending on where this addon is intended to run).
        # Both WebMaster and ConsoleMaster have a 'view' attribute of type mitmproxy.addons.view.View.
        master_with_view = cast(WebMaster, ctx.master)
        
        for flow in master_with_view.view:
            if isinstance(flow, TCPFlow):
                continue
            flow_count += 1

            if flow.request and flow.request.content:
                if self._check_match(flow.request.content):
                    self._mark_flow(flow, "Request")
                    match_count += 1

            if flow.response and flow.response.content:
                if self._check_match(flow.response.content):
                    if flow.id not in self.matches:
                        self._mark_flow(flow, "Response")
                        match_count += 1

        return f"Filter applied to {flow_count} flows: {match_count} matches found."

    def request(self, flow: http.HTTPFlow):
        if not self.enabled or not self.pattern:
            return
        if flow.request.content and self._check_match(flow.request.content):
            self._mark_flow(flow, "Request")

    def response(self, flow: http.HTTPFlow):
        if not self.enabled or not self.pattern:
            return
        if flow.response and flow.response.content:
            if self._check_match(flow.response.content):
                self._mark_flow(flow, "Response")


addons = [BodyFilter()]

