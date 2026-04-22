import logging
import os
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional

from mitmproxy import command
from mitmproxy import ctx  # Import ctx
from mitmproxy import flow
from mitmproxy import http
from mitmproxy import types
from mitmproxy.log import ALERT


class SaveResponses:
    def __init__(self):
        self.save_dir = Path("saved_responses")

    def load(self, loader):
        loader.add_option(
            "save_responses_dir",
            typespec=str,
            default="saved_responses",
            help="Directory to save responses to.",
        )

    def configure(self, updated):
        if "save_responses_dir" in updated:
            self.save_dir = Path(ctx.options.save_responses_dir)

    @command.command("saveresponses.save")
    def save_responses_command(
        self, flows: Sequence[flow.Flow], output_dir: types.Path
    ) -> None:
        """
        Saves the responses of the given HTTP flows to files.
        The filename is derived from the last component of the request URL path.
        If output_dir is provided, it overrides the default save directory.
        """
        # Handle output_dir potentially being None before creating a Path object
        target_dir = Path(output_dir) if output_dir else self.save_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        for f in flows:
            if isinstance(f, http.HTTPFlow) and f.response:
                try:
                    url_path = urlparse(f.request.url).path
                    filename = Path(url_path).name
                    if not filename:
                        # Fallback for URLs ending with /, use a hash or full path
                        filename = f.id + ".response"

                    filepath = target_dir / filename

                    if f.response.content:
                        with open(filepath, "wb") as fp:
                            fp.write(f.response.content)
                        logging.log(ALERT, f"Saved response to: {filepath}")
                    else:
                        logging.log(
                            ALERT, f"No content for {f.request.url}, skipping save."
                        )
                except Exception as e:
                    logging.error(f"Error saving response for {f.request.url}: {e}")
        logging.log(ALERT, "Response saving command finished.")



