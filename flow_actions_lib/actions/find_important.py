import json
import logging
import uuid
from mitmproxy import ctx, http
from mitmproxy.addons.clientplayback import ReplayHandler
from mitmproxy.log import ALERT

def duplicate_flow(original: http.HTTPFlow) -> http.HTTPFlow:
    dup = original.copy()
    dup.id = str(uuid.uuid4())
    dup.is_replay = "request"
    return dup

async def _do_replay(target: http.HTTPFlow) -> None:
    from flow_actions_lib.actions.replay_search import action_replay
    await action_replay(target)

async def action_find_important_headers_cookies(
    target: http.HTTPFlow,
    config: dict,
    vars_dict: dict[str, str],
) -> None:
    scope = config.get("scope", "both").lower()
    output_path = config.get("output")

    if target.response is None:
        try:
            await _do_replay(target)
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

    if scope in ("headers", "both"):
        skip_headers = {"host", "content-length", "transfer-encoding"}
        headers_to_test = [
            (k, v)
            for k, v in target.request.headers.items()
            if k.lower() not in skip_headers
        ]

        for header_name, header_value in headers_to_test:
            probe = duplicate_flow(target)
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
                    f"[flow.actions] \u2605 Header '{header_name}' is IMPORTANT "
                    f"(status: {baseline_status}\u2192{probe_status})"
                )
            else:
                unimportant_headers.append(header_name)
                logging.info(
                    f"[flow.actions] \u00b7 Header '{header_name}' is not important"
                )

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
            probe = duplicate_flow(target)
            remaining = {k: v for k, v in cookies.items() if k != cookie_name}
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
                    f"[flow.actions] \u2605 Cookie '{cookie_name}' is IMPORTANT "
                    f"(status: {baseline_status}\u2192{probe_status})"
                )
            else:
                unimportant_cookies.append(cookie_name)
                logging.info(
                    f"[flow.actions] \u00b7 Cookie '{cookie_name}' is not important"
                )

    results = {
        "flow_id": target.id,
        "url": target.request.pretty_url,
        "baseline_status": baseline_status,
        "important_headers": important_headers,
        "unimportant_headers": unimportant_headers,
        "important_cookies": important_cookies,
        "unimportant_cookies": unimportant_cookies,
    }

    summary = (
        f"[flow.actions] Important headers/cookies for {target.request.pretty_url}:\n"
        f"  Headers: {important_headers or '(none)'}\n"
        f"  Cookies: {important_cookies or '(none)'}"
    )
    logging.log(ALERT, summary)

    target.comment = (
        f"[flow.actions] Important \u2014 H: {important_headers}, C: {important_cookies}"
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
            logging.error(f"[flow.actions] Failed to write results to {output_path}: {e}")
