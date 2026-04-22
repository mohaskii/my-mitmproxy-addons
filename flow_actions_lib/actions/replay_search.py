import logging
from mitmproxy import ctx, http, hooks
from mitmproxy.addons.clientplayback import ReplayHandler
from mitmproxy.log import ALERT
from flow_actions_lib.resolver import resolve

FAIL_MARKER = ":x:"


async def action_replay(target: http.HTTPFlow) -> None:
    try:
        target.response = None
        handler = ReplayHandler(target, ctx.options)
        await handler.replay()
        logging.info(
            f"[flow.actions] Replayed flow {target.id} — "
            f"status {target.response.status_code if target.response else 'N/A'}"
        )
    except Exception as e:
        logging.error(f"[flow.actions] Replay error for flow {target.id}: {e}")
        target.marked = FAIL_MARKER
        target.comment = f"[flow.actions] Replay error: {e}"
        raise


def action_search(
    target: http.HTTPFlow,
    config: dict,
    vars_dict: dict[str, str],
) -> None:
    search_values = resolve(config.get("value", ""), vars_dict)
    condition = config.get("condition", "OR").upper()
    search_in = config.get("in", "body").lower()
    found_mark = config.get("found_mark", ":syringe:")

    haystack = b""
    if search_in == "body":
        if target.response and target.response.content:
            haystack = target.response.content
    elif search_in == "header":
        if target.response:
            haystack = b"\r\n".join(
                f"{k}: {v}".encode() for k, v in target.response.headers.items()
            )

    results = [sv.encode() in haystack for sv in search_values]

    if condition == "AND":
        matched = all(results) and len(results) > 0
    else:
        matched = any(results)

    if matched:
        target.marked = found_mark
        target.comment = (
            f"[flow.actions] Match found ({condition}: "
            f"{', '.join(repr(v) for v in search_values)})"
        )
        logging.log(
            ALERT,
            f"[flow.actions] \u2713 Match in flow {target.id} "
            f"({condition}: {search_values})",
        )
    else:
        target.marked = FAIL_MARKER
        target.comment = (
            f"[flow.actions] No match ({condition}: "
            f"{', '.join(repr(v) for v in search_values)})"
        )
        logging.info(
            f"[flow.actions] \u2717 No match in flow {target.id} "
            f"({condition}: {search_values})"
        )
