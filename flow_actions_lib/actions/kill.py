from mitmproxy import http

def action_kill(
    target: http.HTTPFlow,
    config: bool,
    vars_dict: dict[str, str],
) -> None:
    """
    Terminates the flow immediately if config is true.
    """
    if config:
        target.kill()
