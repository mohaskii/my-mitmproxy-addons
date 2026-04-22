from mitmproxy import http
from flow_actions_lib.resolver import resolve_single

def _replace_in_multidict(
    target: http.HTTPFlow,
    source: str,  # "query" or "form"
    explicit: dict[str, str],
    fallback_value: str | None,
    replace_all: bool,
) -> None:
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

    if source == "query":
        target.request.query = params
    else:
        target.request.urlencoded_form = params

def action_replace_params(
    target: http.HTTPFlow,
    config: dict,
    vars_dict: dict[str, str],
) -> None:
    fallback_cfg = config.get("fallback_payload")
    fallback_value: str | None = None
    replace_all = False

    if fallback_cfg is not None and isinstance(fallback_cfg, dict):
        fb_val = fallback_cfg.get("value")
        if fb_val is not None:
            fallback_value = resolve_single(fb_val, vars_dict)
        replace_all = fallback_cfg.get("all", False)

    explicit: dict[str, str] = {}
    for key, val in config.items():
        if key == "fallback_payload":
            continue
        explicit[key] = resolve_single(val, vars_dict)

    _replace_in_multidict(target, "query", explicit, fallback_value, replace_all)

    if (
        target.request.method == "POST"
        and "application/x-www-form-urlencoded"
        in target.request.headers.get("content-type", "")
    ):
        _replace_in_multidict(target, "form", explicit, fallback_value, replace_all)

def action_add_params(
    target: http.HTTPFlow,
    config: dict,
    vars_dict: dict[str, str],
) -> None:
    has_query = bool(target.request.query)
    has_form = (
        target.request.method == "POST"
        and "application/x-www-form-urlencoded"
        in target.request.headers.get("content-type", "")
    )

    for key, val in config.items():
        resolved = resolve_single(val, vars_dict)

        if has_query:
            query = target.request.query
            query.add(key, resolved)
            target.request.query = query

        if has_form:
            form = target.request.urlencoded_form
            form.add(key, resolved)
            target.request.urlencoded_form = form

        if not has_query and not has_form:
            query = target.request.query
            query.add(key, resolved)
            target.request.query = query
