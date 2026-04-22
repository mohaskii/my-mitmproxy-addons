import re
import logging
from mitmproxy import http
from flow_actions_lib.resolver import resolve_single

def action_remove_headers_cookies(
    target: http.HTTPFlow,
    config: dict,
    vars_dict: dict[str, str],
) -> None:
    except_h_patterns = []
    for eh in config.get("except_headers", []):
        p = resolve_single(eh, vars_dict)
        try:
            except_h_patterns.append(re.compile(p, re.IGNORECASE))
        except re.error as e:
            logging.warning(f"[flow.actions] Invalid except regex '{p}': {e}")

    except_c_patterns = []
    for ec in config.get("except_cookies", []):
        p = resolve_single(ec, vars_dict)
        try:
            except_c_patterns.append(re.compile(p, re.IGNORECASE))
        except re.error as e:
            logging.warning(f"[flow.actions] Invalid except regex '{p}': {e}")

    headers_to_remove = config.get("headers", [])
    for h in headers_to_remove:
        pattern = resolve_single(h, vars_dict)
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            logging.warning(f"[flow.actions] Invalid regex '{pattern}': {e}")
            continue

        # Use a set to prevent KeyError on duplicate headers in mitmproxy 10+ MultiDict
        matched = {k for k in target.request.headers.keys() if regex.fullmatch(k)}
        for name in matched:
            if any(ep.fullmatch(name) for ep in except_h_patterns):
                logging.info(
                    f"[flow.actions] Kept header '{name}' (excepted) "
                    f"in flow {target.id}"
                )
                continue
            del target.request.headers[name]
            logging.info(
                f"[flow.actions] Removed header '{name}' "
                f"(pattern: '{pattern}') from flow {target.id}"
            )

    cookies_to_remove = config.get("cookies", [])
    if cookies_to_remove:
        removed: list[str] = []
        
        for name, _ in list(target.request.cookies.items(multi=True)):
            if name in removed:
                continue

            for c in cookies_to_remove:
                pattern = resolve_single(c, vars_dict)
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    logging.warning(f"[flow.actions] Invalid regex '{pattern}': {e}")
                    continue

                if regex.fullmatch(name):
                    if any(ep.fullmatch(name) for ep in except_c_patterns):
                        logging.info(
                            f"[flow.actions] Kept cookie '{name}' (excepted) "
                            f"in flow {target.id}"
                        )
                    else:
                        del target.request.cookies[name]
                        removed.append(name)
                    break

        if removed:
            logging.info(
                f"[flow.actions] Removed cookies {removed} from flow {target.id}"
            )
            # If the Cookie header is now completely empty but still exists as `Cookie: `
            if not target.request.cookies and "cookie" in target.request.headers:
                del target.request.headers["cookie"]

def action_set_headers_cookies(
    target: http.HTTPFlow,
    config: dict,
    vars_dict: dict[str, str],
) -> None:
    headers_cfg = config.get("headers", {})
    for name, val in headers_cfg.items():
        resolved = resolve_single(val, vars_dict)
        target.request.headers[name] = resolved
        logging.info(f"[flow.actions] Set header '{name}' on flow {target.id}")

    cookies_cfg = config.get("cookies", {})
    if cookies_cfg:
        for name, val in cookies_cfg.items():
            resolved = resolve_single(val, vars_dict)
            target.request.cookies[name] = resolved
            logging.info(f"[flow.actions] Set cookie '{name}' on flow {target.id}")
