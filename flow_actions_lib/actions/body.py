import json
import logging
from mitmproxy import http
from flow_actions_lib.resolver import resolve_single

def set_nested_dict(d: dict, path: str, value: any) -> None:
    """
    Sets a value in a nested dictionary using dot notation for the path.
    Example: set_nested_dict(d, "user.profile.name", "Alice")
    """
    keys = path.split(".")
    current = d
    for key in keys[:-1]:
        if not isinstance(current, dict):
            return
        if key not in current:
            current[key] = {}
        current = current[key]
    
    if isinstance(current, dict):
        current[keys[-1]] = value

def action_body(
    target: http.HTTPFlow,
    config: dict,
    vars_dict: dict[str, str],
) -> None:
    """
    Modifies the request body. Supports 'value' and 'json-set' sub-actions.
    """
    if not isinstance(config, dict):
        return

    if "value" in config:
        val = config["value"]
        if isinstance(val, str):
            resolved_val = resolve_single(val, vars_dict)
        else:
            resolved_val = val
        target.request.text = str(resolved_val)
        
    if "json-set" in config:
        sets = config["json-set"]
        if not sets:
            return
            
        try:
            body_text = target.request.text
            if not body_text:
                data = {}
            else:
                data = json.loads(body_text)
                
            if not isinstance(data, dict):
                logging.warning("[flow.actions] json-set requires a JSON object body.")
                return
                
            if isinstance(sets, list):
                for item in sets:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            resolved_val = resolve_single(v, vars_dict) if isinstance(v, str) else v
                            set_nested_dict(data, k, resolved_val)
            elif isinstance(sets, dict):
                for k, v in sets.items():
                    resolved_val = resolve_single(v, vars_dict) if isinstance(v, str) else v
                    set_nested_dict(data, k, resolved_val)
                    
            target.request.text = json.dumps(data)
        except json.JSONDecodeError:
            logging.warning("[flow.actions] Failed to parse body as JSON for json-set action.")
