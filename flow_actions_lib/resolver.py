from typing import Any

def resolve(value: Any, vars_dict: dict[str, str]) -> list[str]:
    """
    Resolve a value to a list of strings.

    Handles:
        "literal"             → ["literal"]
        { var: "name" }       → [vars_dict["name"]]
        { var: ["a", "b"] }   → [vars_dict["a"], vars_dict["b"]]
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict) and "var" in value:
        ref = value["var"]
        if isinstance(ref, list):
            resolved = []
            for v in ref:
                if v not in vars_dict:
                    raise KeyError(f"Variable '{v}' not found in vars")
                resolved.append(vars_dict[v])
            return resolved
        if ref not in vars_dict:
            raise KeyError(f"Variable '{ref}' not found in vars")
        return [vars_dict[ref]]
    # Fallback: coerce to string
    return [str(value)]

def resolve_single(value: Any, vars_dict: dict[str, str]) -> str:
    """Convenience: resolve to a single string (takes the first value)."""
    return resolve(value, vars_dict)[0]
