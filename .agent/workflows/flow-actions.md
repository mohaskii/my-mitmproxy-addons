---
description: How to use and extend the flow.actions YAML-driven engine
---

# flow.actions Workflow

## Architecture

The engine (`flow_actions.py`) loads YAML rule files and applies action-groups
to flows. It is structured into a modular `flow_actions_lib`:

- `flow_actions.py`: the mitmproxy entrypoint, hook registration, and UI
  management.
- `flow_actions_lib/resolver.py`: handles variable resolution logic.
- `flow_actions_lib/actions/*.py`: contains all specific action implementations.

### Execution order within an action-group

1. **Filter** — `only_ids` / `exclude_ids`
2. **Duplicate** — `duplicate: true` copies the flow
3. **replace_params** — modify existing query/form params
4. **add_params** — inject new key-value pairs
5. **remove_headers_cookies** — remove specific headers/cookies
6. **set_headers_cookies** — set/overwrite headers/cookies
7. **replay** — `replay: true` replays the request (standalone, no search)
8. **search** — search response body/headers for values (post-replay,
   search-only)
9. **find_important_headers_cookies** — terminal action, probes each
   header/cookie individually

### Commands

| Command              | Arguments                   | Description                                        |
| -------------------- | --------------------------- | -------------------------------------------------- |
| `flow.actions`       | `<flows> <yaml_path>`       | Apply rules to selected flows manually             |
| `flow.actions.watch` | `<filter_expr> <yaml_path>` | Auto-apply rules to incoming flows matching filter |
| `flow.actions.stop`  | (none)                      | Stop the active watch                              |

### YAML Schema

```yaml
name: "rule-name"
vars:
  key: "value"
  auth: "Bearer token"
action-groups:
  - duplicate: true
    replace_params:
      fallback_payload:
        value: { var: key }
        all: true
      param_name: { var: key }
    add_params:
      new_key: { var: key }
    remove_headers_cookies:
      headers: ["X-Unwanted"]
      cookies: ["tracking"]
    set_headers_cookies:
      headers:
        Authorization: { var: auth }
      cookies:
        role: "admin"
    replay: true
    search:
      value: { var: key }
      in: "body"
      found_mark: ":syringe:"
      condition: "OR"
    find_important_headers_cookies:
      scope: "both"
      output: "./results.json"
```

### Key patterns

- **Variable resolution**: `{ var: name }` or `{ var: [a, b] }` or `"literal"`
- **`replay`** is a boolean flag — `true` to replay after all modifications
- **`search`** only searches (no replay). Requires `replay: true` before it
- **`remove_headers_cookies`** takes `headers` (list) and `cookies` (list).
  Regex removals match case-insensitively and handle duplicate HTTP headers
  gracefully.
- **`set_headers_cookies`** takes `headers` (dict) and `cookies` (dict),
  supports var refs
- **`find_important_headers_cookies`** does its own internal replays per
  header/cookie
- **`flow.actions.watch`** hooks into `request()` and skips replayed flows to
  prevent loops
- The watch filter uses standard mitmproxy filter syntax (`~u`, `~m`, `~d`,
  etc.)

### Adding a new action

1. Create `action_<name>` function in an appropriate module under
   `flow_actions_lib/actions/` (e.g., `parameters.py`).
2. Register and export it in `flow_actions_lib/actions/__init__.py`.
3. If sync: add to `ORDERED_ACTIONS` list and register in
   `_get_action_handler()` located in `flow_actions.py`.
4. If async/terminal: handle explicitly in `_apply_action_group()` in
   `flow_actions.py` after the ordered actions.
5. Update the YAML schema docstring and this workflow.
