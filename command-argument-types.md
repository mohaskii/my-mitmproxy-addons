# mitmproxy Command Argument Types

mitmproxy's command system automatically parses arguments based on their type annotations in the command function's signature. This document provides a breakdown of the argument types, along with examples of their definition in code and how they would be used in the command line.

## `str`: A Simple String Argument

This is the most basic argument type, where mitmproxy expects a plain string.

### Code Example

In the `comment` command in `mitmproxy/addons/comment.py`, the `comment` argument is a `str`:

```python
class Comment:
    @command.command("flow.comment")
    def comment(self, flow: Sequence[flow.Flow], comment: str) -> None:
        "Add a comment to a flow"
        # ...
```

### Command Line Example

To add the comment "My new comment" to all flows:

```
flow.comment @all "My new comment"
```

Or to a specific flow with ID `a1b2c3d4-e5f6-7890-1234-567890abcdef`:

```
flow.comment @a1b2c3d4-e5f6-7890-1234-567890abcdef "This is a specific flow comment"
```

---

## `Sequence[flow.Flow]`: A List of Flow Objects

This type expects a flow filter expression which mitmproxy's view addon resolves into a list of `flow.Flow` objects. This is handled by the `_FlowsType` class in `mitmproxy/types.py`, which uses `view.flows.resolve` to perform the lookup.

### Code Example

The `flow.kill` command in `mitmproxy/addons/core.py` takes a `Sequence[flow.Flow]` to specify which flows to kill:

```python
class Core:
    # ...
    @command.command("flow.kill")
    def kill(self, flows: Sequence[flow.Flow]) -> None:
        """
        Kill running flows.
        """
        # ...
```

### Command Line Examples

To kill all currently running flows:

```
flow.kill @all
```

To kill only the currently focused flow:

```
flow.kill @focus
```

To kill flows matching a URL filter:

```
flow.kill "~u example.com"
```

---

## `mitmproxy.types.Path`: A File Path

This type is specifically for handling file paths and automatically expands user home directory notations (like `~` or `~/`).

### Code Example

The `options.load` command in `mitmproxy/addons/core.py` uses `mitmproxy.types.Path` for the `path` argument:

```python
class Core:
    # ...
    @command.command("options.load")
    def options_load(self, path: mitmproxy.types.Path) -> None:
        """
        Load options from a file.
        """
        # ...
```

### Command Line Examples

To load options from a file named `my_options.yaml` in your home directory:

```
options.load ~/.mitmproxy/my_options.yaml
```

To load options from a file in the current directory:

```
options.load ./config.yaml
```

---

## `mitmproxy.types.Choice("options_command")`: An Argument with Dynamic Choices

This powerful type allows you to define an argument whose valid values are dynamically provided by another mitmproxy command. The argument in `Choice` refers to the command that will provide these options. This is handled by the `_ChoiceType` class in `mitmproxy/types.py`.

### Code Example

The `flow.set` command in `mitmproxy/addons/core.py` demonstrates this for its `attr` argument, using `mitmproxy.types.Choice("flow.set.options")`:

```python
class Core:
    # ...
    @command.command("flow.set")
    @command.argument("attr", type=mitmproxy.types.Choice("flow.set.options"))
    def flow_set(self, flows: Sequence[flow.Flow], attr: str, value: str) -> None:
        """
        Quickly set a number of common values on flows.
        """
        # ...

    @command.command("flow.set.options")
    def flow_set_options(self) -> Sequence[str]:
        return [
            "host",
            "status_code",
            "method",
            "path",
            "url",
            "reason",
        ]
```

When `flow.set` is called, the `attr` argument will be restricted to the strings returned by `flow.set.options`.

### Command Line Examples

To set the method of the focused flow to `POST`:

```
flow.set @focus method POST
```

To set the status code of the focused flow's response to `404`:

```
flow.set @focus status_code 404
```

If you try to use an invalid attribute, like `invalid_attr`:

```
flow.set @focus invalid_attr some_value
```

mitmproxy would raise an error indicating that `invalid_attr` is not a valid choice, because it's not in the list returned by `flow.set.options`.

---

## Summary

These examples illustrate how type annotations streamline argument parsing and validation within mitmproxy's command system, making it robust and user-friendly.
