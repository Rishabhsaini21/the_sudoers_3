"""Layer 1: tool schema, validation and dispatch.
"""
import re

# xv6 file names are at most DIRSIZ=14 chars and the exercise area is the
# root directory only: "/name". No "..", no sub-directories, no /safe.
PATH_RE = re.compile(r"^/[A-Za-z0-9._-]{1,14}$")
MAX_TEXT = 4000

# name -> {arg name: type}, plus a "dangerous" flag
TOOLS = {
    "list_files":  {"args": {},                "dangerous": False},
    "read_file":   {"args": {"path": str},     "dangerous": False},
    "summarize":   {"args": {"text": str},     "dangerous": False},
    "delete_file": {"args": {"path": str},     "dangerous": True},
}


class ValidationError(Exception):
    pass


def validate_action(action, allow_dangerous=False):
    """Return a normalised copy of `action` or raise ValidationError."""
    if not isinstance(action, dict):
        raise ValidationError("action must be an object")
    if set(action.keys()) != {"tool", "args"}:
        raise ValidationError("action must have exactly 'tool' and 'args'")
    name, args = action["tool"], action["args"]
    if not isinstance(name, str) or name not in TOOLS:
        raise ValidationError(f"unknown tool: {name!r}")
    if not isinstance(args, dict):
        raise ValidationError("args must be an object")

    spec = TOOLS[name]
    for key in args:
        if key not in spec["args"]:
            raise ValidationError(f"unexpected argument: {key!r}")
    for key, typ in spec["args"].items():
        if key not in args:
            raise ValidationError(f"missing argument: {key!r}")
        if not isinstance(args[key], typ):
            raise ValidationError(f"argument {key!r} must be {typ.__name__}")

    if "path" in args and not PATH_RE.fullmatch(args["path"]):
        raise ValidationError(f"path outside the exercise area: {args['path']!r}")
    if "text" in args and len(args["text"]) > MAX_TEXT:
        raise ValidationError("text too long")

    if spec["dangerous"] and not allow_dangerous:
        raise ValidationError(
            f"{name} is destructive and needs explicit confirmation")
    return {"tool": name, "args": dict(args)}


class Tools:
    """Maps validated actions to FIXED guest commands. No shell, no eval."""

    def __init__(self, bridge):
        self.bridge = bridge

    def execute(self, action):
        name, args = action["tool"], action["args"]
        if name == "list_files":
            return self.bridge.command("LIST")
        if name == "read_file":
            return self.bridge.command("READ " + args["path"])
        if name == "delete_file":
            return self.bridge.command("DEL " + args["path"])
        if name == "summarize":           # host-side only, never touches xv6
            text = args["text"]
            lines = [l for l in text.splitlines() if l.strip()]
            first = lines[0] if lines else ""
            return {"ok": True, "rc": 0, "tainted": None, "kernel_log": [],
                    "output": f"{len(lines)} line(s), {len(text.split())} word(s). "
                              f"First line: {first}"}
        raise ValidationError("no executor for " + name)  # unreachable
