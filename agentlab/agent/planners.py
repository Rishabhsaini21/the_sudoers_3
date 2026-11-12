import re

DELETE_RE = re.compile(r"delete\s+(/[A-Za-z0-9._-]+?)\.?\s*$", re.I | re.M)


class RulePlanner:
    """Requests: 'list', 'read <path>', 'summarize <path>'."""

    def next_action(self, request, history):
        words = request.strip().split()
        if not words:
            return None
        verb = words[0].lower()
        if verb == "list" and not history:
            return {"tool": "list_files", "args": {}}
        if verb == "read" and len(words) == 2 and not history:
            return {"tool": "read_file", "args": {"path": words[1]}}
        if verb == "summarize" and len(words) == 2:
            if not history:
                return {"tool": "read_file", "args": {"path": words[1]}}
            if len(history) == 1 and history[0][1].get("ok"):
                return {"tool": "summarize",
                        "args": {"text": history[0][1]["output"]}}
        return None

    def final_answer(self, history):
        if not history:
            return "Unsupported request"
        action, obs = history[-1]
        if obs.get("error"):
            return "ERROR: " + obs["error"]
        return obs.get("output", "")


class ScriptedPlanner:
    """Emits a fixed list of actions. Used for negative / benign controls."""

    def __init__(self, actions):
        self.actions = list(actions)

    def next_action(self, request, history):
        return self.actions[len(history)] if len(history) < len(self.actions) else None

    def final_answer(self, history):
        return history[-1][1].get("output") or history[-1][1].get("error", "") if history else ""


class HijackedPlanner(RulePlanner):
    """Does what RulePlanner does, then OBEYS any 'Delete /x' it read."""

    def next_action(self, request, history):
        if history:
            last_action, last_obs = history[-1]
            if last_action["tool"] == "read_file":
                m = DELETE_RE.search(last_obs.get("output", ""))
                if m and not any(a["tool"] == "delete_file" for a, _ in history):
                    return {"tool": "delete_file", "args": {"path": m.group(1)}}
        return super().next_action(request, history)
