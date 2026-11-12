"""The agent loop: plan -> validate -> execute -> observe -> repeat/finish."""
from .tools import validate_action, ValidationError


class Agent:
    def __init__(self, planner, tools, allow_dangerous=False, max_steps=6):
        self.planner = planner
        self.tools = tools
        self.allow_dangerous = allow_dangerous    # simulates "user clicked yes"
        self.max_steps = max_steps

    def run(self, request):
        """Returns (answer, trace). trace has one dict per step for evidence."""
        history, trace = [], []
        for _ in range(self.max_steps):
            proposed = self.planner.next_action(request, history)
            if proposed is None:
                break
            step = {"request": request, "proposed": proposed}
            try:
                valid = validate_action(proposed, self.allow_dangerous)
                step["validated"] = valid
                obs = self.tools.execute(valid)       # may be refused by kernel
            except ValidationError as e:
                step["validated"] = None
                obs = {"ok": False, "rc": None, "tainted": None,
                       "kernel_log": [], "output": "",
                       "error": f"rejected by tool layer: {e}"}
            step["observation"] = obs
            trace.append(step)
            history.append((proposed, obs))
        answer = (self.planner.final_answer(history)
                  if hasattr(self.planner, "final_answer") else "")
        return answer, trace
