from .bridge import _SerialBase


class MockBridge(_SerialBase):
    def __init__(self, files, untrusted=(), hang_on=None):
        self.files = dict(files)            # "/name" -> text
        self.untrusted = set(untrusted)
        self.hang_on = hang_on              # verb that never answers (timeout test)
        self.tainted = 0
        self.pid = 3
        self.sent = []                      # every line that reached the "guest"

    def start(self, mark=()):
        self.untrusted |= set(mark)

    def new_session(self):                  # new agentd process => clean
        self.tainted = 0
        self.pid += 1

    def close(self):
        pass

    def _exchange(self, line, timeout):
        self.sent.append(line)
        verb, _, arg = line.partition(" ")
        if self.hang_on == verb:
            return None
        out, kern, rc = "", [], 0
        if verb == "LIST":
            out = "".join(n[1:] + "\n" for n in sorted(self.files))
        elif verb == "READ":
            if arg in self.files:
                out = self.files[arg]
                if not out.endswith("\n"):
                    out += "\n"
                if arg in self.untrusted:
                    self.tainted = 1
            else:
                out, rc = f"cannot open {arg}\n", -1
        elif verb == "DEL":
            if self.tainted:
                kern.append(f"taint: unlink refused for pid {self.pid}")
                rc = -1
            elif arg in self.files:
                del self.files[arg]
            else:
                rc = -1
            out = f"unlink({arg}) = {rc}\n"
        elif verb == "MARK":
            self.untrusted.add(arg)
            out = f"marktaint({arg}) = 0\n"
        else:
            out, rc = "bad command\n", -1
        # console order: echo, kernel line (printed inside the syscall), output
        return (line + "\n" + "".join(k + "\n" for k in kern) + out
                + f"\n@@END rc={rc} tainted={self.tainted}\n")
