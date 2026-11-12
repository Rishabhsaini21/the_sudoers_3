import os
import re
import subprocess
import threading
import time

END_RE = re.compile(r"@@END rc=(-?\d+) tainted=([01])\r?\n")
KERNEL_RE = re.compile(r"^taint:.*$")


class BridgeError(Exception):
    pass


def parse_reply(raw, sent_line):
    """Turn raw console text for one command into an observation dict."""
    m = END_RE.search(raw)
    if not m:
        return {"ok": False, "rc": None, "tainted": None, "kernel_log": [],
                "output": "", "error": "malformed reply (no @@END sentinel)"}
    body = raw[:m.start()]
    lines = body.replace("\r", "").split("\n")
    if lines and lines[0].strip() == sent_line.strip():   # console echo
        lines = lines[1:]
    kernel, out = [], []
    for l in lines:
        (kernel if KERNEL_RE.match(l) else out).append(l)
    rc = int(m.group(1))
    return {"ok": rc == 0, "rc": rc, "tainted": int(m.group(2)),
            "kernel_log": kernel, "output": "\n".join(out).strip("\n")}


class _SerialBase:
    """Shared command() logic. Subclasses implement _send and _wait_for_end."""

    def command(self, line, timeout=10.0):
        if "\n" in line or "\r" in line or len(line) > 90:
            raise BridgeError("refusing to send malformed command line")
        raw = self._exchange(line, timeout)
        if raw is None:
            return {"ok": False, "rc": None, "tainted": None, "kernel_log": [],
                    "output": "", "error": f"timeout after {timeout}s"}
        return parse_reply(raw, line)


class QemuBridge(_SerialBase):
    def __init__(self, xv6_dir, make_target="qemu-nox", boot_timeout=90):
        self.xv6_dir = xv6_dir
        self.make_target = make_target
        self.boot_timeout = boot_timeout
        self.proc = None
        self.buf = ""
        self.cursor = 0
        self.cv = threading.Condition()
        self.transcript = []          # full raw console log for evidence

    # -- process / reader thread -------------------------------------------
    def start(self, mark=()):
        self.proc = subprocess.Popen(
            ["make", self.make_target], cwd=self.xv6_dir,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0)
        threading.Thread(target=self._reader, daemon=True).start()
        if self._wait(r"init: starting sh\r?\n\$ ", self.boot_timeout) is None:
            raise BridgeError("xv6 did not boot (no shell prompt)")
        for path in mark:                         # setup only, before any read
            self.start_agentd()
            r = self.command("MARK " + path)
            if not r["ok"]:
                raise BridgeError(f"could not mark {path}: {r}")
            self.quit_agentd()
        self.start_agentd()

    def _reader(self):
        while True:
            chunk = os.read(self.proc.stdout.fileno(), 4096)
            if not chunk:
                break
            text = chunk.decode("utf-8", "replace")
            with self.cv:
                self.buf += text
                self.transcript.append(text)
                self.cv.notify_all()

    def _wait(self, pattern, timeout):
        rx = re.compile(pattern)
        deadline = time.time() + timeout
        with self.cv:
            while True:
                m = rx.search(self.buf, self.cursor)
                if m:
                    seg = self.buf[self.cursor:m.end()]
                    self.cursor = m.end()
                    return seg
                left = deadline - time.time()
                if left <= 0:
                    return None
                self.cv.wait(left)

    def _write(self, line):
        self.proc.stdin.write((line + "\n").encode())
        self.proc.stdin.flush()

    # -- agentd lifecycle ----------------------------------------------------
    def start_agentd(self):
        """New agentd = NEW PROCESS = clean (untainted)."""
        self._write("agentd")
        if self._wait(r"@@READY\r?\n", 15) is None:
            raise BridgeError("agentd did not start")

    def quit_agentd(self):
        self._write("QUIT")
        if self._wait(r"\$ ", 15) is None:
            raise BridgeError("agentd did not exit")

    def new_session(self):
        self.quit_agentd()
        self.start_agentd()

    def _exchange(self, line, timeout):
        self._write(line)
        return self._wait(END_RE.pattern, timeout)

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
