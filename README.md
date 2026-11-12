# AI agent + xv6-public (x86) — integration steps

## 0. Prerequisite
The taint kernel changes from the earlier messages must be in your xv6 tree
(`marktaint`, `istainted`, tainted fork/pipe/file, unlink refusal). agentd uses
both syscalls.

## 1. Copy guest files into the xv6 tree (flat folder)
    cp guest/agentd.c       ~/xv6-public/
    cp guest/inbox.txt guest/report.txt guest/important.txt guest/scratch.txt ~/xv6-public/

(mkfs rejects names containing '/', so the data files must sit in the xv6 root.)

## 2. Makefile (in ~/xv6-public)
UPROGS: add
    _agentd\
EXTRA: add `agentd.c`
fs.img rule: add the data files after `$(UPROGS)` and before `--safe`:

    fs.img: mkfs README $(UPROGS)
    	./mkfs fs.img README inbox.txt report.txt important.txt scratch.txt $(UPROGS) --safe _cat _ls _echo

Do NOT mark inbox.txt untrusted inside mkfs; the bridge does it with
`marktaint` at start-up (setup step, before any read), which persists on disk.

## 3. Build and check by hand (Milestone A)
    make clean && make qemu-nox
    $ ls
    $ cat report.txt
    $ agentd
    LIST
    READ /report.txt
    QUIT

## 4. Run the host agent
    cd agentlab
    python3 -m unittest discover -s tests -v      # logic only, mock guest
    python3 run_demo.py --backend mock            # mock guest
    python3 run_demo.py --backend qemu --xv6dir ~/xv6-public   # REAL evidence

Real logs: `logs/qemu_run.jsonl` and `logs/qemu_run_console.log` (raw QEMU).

## Design
| Layer | File | Role |
|---|---|---|
| Planner | agent/planners.py | proposes one structured action (rules; LLM later) |
| Validator | agent/tools.py | allowlist, schema, path regex, confirmation for delete |
| Bridge | agent/bridge.py | QEMU serial pipe, sentinel `@@END`, timeouts |
| Guest runner | guest/agentd.c | ONE long-lived process, so taint persists |
| Kernel | your xv6 changes | final enforcement |

Why `agentd` is one process: taint is per process. If each tool were a fresh
`cat`/`rm`, the reader and the deleter would be unrelated processes and the
kernel could not link them.

## Limits (write these in the report)
- `MockBridge` replicates kernel rules; it proves host logic only, not the kernel.
- Serial-console bridge: timing based, echo is stripped heuristically.
- The injection planner is scripted; a real LLM may or may not obey.
- `new_session()` models "new task = new process"; a real deployment needs a policy for it.
- Paths limited to `/name` in the root directory.
