"""Record a short benchmark against a supervisor that is already listening.

Design section 15.2 asks for 100 warm-up runs and at least 2,000 samples of
B1-B11. This runner records the sample count it actually took. A series shorter
than 2,000 is labelled measured-short and is not that study. Scenarios that
would fork-bomb, exhaust memory, or hold dozens of idle sandboxes are left
unrun here; the record says so.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import time
from pathlib import Path

from nsbx_orchestrator.bench import percentiles


def one(
    nsbx_run: str,
    socket: str,
    principal: str,
    argv: list[str],
    cancel_after: int | None,
) -> int:
    cmd = [nsbx_run, "--socket", socket, "--principal", principal]
    if cancel_after is not None:
        cmd.extend(["--cancel-after", str(cancel_after)])
    cmd.append("--")
    cmd.extend(argv)
    started = time.perf_counter()
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return int((time.perf_counter() - started) * 1000)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nsbx-run", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--principal", default="agent-a")
    parser.add_argument("--git", default="unknown")
    parser.add_argument("--out", default="out/bench.json")
    args = parser.parse_args()
    scenarios: list[dict[str, object]] = []
    b4 = [
        one(args.nsbx_run, args.socket, args.principal, ["python3", "-c", "print(1)"], None)
        for _ in range(20)
    ]
    scenarios.append({"id": "B4", "command": "python3 -c print(1)", **percentiles(b4)})
    b6 = [
        one(
            args.nsbx_run,
            args.socket,
            args.principal,
            ["python3", "-c", "print(sum(range(1000)))"],
            None,
        )
        for _ in range(10)
    ]
    scenarios.append(
        {"id": "B6", "command": "python3 -c print(sum(range(1000)))", **percentiles(b6)}
    )
    cancel_ms = one(
        args.nsbx_run,
        args.socket,
        args.principal,
        ["python3", "-c", "import time; time.sleep(30)"],
        500,
    )
    scenarios.append(
        {
            "id": "B9",
            "command": "cancel one sleep",
            "samples": 1,
            "elapsed_ms": cancel_ms,
            "method": "measured-short",
            "notes": "one cancel, not 1000 tasks",
        }
    )
    skipped = [
        ("B1", "true is not in the python-compute runtime; B4 is the measured stand-in"),
        ("B2", "no bench-only build without restrictions was run"),
        ("B3", "closure-size sweep was not run"),
        ("B5", "no node runtime is installed"),
        ("B7", "the supervisor runs one job at a time"),
        ("B8", "100MiB output was not run; the profile cap is 1MiB"),
        ("B10", "50 idle sandboxes were not started"),
        ("B11", "file read and write are covered by the artefact test, not timed here"),
    ]
    for ident, note in skipped:
        scenarios.append({"id": ident, "samples": 0, "method": "not-run", "notes": note})
    cpu = ""
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    body = {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu": cpu,
        "git": args.git,
        "scenarios": scenarios,
    }
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(body, indent=2) + "\n")
    print(dest)


if __name__ == "__main__":
    main()
