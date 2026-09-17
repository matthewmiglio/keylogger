#!/usr/bin/env python3
"""Runs the full test suite: native keylogger tests (C, MinGW-w64 gcc) and
the receiver tests (Node). Exits nonzero if any suite fails.

Usage:  python tests/run_all.py
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"


def run(name: str, cmd: list[str], cwd: Path) -> bool:
    print(f"=== {name} ===")
    r = subprocess.run(cmd, cwd=cwd)
    print(f"=== {name}: {'PASS' if r.returncode == 0 else 'FAIL'} ===\n")
    return r.returncode == 0


def main() -> int:
    ok = True

    # 1. Native C tests (buffer, util, crypto). capture.c is not linked —
    #    kbd_title_at is stubbed inside the harness.
    if shutil.which("gcc"):
        exe = TESTS / "keylogger" / "test_native.exe"
        build = [
            "gcc", "-O2", "-Wall", "-Wextra",
            "-I", str(ROOT / "keylogger" / "src"),
            str(TESTS / "keylogger" / "test_native.c"),
            str(ROOT / "keylogger" / "src" / "buffer.c"),
            str(ROOT / "keylogger" / "src" / "util.c"),
            str(ROOT / "keylogger" / "src" / "crypto.c"),
            "-lbcrypt", "-ladvapi32",
            "-o", str(exe),
        ]
        ok &= run("keylogger build", build, ROOT)
        if ok:
            ok &= run("keylogger tests", [str(exe)], ROOT)
        else:
            print("skipping keylogger tests (build failed)")
    else:
        print("=== keylogger tests: SKIPPED (gcc not on PATH) ===\n")

    # 2. Receiver unit + API integration tests.
    if shutil.which("node"):
        ok &= run(
            "receiver tests",
            ["node", "--test", "--test-reporter=spec",
             str(TESTS / "receiver" / "crypto.test.mjs"),
             str(TESTS / "receiver" / "api.test.mjs")],
            ROOT,
        )
    else:
        print("=== receiver tests: SKIPPED (node not on PATH) ===\n")

    print("ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
