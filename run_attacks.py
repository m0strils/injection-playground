"""
run_attacks.py — run every attack against both the vulnerable and the defended
app, and print a PASS/FAIL table.

A row PASSES when the attack LANDS on the vulnerable app (proving the vuln is
real) AND is STOPPED on the defended app (proving the defense works). If either
half fails, the lesson is broken — so this doubles as the test suite and exits
non-zero on any FAIL.

    python run_attacks.py            # the table
    python run_attacks.py --verbose  # + payloads, expectations, and answers

Runs fully offline on the fake model — no API key required.
"""
from __future__ import annotations

import argparse
import sys

from attacks import load_cases
from vulnerable_app import handle

TICK, CROSS = "PASS", "FAIL"


def run() -> int:
    ap = argparse.ArgumentParser(description="run all attack<->defense pairs")
    ap.add_argument("--verbose", action="store_true", help="show payloads and answers")
    args = ap.parse_args()

    cases = load_cases()
    rows, all_pass = [], True

    for c in cases:
        undef = handle(c.payload, defended=False)
        deff = handle(c.payload, defended=True)
        landed = c.succeeded(undef)          # attack should succeed undefended
        stopped = not c.succeeded(deff)      # ...and be stopped defended
        ok = landed and stopped
        all_pass = all_pass and ok
        rows.append((c, landed, stopped, ok, undef, deff))

    # --- table ---
    print("\nPrompt-Injection Playground — attack vs. defense\n")
    print(f"{'#':<3}{'Attack':<38}{'OWASP':<13}{'Undef lands':<13}{'Defended stops':<16}{'Result'}")
    print("-" * 95)
    for c, landed, stopped, ok, _, _ in rows:
        print(f"{c.id[:2]:<3}{c.name:<38}{c.owasp:<13}"
              f"{('yes' if landed else 'NO'):<13}{('yes' if stopped else 'NO'):<16}"
              f"{TICK if ok else CROSS}")
    print("-" * 95)
    n_ok = sum(1 for *_, ok, _, _ in rows)
    print(f"{n_ok}/{len(rows)} lessons pass "
          f"(attack lands undefended AND is stopped defended)\n")

    if args.verbose:
        for c, landed, stopped, ok, undef, deff in rows:
            print("=" * 92)
            print(f"[{c.id}] {c.name}  ({c.owasp})   -> {TICK if ok else CROSS}")
            print(f"  exploits : {c.exploits}")
            print(f"  payload  : {c.payload}")
            print(f"  defense  : {c.defense}")
            print(f"  UNDEFENDED expected: {c.expected_undefended}")
            print(f"    answer : {undef.answer.splitlines()[0][:80]}")
            print(f"    sink   : {undef.sink_action}")
            print(f"  DEFENDED   expected: {c.expected_defended}")
            print(f"    answer : {deff.answer.splitlines()[0][:80]}")
            print(f"    sink   : {deff.sink_action}")
        print("=" * 92)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(run())
