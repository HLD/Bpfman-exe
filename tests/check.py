#!/usr/bin/env python3
"""Compare EXPECT lines from simulate.sh with rule ids in an alerts JSONL file."""
import json, sys

sim_log, alerts_file = sys.argv[1], sys.argv[2]
expected = []
for line in open(sim_log):
    if line.startswith("EXPECT"):
        expected += line.split("#")[0].split()[1:]
fired = {}
for line in open(alerts_file):
    a = json.loads(line)
    fired.setdefault(a["rule"]["id"], a)
ok = 0
for rid in sorted(set(expected)):
    hit = rid in fired
    ok += hit
    detail = fired[rid]["process_tree"] if hit else ""
    print(f"{'PASS' if hit else 'MISS'}  {rid}  {detail}")
extra = sorted(set(fired) - set(expected))
print(f"\n{ok}/{len(set(expected))} expected detections fired")
if extra:
    print("also fired (not expected by a step):", ", ".join(extra))
sys.exit(0 if ok == len(set(expected)) else 1)
