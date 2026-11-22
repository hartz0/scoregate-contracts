#!/usr/bin/env python3
"""Replay the committed fixtures and compare the results with the reviewed baseline.

    scripts/check_replay_baselines.py            # compare; exit 1 on any difference
    scripts/check_replay_baselines.py --update   # rewrite tools/replay/baselines/expected.json

For each replay fixture the baseline pins the processed-entry count and the evidence hashes; for the
failure-injection run it pins every per-entry accepted/rejected tally. A fixture whose processed
count differs from its number of entries, or a failure scenario that reports an error, fails
regardless of the baseline. Baselines change only through a reviewed commit that runs --update.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPLAY_DIR = os.path.join(ROOT, "tools", "replay")
BASELINE = os.path.join(REPLAY_DIR, "baselines", "expected.json")
REPLAY_FIXTURES = ["testdata/reference.ndjson", "testdata/versioned_v1.ndjson"]
HASH_FIELDS = ["transactions_hash", "events_hash", "config_hash", "bundle_hash"]


def run_replay(*args):
    cmd = ["cargo", "run", "-q", "--manifest-path", os.path.join(REPLAY_DIR, "Cargo.toml"), "--"] + list(args)
    done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if done.returncode != 0:
        sys.exit("replay %s failed (exit %d):\n%s" % (" ".join(args), done.returncode, done.stderr))
    return done.stdout


def entry_count(relative):
    with open(os.path.join(REPLAY_DIR, relative), encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def collect(problems):
    result = {"replay": {}, "failure_injection": {}}
    for fixture in REPLAY_FIXTURES:
        out = run_replay("replay", os.path.join(REPLAY_DIR, fixture))
        processed = re.search(r"^processed (\d+) entries$", out, re.M)
        facts = {"processed": int(processed.group(1)) if processed else None}
        for field in HASH_FIELDS:
            found = re.search(r'"%s":\s*"([0-9a-f]+)"' % field, out)
            facts[field] = found.group(1) if found else None
        if facts["processed"] != entry_count(fixture):
            problems.append("%s: processed %s entries but the fixture has %d" % (fixture, facts["processed"], entry_count(fixture)))
        for field, value in facts.items():
            if value is None:
                problems.append("%s: no %s in the replay output" % (fixture, field))
        result["replay"][fixture] = facts

    out = run_replay("failure-inject")
    for line in out.splitlines():
        if re.search(r"Scenario '.*' error:", line):
            problems.append("failure injection reported: " + line.strip())
    result["failure_injection"] = {
        "entries": [l.strip() for l in out.splitlines() if l.startswith("scenario=")],
        "processed": [l.strip() for l in out.splitlines() if re.match(r"\s*Scenario '.*' processed \d+ entries", l)],
    }
    if not result["failure_injection"]["entries"]:
        problems.append("failure injection produced no per-entry results")
    return result


def main():
    problems = []
    actual = collect(problems)
    if "--update" in sys.argv:
        if problems:
            sys.exit("not updating the baseline:\n  " + "\n  ".join(problems))
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(actual, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print("wrote", os.path.relpath(BASELINE, ROOT))
        return 0
    if not os.path.isfile(BASELINE):
        problems.append("no baseline at %s; generate it with --update and have it reviewed" % os.path.relpath(BASELINE, ROOT))
    else:
        with open(BASELINE, encoding="utf-8") as handle:
            expected = json.load(handle)
        if expected != actual:
            for key in sorted(set(expected) | set(actual)):
                if expected.get(key) != actual.get(key):
                    problems.append("%s differs from the baseline:\n    expected %s\n    actual   %s" % (
                        key, json.dumps(expected.get(key), sort_keys=True), json.dumps(actual.get(key), sort_keys=True)))
    if problems:
        print("Replay regression FAILED:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 1
    print("Replay regression passed: %d replay fixtures and %d failure-injection entries match the baseline"
          % (len(actual["replay"]), len(actual["failure_injection"]["entries"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
