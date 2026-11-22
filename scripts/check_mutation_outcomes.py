#!/usr/bin/env python3
"""Gate a cargo-mutants shard on its outcomes.json.

    scripts/check_mutation_outcomes.py --shard shard-b --report-dir mutants-report-shard-b \\
        --max-survivors 0

Exit status:
    0  every outcome parsed and the survivors are within the threshold
    1  survivors (missed mutants plus timeouts) exceed --max-survivors
    2  the run itself failed: no outcomes file, invalid JSON or shape, an unknown outcome, a failed
       baseline, a failed mutant build, or no mutants at all

A Markdown summary goes to stdout so it can be appended to $GITHUB_STEP_SUMMARY. Timeouts count as
survivors, as in docs/mutation-testing.md.
"""
import argparse
import json
import os
import sys

KNOWN_SUMMARIES = {"Success", "CaughtMutant", "MissedMutant", "Unviable", "Timeout", "Failure"}
LISTED_SURVIVORS = 25


class RunFailure(Exception):
    """The mutation run did not produce usable results."""


def find_outcomes(report_dir):
    # `cargo mutants --output DIR` writes DIR/mutants.out/outcomes.json; accept DIR/outcomes.json too.
    candidates = [
        os.path.join(report_dir, "mutants.out", "outcomes.json"),
        os.path.join(report_dir, "outcomes.json"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    raise RunFailure("no outcomes.json under %s (looked for %s)" % (report_dir, ", ".join(candidates)))


def describe(scenario):
    mutant = scenario.get("Mutant", {}) if isinstance(scenario, dict) else {}
    if mutant.get("name"):
        return str(mutant["name"])
    function = mutant.get("function") or {}
    parts = [str(mutant.get("file", "?")), str(function.get("function_name", "?"))]
    if mutant.get("replacement"):
        parts.append("-> " + str(mutant["replacement"]))
    return " ".join(parts)


def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as error:
        raise RunFailure("%s is not valid JSON: %s" % (path, error))
    if not isinstance(data, dict) or not isinstance(data.get("outcomes"), list):
        raise RunFailure("%s has no 'outcomes' list" % path)

    counts = {"CaughtMutant": 0, "MissedMutant": 0, "Timeout": 0, "Unviable": 0}
    survivors = []
    for index, outcome in enumerate(data["outcomes"]):
        if not isinstance(outcome, dict) or outcome.get("summary") not in KNOWN_SUMMARIES:
            raise RunFailure("outcome %d in %s has an unknown or missing summary" % (index, path))
        summary = outcome["summary"]
        scenario = outcome.get("scenario")
        if scenario == "Baseline":
            if summary != "Success":
                raise RunFailure("the baseline test run ended as %s, so no mutant was judged" % summary)
            continue
        if not isinstance(scenario, dict) or "Mutant" not in scenario:
            raise RunFailure("outcome %d in %s has an unknown scenario" % (index, path))
        if summary in ("Success", "Failure"):
            raise RunFailure("mutant outcome %d (%s) ended as %s, not a test verdict" % (index, describe(scenario), summary))
        counts[summary] += 1
        if summary in ("MissedMutant", "Timeout"):
            survivors.append((summary, describe(scenario)))
    if sum(counts.values()) == 0:
        raise RunFailure("%s lists no mutants" % path)
    return counts, survivors


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--shard", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--max-survivors", type=int, default=0,
                        help="survivors (missed mutants plus timeouts) allowed before the shard fails")
    args = parser.parse_args()
    if args.max_survivors < 0:
        parser.error("--max-survivors must not be negative")

    try:
        counts, survivors = load(find_outcomes(args.report_dir))
    except RunFailure as error:
        print("## Shard %s: mutation run FAILED\n\n%s" % (args.shard, error))
        print("::error title=Mutation run failed (%s)::%s" % (args.shard, error), file=sys.stderr)
        return 2

    over = len(survivors) > args.max_survivors
    print("## Shard %s: %s\n" % (args.shard, "FAILED, too many surviving mutants" if over else "passed"))
    print("| Caught | Missed | Timed out | Unviable | Survivors allowed |")
    print("|---|---|---|---|---|")
    print("| %d | %d | %d | %d | %d |" % (counts["CaughtMutant"], counts["MissedMutant"],
                                           counts["Timeout"], counts["Unviable"], args.max_survivors))
    if survivors:
        print("\nSurviving mutants (%d, first %d shown):\n" % (len(survivors), LISTED_SURVIVORS))
        for summary, name in survivors[:LISTED_SURVIVORS]:
            print("- `%s` %s" % (summary, name))
    if over:
        print("::error title=Surviving mutants (%s)::%d survivors exceed the allowed %d"
              % (args.shard, len(survivors), args.max_survivors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
