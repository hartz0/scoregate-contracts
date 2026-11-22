#!/usr/bin/env bash
# Runs cargo-mutants and separates "mutants survived" from "the tool failed".
# Exit codes: 0 all caught, 2 mutants missed, 3 timeouts (both judged against the threshold by
# scripts/check_mutation_outcomes.py); anything else (1 usage error, 4 baseline failed) is a failure.
set -uo pipefail
cargo mutants "$@"
status=$?
case "$status" in
  0) ;;
  2|3) echo "cargo-mutants exit $status: surviving mutants; the outcome gate applies the threshold." ;;
  *) echo "cargo-mutants failed with exit code $status" >&2; exit "$status" ;;
esac
exit 0
