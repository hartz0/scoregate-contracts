#!/usr/bin/env bash
set -euo pipefail

VERIFY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$VERIFY_DIR/.." && pwd)"

DRY_RUN=false
SKIP_SMOKE=false
POSITIONAL=()

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --skip-smoke) SKIP_SMOKE=true ;;
    --help)
      sed -n '3,15p' "$0"
      exit 0
      ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

NETWORK="${1:?ERROR: network argument is required}"
CONTRACT_ID="${2:?ERROR: contract-id argument is required}"
ADMIN_IDENTITY="${3:?ERROR: admin-identity argument is required}"

ADMIN_ADDRESS=$(soroban keys address "$ADMIN_IDENTITY" 2>/dev/null || echo "<ADMIN_ADDRESS>")

log() {
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "[$ts] $*"
}

PASS=0
FAIL=0
WARN=0
SKIPPED=0

check() {
  local label="$1"
  local result="$2"
  if [ -n "$result" ] && [ "$result" != "FAIL" ] && [ "$result" != "VERIFY_FAILED" ] && [ "$result" != "SCORE_NOT_FOUND" ]; then
    log "  PASS: $label"
    PASS=$((PASS + 1))
  else
    log "  FAIL: $label"
    FAIL=$((FAIL + 1))
  fi
}

# fail_check <label> <detail>: record a failed check with the reason.
fail_check() {
  log "  FAIL: $1 ($2)"
  FAIL=$((FAIL + 1))
}

# read_value <function> [args...]: call a contract view function, keeping its exit status apart
# from its output. Sets READ_OK (true only when the call succeeded) and READ_VALUE (stdout with one
# pair of surrounding double quotes removed). A failed call never yields a value.
read_value() {
  local out
  if out=$(soroban contract invoke \
    --id "$CONTRACT_ID" \
    --source "$ADMIN_IDENTITY" \
    --network "$NETWORK" \
    -- \
    "$@" 2>/dev/null); then
    READ_OK=true
    READ_VALUE="${out#\"}"
    READ_VALUE="${READ_VALUE%\"}"
  else
    READ_OK=false
    READ_VALUE=""
  fi
}

# check_number_in_range <label> <function> <min> <max>: pass only when the call succeeds and returns
# an unsigned integer within [min, max]. A failed call, malformed output or an out-of-domain value
# fails; nothing is substituted for a failed read.
check_number_in_range() {
  local label="$1" fn="$2" min="$3" max="$4"
  read_value "$fn"
  if [ "$READ_OK" != true ]; then
    fail_check "$label" "$fn call failed"
  elif ! [[ "$READ_VALUE" =~ ^[0-9]{1,18}$ ]]; then
    fail_check "$label" "$fn returned '$READ_VALUE', expected an unsigned integer"
  elif [ "$((10#$READ_VALUE))" -lt "$min" ] || [ "$((10#$READ_VALUE))" -gt "$max" ]; then
    fail_check "$label" "$fn returned $READ_VALUE, expected $min to $max"
  else
    check "$label" "$READ_VALUE"
  fi
}

log "Verifying deployment on $NETWORK (contract=$CONTRACT_ID)"
log "Admin: $ADMIN_ADDRESS"
echo ""

# ── 1. Basic state checks ──────────────────────────────
log "1. Basic state checks"

ADMIN=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  get_admin 2>/dev/null || echo "VERIFY_FAILED")
if [ "$ADMIN" != "VERIFY_FAILED" ]; then
  check "get_admin returns valid address" "$ADMIN"
else
  check "get_admin returns valid address" "FAIL"
fi

SERVICE=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  get_service 2>/dev/null || echo "VERIFY_FAILED")
if [ "$SERVICE" != "VERIFY_FAILED" ]; then
  check "get_service returns valid address" "$SERVICE"
else
  check "get_service returns valid address" "FAIL"
fi

# CONTRACT_VERSION is positive; get_version returns a u32.
check_number_in_range "get_version returns non-zero" get_version 1 4294967295

# is_paused returns a boolean. An unreadable or malformed pause state is a failure; only a
# readable true is a (non-critical) warning.
read_value is_paused
if [ "$READ_OK" != true ]; then
  fail_check "Contract pause state is readable" "is_paused call failed"
elif [ "$READ_VALUE" = "false" ]; then
  check "Contract is not paused" "true"
elif [ "$READ_VALUE" = "true" ]; then
  WARN=$((WARN + 1))
  log "  WARN: Contract is paused (is_paused=true)"
else
  fail_check "Contract pause state is readable" "is_paused returned '$READ_VALUE', expected true or false"
fi

# 0 disables the finality buffer and is valid; the setter rejects more than 24 hours.
check_number_in_range "Finality buffer is within its allowed range" get_finality_buffer 0 86400

# MIN_COOLDOWN_SECS..MAX_COOLDOWN_SECS (1 minute to 24 hours).
check_number_in_range "Cooldown is configured" get_cooldown 60 86400

# MIN_UPGRADE_DELAY_SECS..MAX_UPGRADE_DELAY_SECS (48 hours to 14 days).
check_number_in_range "Upgrade delay is configured" get_upgrade_delay 172800 1209600

echo ""

# ── 2. Functional smoke tests ──────────────────────────
log "2. Functional smoke tests"

# json_number <json> <field>: the unsigned integer value of a top-level field in the CLI's JSON
# output (a bare or quoted number), or nothing when the field is absent or not a number.
json_number() {
  printf '%s' "$1" | tr -d '\n' \
    | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"?[0-9]+" | head -1 | grep -oE '[0-9]+$' || true
}

if [ "$SKIP_SMOKE" = true ]; then
  SKIPPED=$((SKIPPED + 1))
  log "  SKIPPED: functional smoke tests (--skip-smoke); the submit/read round trip was NOT verified"
else
  # A pair that no earlier run can have written (S + 8 hex digits of the start time, 9 characters),
  # a timestamp from this run, and a score that is read back and compared, so a pre-existing record
  # or unrelated output can never satisfy the round trip.
  TEST_TIMESTAMP=$(date +%s)
  TEST_PAIR=$(printf 'S%08x' $((TEST_TIMESTAMP % 4294967296)))
  TEST_SCORE=42

  if SUBMIT_RESULT=$(soroban contract invoke \
    --id "$CONTRACT_ID" \
    --source "$ADMIN_IDENTITY" \
    --network "$NETWORK" \
    -- \
    submit_score \
    --signers "[]" \
    --wallet "$ADMIN_ADDRESS" \
    --asset-pair "$TEST_PAIR" \
    --score "$TEST_SCORE" \
    --benford-flag false \
    --ml-flag false \
    --timestamp "$TEST_TIMESTAMP" \
    --confidence 80 \
    --model-version 1 \
    --attestation-input null 2>&1); then
    check "Smoke test score submission succeeded" "submitted"
    if SCORE_JSON=$(soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      get_score \
      --wallet "$ADMIN_ADDRESS" \
      --asset-pair "$TEST_PAIR" 2>/dev/null); then
      READ_SCORE=$(json_number "$SCORE_JSON" score)
      READ_TIMESTAMP=$(json_number "$SCORE_JSON" timestamp)
      if [ "$READ_SCORE" = "$TEST_SCORE" ] && [ "$READ_TIMESTAMP" = "$TEST_TIMESTAMP" ]; then
        check "Smoke test round trip returned the submitted score and timestamp" "matched"
      else
        fail_check "Smoke test round trip" "submitted score $TEST_SCORE at $TEST_TIMESTAMP, read score '${READ_SCORE:-none}' at '${READ_TIMESTAMP:-none}'"
      fi
    else
      fail_check "Smoke test round trip" "get_score failed for the pair just submitted"
    fi
  else
    # Attestation-enforcing deployments reject an unsigned submission; that is a failed smoke test,
    # not a warning. Use --skip-smoke to run the other checks without it.
    fail_check "Smoke test score submission" "submit_score failed: $SUBMIT_RESULT"
  fi
fi

echo ""

# ── 3. Pending upgrade check ───────────────────────────
log "3. Pending upgrade check"
PENDING_UPGRADE=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  get_pending_upgrade 2>/dev/null || echo "NO_PENDING_UPGRADE")
if [ "$PENDING_UPGRADE" = "NO_PENDING_UPGRADE" ] || [ -z "$PENDING_UPGRADE" ]; then
  check "No unexpected pending upgrade" "true"
else
  WARN=$((WARN + 1))
  log "  WARN: Pending upgrade exists — may be intentional (governance review): $PENDING_UPGRADE"
fi

echo ""

# ── 4. Service set check ──────────────────────────────
log "4. Service configuration check"
read_value get_service_signers
if [ "$READ_OK" != true ]; then
  fail_check "Service signers are configured" "get_service_signers call failed"
elif [ -z "$READ_VALUE" ] || [ "$READ_VALUE" = "[]" ]; then
  fail_check "Service signers are configured" "get_service_signers returned no signers"
else
  check "Service signers are configured" "$READ_VALUE"
fi

read_value get_service_threshold
if [ "$READ_OK" != true ]; then
  fail_check "Service threshold is set (>0)" "get_service_threshold call failed"
elif ! [[ "$READ_VALUE" =~ ^[0-9]{1,18}$ ]]; then
  fail_check "Service threshold is set (>0)" "get_service_threshold returned '$READ_VALUE', expected an unsigned integer"
elif [ "$((10#$READ_VALUE))" -gt 0 ]; then
  check "Service threshold is set (>0)" "$READ_VALUE"
else
  WARN=$((WARN + 1))
  log "  WARN: Service threshold is 0 — single service key auth is in effect"
fi

echo ""

# ── Summary ────────────────────────────────────────────
echo ""
log "── Verification Summary ──"
log "PASS: $PASS"
log "FAIL: $FAIL"
log "WARN: $WARN"
log "SKIPPED: $SKIPPED"

if [ "$FAIL" -gt 0 ]; then
  log "STATUS: FAILED — $FAIL check(s) failed"
  exit 1
else
  log "STATUS: PASSED — All critical checks passed"
  if [ "$WARN" -gt 0 ]; then
    log "NOTICE: $WARN non-critical warning(s) — review recommended"
  fi
fi
echo ""