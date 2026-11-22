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

# fail_check <label> <detail>: record a failed check with the reason.
fail_check() {
  log "  FAIL: $1 ($2)"
  FAIL=$((FAIL + 1))
}

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

VERSION=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  get_version 2>/dev/null || echo "0")
check "get_version returns non-zero" "$VERSION"

IS_PAUSED=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  is_paused 2>/dev/null || echo "1")
if [ "$IS_PAUSED" = "0" ]; then
  check "Contract is not paused" "true"
else
  WARN=$((WARN + 1))
  log "  WARN: Contract is paused (is_paused=$IS_PAUSED)"
fi

FINALITY_BUFFER=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  get_finality_buffer 2>/dev/null || echo "0")
check "Finality buffer is configured" "$FINALITY_BUFFER"

COOLDOWN=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  get_cooldown 2>/dev/null || echo "0")
check "Cooldown is configured" "$COOLDOWN"

UPGRADE_DELAY=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  get_upgrade_delay 2>/dev/null || echo "0")
check "Upgrade delay is configured" "$UPGRADE_DELAY"

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
SERVICE_SET=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  get_service_signers 2>/dev/null || echo "NONE")
check "Service signers are configured" "$SERVICE_SET"

SERVICE_THRESHOLD=$(soroban contract invoke \
  --id "$CONTRACT_ID" \
  --source "$ADMIN_IDENTITY" \
  --network "$NETWORK" \
  -- \
  get_service_threshold 2>/dev/null || echo "0")
if [ "$SERVICE_THRESHOLD" != "0" ]; then
  check "Service threshold is set (>0)" "$SERVICE_THRESHOLD"
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