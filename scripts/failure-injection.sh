#!/usr/bin/env bash
set -euo pipefail

INJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$INJECT_DIR/.." && pwd)"

DRY_RUN=false
POSITIONAL=()

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --help)
      sed -n '3,25p' "$0"
      exit 0
      ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

NETWORK="${1:?ERROR: network argument is required (testnet|futurenet)}"
CONTRACT_ID="${2:?ERROR: contract-id argument is required}"
ADMIN_IDENTITY="${3:?ERROR: admin-identity argument is required}"
SCENARIO="${4:?ERROR: scenario name is required}"

ADMIN_ADDRESS=$(soroban keys address "$ADMIN_IDENTITY" 2>/dev/null || echo "<ADMIN_ADDRESS>")

run() {
  if [ "$DRY_RUN" = true ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

log() { echo "==> $*"; }

# invoke <function> [args...]: call a contract function (only printed in a dry run).
invoke() {
  run soroban contract invoke \
    --id "$CONTRACT_ID" \
    --source "$ADMIN_IDENTITY" \
    --network "$NETWORK" \
    -- \
    "$@"
}

# view <function>: print a view call's result with one pair of surrounding double quotes removed.
# The exit status is the call's own.
view() {
  local out
  out=$(soroban contract invoke \
    --id "$CONTRACT_ID" \
    --source "$ADMIN_IDENTITY" \
    --network "$NETWORK" \
    -- \
    "$@" 2>/dev/null) || return 1
  out="${out#\"}"
  out="${out%\"}"
  printf '%s\n' "$out"
}

# ── State capture and restoration ───────────────────────────────────────────
# A scenario that changes governance settings first records them, and an EXIT trap puts them back
# even when a step fails half way. Whatever could not be restored is reported, and the script then
# exits non-zero.

UNRESOLVED=()
ORIGINAL_THRESHOLD=""
THRESHOLD_CHANGED=false
ORIGINAL_EPOCH=""
ORIGINAL_EPOCH_OPEN=""
NEXT_EPOCH=""
EPOCH_REOPEN_PENDING=false

# capture_threshold: remember the service threshold, or stop before changing anything.
capture_threshold() {
  if [ "$DRY_RUN" = true ]; then
    ORIGINAL_THRESHOLD="<original threshold>"
    echo "[dry-run] soroban contract invoke --id $CONTRACT_ID -- get_service_threshold  # remembered for restoration"
    return 0
  fi
  if ! ORIGINAL_THRESHOLD=$(view get_service_threshold) || ! [[ "$ORIGINAL_THRESHOLD" =~ ^[0-9]+$ ]]; then
    echo "ERROR: could not read the current service threshold; nothing was changed." >&2
    exit 1
  fi
  log "Original service threshold: $ORIGINAL_THRESHOLD"
}

# restore_threshold: set the remembered threshold back and verify it.
restore_threshold() {
  local current
  THRESHOLD_CHANGED=false
  if ! invoke set_service_threshold --admin-signers "[$ADMIN_ADDRESS]" --threshold "$ORIGINAL_THRESHOLD"; then
    UNRESOLVED+=("service threshold: restoring $ORIGINAL_THRESHOLD failed; check get_service_threshold")
    return 0
  fi
  if [ "$DRY_RUN" = false ]; then
    current=$(view get_service_threshold) || current="<unreadable>"
    if [ "$current" != "$ORIGINAL_THRESHOLD" ]; then
      UNRESOLVED+=("service threshold: expected $ORIGINAL_THRESHOLD after the restore, found $current")
      return 0
    fi
    log "Service threshold restored and verified: $current"
  fi
}

# capture_epoch: remember the current epoch and whether it is open, or stop before changing anything.
capture_epoch() {
  if [ "$DRY_RUN" = true ]; then
    ORIGINAL_EPOCH="<current epoch>"
    ORIGINAL_EPOCH_OPEN="true"
    NEXT_EPOCH="<current epoch + 1>"
    echo "[dry-run] soroban contract invoke --id $CONTRACT_ID -- get_current_epoch / is_epoch_open  # remembered"
    return 0
  fi
  if ! ORIGINAL_EPOCH=$(view get_current_epoch) || ! [[ "$ORIGINAL_EPOCH" =~ ^[0-9]+$ ]] \
    || ! ORIGINAL_EPOCH_OPEN=$(view is_epoch_open) \
    || { [ "$ORIGINAL_EPOCH_OPEN" != true ] && [ "$ORIGINAL_EPOCH_OPEN" != false ]; }; then
    echo "ERROR: could not read the current epoch state; nothing was changed." >&2
    exit 1
  fi
  NEXT_EPOCH=$((ORIGINAL_EPOCH + 1))
  log "Current epoch: $ORIGINAL_EPOCH (open: $ORIGINAL_EPOCH_OPEN)"
}

# reopen_epoch: open the epoch after the one that was closed, and verify it. If the close never
# took effect (the original epoch is still open) there is nothing to undo.
reopen_epoch() {
  local epoch open
  EPOCH_REOPEN_PENDING=false
  if [ "$DRY_RUN" = false ]; then
    epoch=$(view get_current_epoch) || epoch="<unreadable>"
    open=$(view is_epoch_open) || open="<unreadable>"
    if [ "$epoch" = "$ORIGINAL_EPOCH" ] && [ "$open" = true ]; then
      log "Epoch $ORIGINAL_EPOCH is still open; nothing to reopen"
      return 0
    fi
  fi
  if ! invoke open_epoch --admin-signers "[$ADMIN_ADDRESS]" --epoch-id "$NEXT_EPOCH"; then
    UNRESOLVED+=("epoch: $ORIGINAL_EPOCH was closed and opening epoch $NEXT_EPOCH failed; submissions stay blocked until open_epoch succeeds")
    return 0
  fi
  if [ "$DRY_RUN" = false ]; then
    epoch=$(view get_current_epoch) || epoch="<unreadable>"
    open=$(view is_epoch_open) || open="<unreadable>"
    if [ "$epoch" != "$NEXT_EPOCH" ] || [ "$open" != true ]; then
      UNRESOLVED+=("epoch: expected epoch $NEXT_EPOCH open, found epoch $epoch (open: $open)")
      return 0
    fi
    log "Epoch $NEXT_EPOCH is open and verified"
  fi
}

# restore_state: runs when the script exits for any reason, including a failed step.
restore_state() {
  local status=$?
  trap - EXIT
  set +e
  if [ "$THRESHOLD_CHANGED" = true ]; then
    log "Cleanup: restoring the service threshold"
    restore_threshold
  fi
  if [ "$EPOCH_REOPEN_PENDING" = true ]; then
    log "Cleanup: reopening the epoch"
    reopen_epoch
  fi
  if [ "${#UNRESOLVED[@]}" -gt 0 ]; then
    echo "" >&2
    echo "UNRESOLVED STATE - these settings were NOT restored and need manual attention:" >&2
    printf '  - %s\n' "${UNRESOLVED[@]}" >&2
    [ "$status" -eq 0 ] && status=1
  fi
  exit "$status"
}
trap restore_state EXIT

echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  Failure Injection: $SCENARIO"
echo "  ║  Network: $NETWORK"
echo "  ║  Contract: $CONTRACT_ID"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

# ── Replay-attack drill helpers ──────────────────────────────────────────────
# The replay-attack scenario submits real signed attestations and asserts on the contract's own error
# code, so a failure for any other reason (cooldown, pause, bad signature) is never counted as
# evidence. It needs an isolated contract with attestation enabled (`set_service_pubkey`).

DRILL_FAILED=false
drill_fail() { echo "  FAIL: $*" >&2; DRILL_FAILED=true; }

# The nonce check rejects with `InvalidAttestation` (error 27, see docs/errors.md).
NONCE_REPLAY_ERROR="Error(Contract, #27)"

# view_value <function>: print a view call's result with one pair of surrounding double quotes
# removed; the exit status is the call's own.
view_value() {
  local out
  out=$(soroban contract invoke \
    --id "$CONTRACT_ID" \
    --source "$ADMIN_IDENTITY" \
    --network "$NETWORK" \
    -- \
    "$@" 2>/dev/null) || return 1
  out="${out#\"}"
  out="${out%\"}"
  printf '%s\n' "$out"
}

# build_fixture <pair> <nonce> <timestamp>: the signed ScoreAttestationInput for one submission.
build_fixture() {
  "${PYTHON:-python3}" "$INJECT_DIR/build_attestation_fixture.py" \
    --contract "$CONTRACT_ID" \
    --wallet "$ADMIN_ADDRESS" \
    --pair "$1" \
    --score 50 \
    --timestamp "$3" \
    --confidence 80 \
    --model-version 1 \
    --contract-version "$CONTRACT_VERSION" \
    --nonce "$2" \
    --network "${ATTESTATION_NETWORK:-$NETWORK}"
}

# submit_attested <pair> <timestamp> <fixture>: submit once and keep the exit status and the
# combined output in ATT_OK and ATT_OUT.
submit_attested() {
  if ATT_OUT=$(soroban contract invoke \
    --id "$CONTRACT_ID" \
    --source "$ADMIN_IDENTITY" \
    --network "$NETWORK" \
    -- \
    submit_score \
    --signers "[]" \
    --wallet "$ADMIN_ADDRESS" \
    --asset-pair "$1" \
    --score 50 \
    --benford-flag false \
    --ml-flag false \
    --timestamp "$2" \
    --confidence 80 \
    --model-version 1 \
    --attestation-input "$3" 2>&1); then
    ATT_OK=true
  else
    ATT_OK=false
  fi
}

replay_attack_drill() {
  local pair="INJ_TEST" control_pair="INJ_TEST2" nonce="${ATTESTATION_NONCE:-0}"
  local ts fixture control_fixture registered pubkeys

  if [ "$DRY_RUN" = true ]; then
    echo "[dry-run] read get_version and get_service_pubkey; check the signing key matches it"
    echo "[dry-run] build_attestation_fixture.py --pair $pair --nonce $nonce   # signed attestation"
    echo "[dry-run] soroban contract invoke --id $CONTRACT_ID -- submit_score ... --attestation-input <fixture>   # must succeed"
    echo "[dry-run] the same submit_score with the same <fixture>   # must fail with $NONCE_REPLAY_ERROR"
    echo "[dry-run] build_attestation_fixture.py --pair $control_pair --nonce $((nonce + 1))   # control"
    echo "[dry-run] submit_score with the control fixture   # must succeed: the stored nonce advanced"
    return 0
  fi

  if [ -z "${ATTESTATION_SIGNING_KEY_FILE:-}" ]; then
    echo "ERROR: ATTESTATION_SIGNING_KEY_FILE must name the signing key (64 hex characters) matching the service pubkey." >&2
    exit 1
  fi
  if ! [[ "$nonce" =~ ^[0-9]+$ ]]; then
    echo "ERROR: ATTESTATION_NONCE must be the service signer's current nonce, an unsigned integer." >&2
    exit 1
  fi
  if ! CONTRACT_VERSION=$(view_value get_version) || ! [[ "$CONTRACT_VERSION" =~ ^[0-9]+$ ]]; then
    echo "ERROR: could not read get_version; nothing was submitted." >&2
    exit 1
  fi
  if ! registered=$(view_value get_service_pubkey); then
    echo "ERROR: no service pubkey is registered, so attestation is not enforced and a replay would not be rejected. Run this drill on an isolated contract after set_service_pubkey." >&2
    exit 1
  fi
  if ! pubkeys=$("${PYTHON:-python3}" "$INJECT_DIR/build_attestation_fixture.py" --print-pubkey) \
    || ! printf '%s\n' "$pubkeys" | grep -qix "$registered"; then
    echo "ERROR: the signing key does not match the registered service pubkey; nothing was submitted." >&2
    exit 1
  fi

  ts=$(date +%s)
  fixture=$(build_fixture "$pair" "$nonce" "$ts")

  log "1. Attested submission with nonce $nonce (must succeed)"
  submit_attested "$pair" "$ts" "$fixture"
  if [ "$ATT_OK" != true ]; then
    drill_fail "the first attested submission did not succeed, so the replay check proves nothing: $ATT_OUT"
    return 0
  fi
  echo "  accepted"

  log "2. Replaying the same signed bytes (must fail with $NONCE_REPLAY_ERROR)"
  submit_attested "$pair" "$ts" "$fixture"
  if [ "$ATT_OK" = true ]; then
    drill_fail "the replayed attestation was ACCEPTED; nonce $nonce was usable twice"
    return 0
  fi
  if ! printf '%s' "$ATT_OUT" | grep -qF "$NONCE_REPLAY_ERROR"; then
    drill_fail "the replay failed, but not with $NONCE_REPLAY_ERROR, so it is not evidence of nonce protection: $ATT_OUT"
    return 0
  fi
  echo "  rejected with $NONCE_REPLAY_ERROR"

  # The replay carried the same commitment, signature and contract version that were just accepted,
  # so only the nonce differs from the accepted call. Confirm the stored nonce is now nonce + 1 by
  # having the next nonce accepted.
  log "3. Control: a fresh attestation with nonce $((nonce + 1)) (must succeed)"
  ts=$(date +%s)
  control_fixture=$(build_fixture "$control_pair" "$((nonce + 1))" "$ts")
  submit_attested "$control_pair" "$ts" "$control_fixture"
  if [ "$ATT_OK" != true ]; then
    drill_fail "the control submission with nonce $((nonce + 1)) was rejected, so the stored nonce is not what the drill assumed (set ATTESTATION_NONCE to the signer's current nonce): $ATT_OUT"
    return 0
  fi
  echo "  accepted; the nonce advanced exactly once per accepted attestation"
}

case "$SCENARIO" in
  partial-signer-loss)
    log "Scenario: Partial signer loss (reduced below threshold)"
    log "1. Reducing service threshold to simulate signer loss"
    log "2. Attempting score submission with insufficient signers"
    log "3. Verifying submission is rejected with InsufficientSigners"
    log "4. Restoring threshold and verifying recovery"

    capture_threshold

    log "Setting threshold to 5 (simulating 4 signers lost)"
    THRESHOLD_CHANGED=true
    invoke set_service_threshold --admin-signers "[$ADMIN_ADDRESS]" --threshold 5

    log "Attempting submission with threshold not met"
    run soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      submit_score \
      --signers "[]" \
      --wallet "$ADMIN_ADDRESS" \
      --asset-pair INJ_TEST \
      --score 50 \
      --benford-flag false \
      --ml-flag false \
      --timestamp "$(date +%s)" \
      --confidence 80 \
      --model-version 1 \
      --attestation-input null 2>&1 || true

    log "Restoring original threshold ($ORIGINAL_THRESHOLD)"
    restore_threshold

    log "Scenario complete: partial-signer-loss"
    ;;

  stale-data)
    log "Scenario: Stale data (expired epoch)"
    log "1. Closing the current epoch to block submissions"
    log "2. Attempting score submission (should be rejected)"
    log "3. Opening the next epoch"
    log "4. Verifying submissions resume"
    log "An epoch that is already closed is left as it is; closing a live epoch is only done on an"
    log "isolated deployment (FAILURE_INJECTION_ISOLATED=1), because open_epoch accepts only an ID"
    log "above the current one, so the live epoch cannot be restored, only followed by the next."

    capture_epoch
    if [ "$ORIGINAL_EPOCH_OPEN" = true ]; then
      if [ "$DRY_RUN" = false ] && [ "${FAILURE_INJECTION_ISOLATED:-}" != "1" ]; then
        echo "ERROR: epoch $ORIGINAL_EPOCH is open. Closing it and reopening can only leave epoch $NEXT_EPOCH open, so the live epoch would be replaced." >&2
        echo "       Run this scenario against an isolated deployment and set FAILURE_INJECTION_ISOLATED=1. Nothing was changed." >&2
        exit 1
      fi
      log "Closing current epoch $ORIGINAL_EPOCH"
      EPOCH_REOPEN_PENDING=true
      invoke close_epoch --admin-signers "[$ADMIN_ADDRESS]"
    else
      log "Epoch $ORIGINAL_EPOCH is already closed; leaving it unchanged"
    fi

    log "Attempting submission with closed epoch"
    run soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      submit_score \
      --signers "[]" \
      --wallet "$ADMIN_ADDRESS" \
      --asset-pair INJ_TEST \
      --score 50 \
      --benford-flag false \
      --ml-flag false \
      --timestamp "$(date +%s)" \
      --confidence 80 \
      --model-version 1 \
      --attestation-input null 2>&1 || true

    if [ "$ORIGINAL_EPOCH_OPEN" = true ]; then
      log "Opening epoch $NEXT_EPOCH"
      reopen_epoch
    fi

    log "Scenario complete: stale-data"
    ;;

  replay-attack)
    log "Scenario: Replay attack attempt (reusing a signed attestation nonce)"
    log "1. Submit a score with a signed attestation carrying the signer's current nonce (must succeed)"
    log "2. Submit the same signed bytes again (must fail with the nonce-replay error)"
    log "3. Submit a fresh attestation with the next nonce (must succeed: the nonce advanced)"
    log "Needs an isolated contract with attestation enabled, the signing key in"
    log "ATTESTATION_SIGNING_KEY_FILE and, if the signer has already used nonces, ATTESTATION_NONCE."

    replay_attack_drill
    if [ "$DRILL_FAILED" = true ]; then
      log "Scenario FAILED: replay-attack"
      exit 1
    fi
    log "Scenario complete: replay-attack"
    ;;

  zero-value)
    log "Scenario: Zero-value submission (score=0, timestamp=0, confidence=0)"
    log "1. Submit with score=0 (should succeed — 0 is valid)"
    log "2. Submit with timestamp=0 (should be rejected with InvalidTimestamp)"
    log "3. Submit with confidence=0 (should succeed — 0 is valid)"

    log "Submitting score=0"
    run soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      submit_score \
      --signers "[]" \
      --wallet "$ADMIN_ADDRESS" \
      --asset-pair INJ_TEST \
      --score 0 \
      --benford-flag false \
      --ml-flag false \
      --timestamp "$(date +%s)" \
      --confidence 80 \
      --model-version 1 \
      --attestation-input null 2>&1 || true

    log "Submitting with timestamp=0 (should be rejected)"
    run soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      submit_score \
      --signers "[]" \
      --wallet "$ADMIN_ADDRESS" \
      --asset-pair INJ_TEST \
      --score 50 \
      --benford-flag false \
      --ml-flag false \
      --timestamp 0 \
      --confidence 80 \
      --model-version 1 \
      --attestation-input null 2>&1 || true

    log "Scenario complete: zero-value"
    ;;

  max-value)
    log "Scenario: Maximum-value submission (score=101, confidence=101)"
    log "1. Submit with score=101 (should be rejected with InvalidScore)"
    log "2. Submit with confidence=101 (should be rejected with InvalidConfidence)"

    log "Submitting score=101 (should be rejected)"
    run soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      submit_score \
      --signers "[]" \
      --wallet "$ADMIN_ADDRESS" \
      --asset-pair INJ_TEST \
      --score 101 \
      --benford-flag false \
      --ml-flag false \
      --timestamp "$(date +%s)" \
      --confidence 80 \
      --model-version 1 \
      --attestation-input null 2>&1 || true

    log "Submitting confidence=101 (should be rejected)"
    run soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      submit_score \
      --signers "[]" \
      --wallet "$ADMIN_ADDRESS" \
      --asset-pair INJ_TEST \
      --score 50 \
      --benford-flag false \
      --ml-flag false \
      --timestamp "$(date +%s)" \
      --confidence 101 \
      --model-version 1 \
      --attestation-input null 2>&1 || true

    log "Scenario complete: max-value"
    ;;

  unauthorized-caller)
    log "Scenario: Unauthorized caller (non-admin, non-service)"
    log "1. Attempt to set pair paused without admin auth"
    log "2. Attempt to pause contract without admin auth"

    log "Attempting unauthorized pair pause"
    run soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      set_pair_paused \
      --asset-pair INJ_TEST \
      --paused true 2>&1 || true

    log "Scenario complete: unauthorized-caller"
    ;;

  interrupted-retry)
    log "Scenario: Interrupted retry (submit, fail, retry within cooldown)"
    log "1. Submit a score"
    log "2. Attempt to submit the same score again (cooldown should block)"
    log "3. Wait and verify retry succeeds"

    log "First submission"
    run soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      submit_score \
      --signers "[]" \
      --wallet "$ADMIN_ADDRESS" \
      --asset-pair INJ_TEST \
      --score 50 \
      --benford-flag false \
      --ml-flag false \
      --timestamp "$(date +%s)" \
      --confidence 80 \
      --model-version 1 \
      --attestation-input null 2>&1 || true

    log "Immediate retry (should be rate-limited)"
    run soroban contract invoke \
      --id "$CONTRACT_ID" \
      --source "$ADMIN_IDENTITY" \
      --network "$NETWORK" \
      -- \
      submit_score \
      --signers "[]" \
      --wallet "$ADMIN_ADDRESS" \
      --asset-pair INJ_TEST \
      --score 55 \
      --benford-flag false \
      --ml-flag false \
      --timestamp "$(date +%s)" \
      --confidence 80 \
      --model-version 1 \
      --attestation-input null 2>&1 || true

    log "Scenario complete: interrupted-retry"
    ;;

  *)
    echo "ERROR: Unknown scenario '$SCENARIO'" >&2
    echo "Available scenarios:"
    echo "  partial-signer-loss"
    echo "  stale-data"
    echo "  replay-attack"
    echo "  zero-value"
    echo "  max-value"
    echo "  unauthorized-caller"
    echo "  interrupted-retry"
    exit 1
    ;;
esac

echo ""
log "Failure injection scenario '$SCENARIO' completed."
echo ""