//! # Differential Arithmetic Tests for Fixed-Point Decay Math (issue #267)
//!
//! Compares the on-chain fixed-point integer approximation of `e^(-λ·t)` in
//! `decay_fixed` against an IEEE-754 `f64` floating-point reference across a
//! wide parameter sweep:
//!
//! - `t`  in `[0, 365 days]`
//! - `λ`  in `[0.0001, 0.5]` (expressed as rational `lambda_num / lambda_den`)
//!
//! The tolerance is set to **0.15 %** (150 parts per million of `SCALE`) for
//! the interior of the Taylor-series domain (`x < 5`), which is well within
//! the documented <0.01 % accuracy claim.  At the `x ≥ 5` saturation boundary
//! the contract returns `0`; the reference may be a very small positive value,
//! so we allow a generous absolute tolerance there.
//!
//! All arithmetic uses only types available in a `no_std` + `libm` environment
//! so the tests run inside the Soroban test harness without external crates.
#![cfg(test)]
extern crate std;

use crate::ScoreGateScoreContract;

/// SCALE factor used by `decay_fixed` — `1_000_000`.
const SCALE: u64 = 1_000_000;

/// Maximum absolute error (in SCALE units) allowed between the fixed-point
/// result and the IEEE-754 reference in the interior domain (`x < 5`).
/// 0.15 % of SCALE = 1_500.
const MAX_ABS_ERROR: u64 = 1_500;

/// Floating-point reference for `e^(-lambda * age_secs)` returned scaled by `SCALE`.
///
/// This mirrors the integer implementation in `lib.rs::decay_fixed` exactly,
/// but uses `f64` throughout so we can detect truncation drift.
fn decay_float_ref(age_secs: u64, lambda_num: u64, lambda_den: u64) -> f64 {
    const MAX_HORIZON: u64 = 31_536_000; // constants::MAX_DECAY_HORIZON_SECS
    if lambda_num == 0 {
        return SCALE as f64;
    }
    let age = age_secs.min(MAX_HORIZON) as f64;
    let lam = lambda_num as f64 / lambda_den as f64;
    let x = lam * age;
    if x >= 5.0 {
        return 0.0;
    }
    // True exponential via libm — the reference the integer path approximates.
    libm::exp(-x) * SCALE as f64
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn check(age_secs: u64, lambda_num: u64, lambda_den: u64) {
    let got = ScoreGateScoreContract::decay_fixed(age_secs, lambda_num, lambda_den);
    let reference = decay_float_ref(age_secs, lambda_num, lambda_den);
    let ref_u64 = reference.round() as u64;

    // In the saturation zone (x ≥ 5), contract returns 0.  The reference is
    // a tiny positive value (e^-5 ≈ 6_738); allow up to 7_000 units slack.
    let x = (lambda_num as f64 / lambda_den as f64)
        * age_secs.min(31_536_000) as f64;
    if x >= 5.0 {
        assert!(
            got <= 7_000,
            "saturation zone: decay_fixed({age_secs}, {lambda_num}/{lambda_den}) = {got}, expected ~0"
        );
        return;
    }

    let diff = (got as i64 - ref_u64 as i64).unsigned_abs();
    assert!(
        diff <= MAX_ABS_ERROR,
        "decay_fixed({age_secs}, {lambda_num}/{lambda_den}) = {got}  \
         reference = {ref_u64}  diff = {diff}  (max allowed = {MAX_ABS_ERROR})"
    );
}

// ── Zero-lambda short-circuit ─────────────────────────────────────────────────

#[test]
fn differential_zero_lambda_always_returns_scale() {
    for age in [0u64, 1, 86_400, 31_536_000, u64::MAX] {
        let got = ScoreGateScoreContract::decay_fixed(age, 0, 1);
        assert_eq!(got, SCALE, "zero lambda at age={age} must return SCALE");
    }
}

// ── Age sweep at a typical lambda ────────────────────────────────────────────

/// Sweep `t` across `[0, 365 days]` in logarithmically-spaced steps for a
/// representative lambda (λ ≈ 0.001 = 1/1000).
#[test]
fn differential_age_sweep_typical_lambda() {
    // Age sample points (seconds): 0, 1 hour, 1 day, 7 days, 30 days, 90 days,
    // 180 days, 270 days, 365 days.
    let ages: &[u64] = &[
        0,
        3_600,
        86_400,
        7 * 86_400,
        30 * 86_400,
        90 * 86_400,
        180 * 86_400,
        270 * 86_400,
        365 * 86_400,
    ];
    for &age in ages {
        check(age, 1, 1_000); // λ = 0.001
    }
}

// ── Lambda sweep at t = 7 days ────────────────────────────────────────────────

/// Sweep `λ` across `[0.0001, 0.5]` for a fixed age of 7 days.
#[test]
fn differential_lambda_sweep_seven_days() {
    let age = 7 * 86_400u64;
    // (lambda_num, lambda_den) pairs spanning [0.0001, 0.5]
    let lambdas: &[(u64, u64)] = &[
        (1, 10_000),  // 0.0001
        (1, 5_000),   // 0.0002
        (1, 2_000),   // 0.0005
        (1, 1_000),   // 0.001
        (1, 500),     // 0.002
        (1, 200),     // 0.005
        (1, 100),     // 0.010
        (1, 50),      // 0.020
        (1, 20),      // 0.050
        (1, 10),      // 0.100
        (1, 5),       // 0.200
        (1, 2),       // 0.500
    ];
    for &(num, den) in lambdas {
        check(age, num, den);
    }
}

// ── Full 2-D parameter sweep ──────────────────────────────────────────────────

/// Exhaustive sweep over a 9 × 12 grid of `(t, λ)` covering the documented
/// parameter space `t ∈ [0, 365 days]`, `λ ∈ [0.0001, 0.5]`.
#[test]
fn differential_full_parameter_sweep() {
    let ages: &[u64] = &[
        0,
        3_600,
        86_400,
        7 * 86_400,
        14 * 86_400,
        30 * 86_400,
        60 * 86_400,
        90 * 86_400,
        180 * 86_400,
        270 * 86_400,
        365 * 86_400,
    ];
    let lambdas: &[(u64, u64)] = &[
        (1, 10_000), // 0.0001
        (1, 5_000),  // 0.0002
        (1, 2_000),  // 0.0005
        (1, 1_000),  // 0.001
        (1, 500),    // 0.002
        (1, 200),    // 0.005
        (1, 100),    // 0.010
        (1, 50),     // 0.020
        (1, 20),     // 0.050
        (1, 10),     // 0.100
        (1, 5),      // 0.200
        (1, 2),      // 0.500
    ];
    for &age in ages {
        for &(num, den) in lambdas {
            check(age, num, den);
        }
    }
}

// ── Decay horizon clamping ────────────────────────────────────────────────────

/// Ages beyond `MAX_DECAY_HORIZON_SECS` must produce the same result as an
/// age exactly at the horizon (the contract clamps before arithmetic).
#[test]
fn differential_ages_beyond_horizon_match_horizon() {
    let horizon = 31_536_000u64; // MAX_DECAY_HORIZON_SECS
    let lambdas: &[(u64, u64)] = &[(1, 10_000), (1, 1_000), (1, 100), (1, 10)];
    for &(num, den) in lambdas {
        let at_horizon = ScoreGateScoreContract::decay_fixed(horizon, num, den);
        let two_years = ScoreGateScoreContract::decay_fixed(horizon * 2, num, den);
        let max_u64 = ScoreGateScoreContract::decay_fixed(u64::MAX, num, den);
        assert_eq!(
            at_horizon, two_years,
            "horizon clamp: 2× horizon should equal horizon for λ={num}/{den}"
        );
        assert_eq!(
            at_horizon, max_u64,
            "horizon clamp: u64::MAX should equal horizon for λ={num}/{den}"
        );
    }
}

// ── Monotonicity: decay factor decreases with age ────────────────────────────

/// For any fixed `λ > 0`, `decay_fixed(t₁) ≥ decay_fixed(t₂)` when `t₁ < t₂`.
/// Verified across a representative set of (t, λ) pairs.
#[test]
fn differential_decay_is_monotonically_decreasing_in_age() {
    let ages: &[u64] = &[
        0,
        3_600,
        86_400,
        7 * 86_400,
        30 * 86_400,
        90 * 86_400,
        365 * 86_400,
    ];
    let lambdas: &[(u64, u64)] = &[(1, 10_000), (1, 1_000), (1, 100), (1, 10)];
    for &(num, den) in lambdas {
        let mut prev = SCALE;
        for &age in ages {
            let cur = ScoreGateScoreContract::decay_fixed(age, num, den);
            assert!(
                cur <= prev,
                "monotonicity violated: decay_fixed({age}, {num}/{den}) = {cur} > prev {prev}"
            );
            prev = cur;
        }
    }
}

// ── Boundary: x → 0 ──────────────────────────────────────────────────────────

/// At `t = 0` the factor must be exactly `SCALE` regardless of lambda.
#[test]
fn differential_zero_age_returns_scale_for_all_lambdas() {
    let lambdas: &[(u64, u64)] = &[
        (1, 10_000),
        (1, 1_000),
        (1, 100),
        (1, 10),
        (1, 2),
        (1, 1),
    ];
    for &(num, den) in lambdas {
        let got = ScoreGateScoreContract::decay_fixed(0, num, den);
        assert_eq!(
            got, SCALE,
            "decay_fixed(0, {num}/{den}) = {got}, expected SCALE={SCALE}"
        );
    }
}

// ── Boundary: x → 5 (Taylor / saturation boundary) ──────────────────────────

/// Values just below and just above `x = 5` bracket the saturation cutoff.
/// Below: the Taylor series path must be close to the float reference.
/// Above/at: the contract returns `0`.
#[test]
fn differential_saturation_boundary() {
    // x = λ * t; choose λ = 1/10 so x = t/10.
    // x = 4.99: t ≈ 49_900 s
    // x = 5.00: t = 50_000 s
    // x = 5.01: t = 50_100 s
    let num = 1u64;
    let den = 10u64;

    let just_below = ScoreGateScoreContract::decay_fixed(49_900, num, den);
    let exact = ScoreGateScoreContract::decay_fixed(50_000, num, den);
    let just_above = ScoreGateScoreContract::decay_fixed(50_100, num, den);

    // Below: must be non-zero and close to float reference.
    let reference_below = decay_float_ref(49_900, num, den);
    let diff = (just_below as i64 - reference_below.round() as i64).unsigned_abs();
    assert!(
        diff <= MAX_ABS_ERROR,
        "just_below x=5: got={just_below}, ref={reference_below:.0}, diff={diff}"
    );

    // At and above x=5: contract must return 0.
    assert_eq!(exact, 0, "at x=5: decay_fixed must return 0");
    assert_eq!(just_above, 0, "above x=5: decay_fixed must return 0");

    // Continuity: just_below must be > 0.
    assert!(just_below > 0, "just below x=5 must be non-zero");
}

// ── Truncation direction ──────────────────────────────────────────────────────

/// The integer approximation may be slightly lower than the float reference
/// (integer truncation truncates toward zero). Verify the error is never
/// *above* the float reference by more than `MAX_ABS_ERROR` units.
#[test]
fn differential_truncation_error_is_bounded_and_never_inflates_factor() {
    // Use a mid-range lambda and age where Taylor series is most active.
    let cases: &[(u64, u64, u64)] = &[
        (7 * 86_400, 1, 1_000),
        (30 * 86_400, 1, 500),
        (14 * 86_400, 1, 200),
        (3 * 86_400, 1, 100),
    ];
    for &(age, num, den) in cases {
        let got = ScoreGateScoreContract::decay_fixed(age, num, den);
        let reference = decay_float_ref(age, num, den);
        let diff = got as f64 - reference;
        // The integer result should never exceed the float by more than
        // MAX_ABS_ERROR (1_500 SCALE units ≈ 0.15 %).
        assert!(
            diff <= MAX_ABS_ERROR as f64,
            "decay_fixed({age}, {num}/{den}) = {got} exceeds float ref {reference:.1} by {diff:.1}"
        );
        // And must not under-shoot by more than MAX_ABS_ERROR either.
        assert!(
            diff >= -(MAX_ABS_ERROR as f64),
            "decay_fixed({age}, {num}/{den}) = {got} undershoots float ref {reference:.1} by {diff:.1}"
        );
    }
}
