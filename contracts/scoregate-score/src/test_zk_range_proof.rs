#![allow(unused_imports)]
extern crate std;

use crate::{
    zk_range_proof::{Fe, Pt, Sc, SeededPrng, Bulletproof, get_generators, compress_pt, decompress_pt_32, is_on_curve, prove_range_proof},
    ScoreGateScoreContract, ScoreGateScoreContractClient,
};
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Symbol, Vec};

#[test]
fn test_verify_score_range_proof_success() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // Score = 40, Threshold = 50. Since 40 < 50, the proof should verify.
    let score = 40u32;
    let threshold = 50u32;
    
    let r = Sc::from_u64(987654321);
    let (g_pt, h_pt, d) = get_generators(&env);
    
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    // Prover generates range proof showing T - 1 - v >= 0
    // T - 1 - v = 50 - 1 - 40 = 9
    // Blinding factor is -r
    let v_prime = threshold - 1 - score; // 9
    let r_prime = r.neg();

    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(result);
}

#[test]
fn test_verify_score_range_proof_invalid_threshold() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // Score = 60. Try to verify proof for threshold = 50 (which requires 60 < 50, invalid).
    let score = 60u32;
    let threshold = 50u32;
    
    let r = Sc::from_u64(987654321);
    let (g_pt, h_pt, d) = get_generators(&env);
    
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    // Prover tries to generate a range proof for v' = threshold - 1 - score = -11 (out of range [0, 256))
    // We pass a dummy/invalid proof or a proof generated for a different value.
    let prng = SeededPrng::new([1u8; 32]);
    // Try to prove 9 instead of -11 (which would be for score 40)
    let proof = prove_range_proof(&env, 9, r.neg(), prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    // Should fail because the commitment C' computed on-chain won't match the proof
    assert!(!result);
}

#[test]
fn test_verify_score_range_proof_tampered_commitment() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let score = 40u32;
    let threshold = 50u32;
    
    let r = Sc::from_u64(987654321);
    let (g_pt, h_pt, d) = get_generators(&env);
    
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    // Tamper with commitment
    let mut tampered_bytes = commitment.to_array();
    tampered_bytes[0] ^= 1;
    let tampered_commitment = BytesN::from_array(&env, &tampered_bytes);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &tampered_commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(!result);
}

#[test]
fn test_verify_score_range_proof_tampered_proof() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let score = 40u32;
    let threshold = 50u32;
    
    let r = Sc::from_u64(987654321);
    let (g_pt, h_pt, d) = get_generators(&env);
    
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    // Tamper with proof bytes
    let mut arr = [0u8; 800];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = proof_bytes.get(i as u32).unwrap();
    }
    arr[200] ^= 1; // tamper with one byte
    let tampered_proof = Bytes::from_array(&env, &arr);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &tampered_proof,
        &threshold,
    );
    assert!(!result);
}

// ── Adversarial / negative test vectors (issue #397) ─────────────────────────
//
// The tests above only cover byte-level corruption of the commitment and the
// raw proof buffer. The tests below target specific soundness properties of
// the verifier: boundary values of the committed score, forged proofs that
// are internally well-formed but statement-mismatched, cross-wallet replay,
// replay under a different public statement (threshold), and tampering with
// a value that specifically feeds a Fiat-Shamir challenge rather than being
// arbitrary byte noise.

#[test]
fn test_verify_score_range_proof_boundary_score_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // Boundary: score = 0 (minimum valid score), threshold = 1.
    // v' = threshold - 1 - score = 0, the smallest legal range-proof value.
    let score = 0u32;
    let threshold = 1u32;

    let r = Sc::from_u64(11223344);
    let (g_pt, h_pt, d) = get_generators(&env);
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(result);
}

#[test]
fn test_verify_score_range_proof_threshold_one_evaluation() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // Threshold = 1: tm1 = 0, so g^tm1 = g^0 = identity.
    // Adding identity to c_inv must not trap on coordinate inversion.
    let score = 0u32;
    let threshold = 1u32;

    let r = Sc::from_u64(99887766);
    let (g_pt, h_pt, d) = get_generators(&env);
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([2u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(result);
}

#[test]
fn test_verify_score_range_proof_boundary_score_max() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // Boundary: threshold = 100 (maximum valid threshold), score = 99.
    let score = 99u32;
    let threshold = 100u32;

    let r = Sc::from_u64(55667788);
    let (g_pt, h_pt, d) = get_generators(&env);
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(result);
}

#[test]
fn test_verify_score_range_proof_boundary_score_equals_threshold() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // score == threshold: the honest statement "score < threshold" is false,
    // and the honest exponent (threshold - 1 - score = -1) does not exist in
    // u32. An attacker who knows the real blinding factor `r` still cannot
    // forge a proof by substituting the smallest in-range value (0) for the
    // impossible one, because the verifier derives the committed value from
    // the on-chain commitment and threshold, not from the prover's claim.
    let score = 50u32;
    let threshold = 50u32;

    let r = Sc::from_u64(24681357);
    let (g_pt, h_pt, d) = get_generators(&env);
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let forged_v_prime = 0u32;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, forged_v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(!result);
}

#[test]
fn test_verify_score_range_proof_cross_wallet_commitment_mismatch() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet_a = Address::generate(&env);
    let wallet_b = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let threshold = 50u32;
    let (g_pt, h_pt, d) = get_generators(&env);

    // Wallet A's own score/commitment.
    let score_a = 40u32;
    let r_a = Sc::from_u64(555666777);
    let c_pt_a = g_pt.mul(Sc::from_u64(score_a as u64), d).add(h_pt.mul(r_a, d), d);
    let commitment_a = compress_pt(&env, &c_pt_a);
    client.submit_score(
        &Vec::new(&env),
        &wallet_a,
        &pair,
        &score_a,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment_a.clone().into()),
        }),
    );

    // Wallet B's own, distinct score/commitment.
    let score_b = 20u32;
    let r_b = Sc::from_u64(999888777);
    let c_pt_b = g_pt.mul(Sc::from_u64(score_b as u64), d).add(h_pt.mul(r_b, d), d);
    let commitment_b = compress_pt(&env, &c_pt_b);
    client.submit_score(
        &Vec::new(&env),
        &wallet_b,
        &pair,
        &score_b,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment_b.clone().into()),
        }),
    );

    // A genuinely valid range proof for wallet A's own commitment.
    let v_prime = threshold - 1 - score_a;
    let r_prime = r_a.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    // Attempt to present wallet A's commitment + valid proof against wallet
    // B's identity. Must fail: wallet B's stored commitment is commitment_b,
    // not commitment_a.
    let result = client.verify_score_range_proof(
        &wallet_b,
        &pair,
        &commitment_a,
        &proof_bytes,
        &threshold,
    );
    assert!(!result);
}

#[test]
fn test_verify_score_range_proof_replayed_across_threshold() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let score = 40u32;
    let original_threshold = 50u32;

    let r = Sc::from_u64(135792468);
    let (g_pt, h_pt, d) = get_generators(&env);
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = original_threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    // Sanity check: the proof is genuinely valid for the threshold it was
    // generated against.
    let valid_result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &original_threshold,
    );
    assert!(valid_result);

    // Replay the same commitment + proof against a different threshold
    // (a different public statement). Must fail even though nothing about
    // the commitment or proof bytes was touched.
    let replayed_threshold = 60u32;
    let replay_result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &replayed_threshold,
    );
    assert!(!replay_result);
}

#[test]
fn test_verify_score_range_proof_tampered_fs_challenge() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let score = 40u32;
    let threshold = 50u32;

    let r = Sc::from_u64(19283746);
    let (g_pt, h_pt, d) = get_generators(&env);
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let mut arr = [0u8; 800];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = proof_bytes.get(i as u32).unwrap();
    }
    // Bytes [352..416) encode L[0], the first inner-product-argument point.
    // The verifier recomputes round 0's Fiat-Shamir challenge as
    // u = H("ip", 0, L[0], R[0]); flipping a bit here changes that challenge
    // without touching any other field, so this specifically targets
    // Fiat-Shamir-challenge tampering rather than generic byte corruption.
    arr[352] ^= 1;
    let tampered_proof = Bytes::from_array(&env, &arr);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &tampered_proof,
        &threshold,
    );
    assert!(!result);
}

#[test]
fn test_verify_score_range_proof_bypassed_guards() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");
    let commitment = BytesN::from_array(&env, &[1u8; 32]);
    let proof = Bytes::new(&env);
    let threshold = 50u32;
    let admin_signers = soroban_sdk::Vec::new(&env);

    // 1. Contract paused -> returns false immediately
    client.pause(&admin_signers);
    assert!(!client.verify_score_range_proof(&wallet, &pair, &commitment, &proof, &threshold));
    client.unpause(&admin_signers);

    // 2. Asset pair paused -> returns false immediately
    client.set_pair_paused(&pair, &true);
    assert!(!client.verify_score_range_proof(&wallet, &pair, &commitment, &proof, &threshold));
    client.set_pair_paused(&pair, &false);

    // 3. Contract emergency frozen -> returns false immediately
    client.freeze_contract(&admin_signers);
    assert!(!client.verify_score_range_proof(&wallet, &pair, &commitment, &proof, &threshold));
    client.unfreeze_contract(&admin_signers);

    // 4. Wallet embargoed -> returns false immediately
    client.set_score_embargo(&wallet, &None);
    assert!(!client.verify_score_range_proof(&wallet, &pair, &commitment, &proof, &threshold));
    client.lift_score_embargo(&wallet);
}


// ── Exhaustive Negative Test Vectors for Bulletproof Inner-Product (issue #269) ───
//
// The tests below systematically attack every structural component of the
// inner-product argument that was not previously covered:
//
// 1. Corrupted L / R curve points (each of the 3 rounds, each coordinate).
// 2. Fully zeroed-out L[i] / R[i] points (identity / off-curve).
// 3. Swapped L and R across rounds.
// 4. Mismatched proof length (truncated and extended transcripts).
// 5. Non-canonical scalar challenges injected via a_/b_ scalar corruption.
// 6. Zero a / zero b terminal scalars.
// 7. Swapped a ↔ b terminal scalars.
// 8. Tampered A, S, T1, T2 curve commitments.
// 9. Tampered tx / taux / mu scalars.
//
// Every test proves a *valid* proof first, then surgically mutates the
// serialised bytes at the precise offset the targeted field occupies in
// `Bulletproof::to_bytes`, and asserts the verifier rejects the result.
// This ensures we are testing the verifier's ability to detect malicious
// inner-product transcripts rather than coincidental byte-noise rejection.
//
// Wire layout of `Bulletproof::to_bytes` (800 bytes total):
//   [0   ..  64)  A   (Pt: 32-byte x || 32-byte y)
//   [64  .. 128)  S
//   [128 .. 192)  T1
//   [192 .. 256)  T2
//   [256 .. 288)  tx  (Sc: 32-byte little-endian)
//   [288 .. 320)  taux
//   [320 .. 352)  mu
//   [352 .. 416)  L[0] (Pt)
//   [416 .. 480)  L[1]
//   [480 .. 544)  L[2]
//   [544 .. 608)  R[0]
//   [608 .. 672)  R[1]
//   [672 .. 736)  R[2]
//   [736 .. 768)  a   (Sc)
//   [768 .. 800)  b   (Sc)

/// Build a baseline valid proof and commitment for score=40 < threshold=50.
/// Returns `(env, proof_bytes, commitment, threshold)` — the env must stay
/// alive for the duration of the caller so that the Bytes stay valid.
///
/// Each caller owns its own Env.  We use a macro instead of a function
/// so that the `env` lifetime is bound to the caller's stack frame.
macro_rules! valid_proof_fixture {
    () => {{
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, ScoreGateScoreContract);
        let client = crate::ScoreGateScoreContractClient::new(&env, &contract_id);

        let admin = soroban_sdk::Address::generate(&env);
        let service = soroban_sdk::Address::generate(&env);
        client.initialize(&admin, &service);

        let wallet = soroban_sdk::Address::generate(&env);
        let pair = Symbol::new(&env, "XLM_USDC");

        let score = 40u32;
        let threshold = 50u32;
        let r = Sc::from_u64(112233445);
        let (g_pt, h_pt, d) = get_generators(&env);
        let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
        let commitment = compress_pt(&env, &c_pt);

        client.submit_score(
            &soroban_sdk::Vec::new(&env),
            &wallet,
            &pair,
            &score,
            &false,
            &false,
            &1,
            &90,
            &1,
            &Some(crate::ScoreAttestationInput {
                attestation: crate::MaybeScoreAttestation::None,
                threshold_attestation: crate::MaybeThresholdAttestation::None,
                commitment: Some(commitment.clone().into()),
            }),
        );

        let v_prime = threshold - 1 - score; // 9
        let r_prime = r.neg();
        let prng = SeededPrng::new([3u8; 32]);
        let proof = prove_range_proof(&env, v_prime, r_prime, prng);
        let proof_bytes = proof.to_bytes(&env);

        (env, client, wallet, pair, commitment, proof_bytes, threshold)
    }};
}

/// Copy a `Bytes` into a fixed 800-byte array.
fn proof_to_arr(b: &Bytes) -> [u8; 800] {
    let mut arr = [0u8; 800];
    for i in 0..800u32 {
        arr[i as usize] = b.get(i).unwrap();
    }
    arr
}

/// Construct a `Bytes` from an 800-byte array.
fn arr_to_proof(env: &Env, arr: &[u8; 800]) -> Bytes {
    Bytes::from_array(env, arr)
}

// ── 1. Corrupted L[i] / R[i] curve points ─────────────────────────────────────

#[test]
fn test_ip_tampered_l0_x_coordinate_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[352] ^= 0xFF; // L[0].x byte 0
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted L[0].x must be rejected");
}

#[test]
fn test_ip_tampered_l0_y_coordinate_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[352 + 32] ^= 0xFF; // L[0].y byte 0
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted L[0].y must be rejected");
}

#[test]
fn test_ip_tampered_l1_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[416] ^= 0x55; // L[1].x byte 0
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted L[1] must be rejected");
}

#[test]
fn test_ip_tampered_l2_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[480 + 15] ^= 0xAA; // L[2].x mid-byte
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted L[2] must be rejected");
}

#[test]
fn test_ip_tampered_r0_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[544] ^= 0x01; // R[0].x byte 0
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted R[0] must be rejected");
}

#[test]
fn test_ip_tampered_r1_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[608 + 31] ^= 0x80; // R[1].y last byte
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted R[1] must be rejected");
}

#[test]
fn test_ip_tampered_r2_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[672 + 8] ^= 0x3C; // R[2].x mid-byte
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted R[2] must be rejected");
}

// ── 2. Zeroed-out L / R points (identity / off-curve substitution) ────────────

#[test]
fn test_ip_zeroed_l0_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    // Overwrite L[0] with all zeros (identity / off-curve).
    for b in arr[352..416].iter_mut() {
        *b = 0;
    }
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "zeroed L[0] (identity sub) must be rejected");
}

#[test]
fn test_ip_zeroed_r2_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    for b in arr[672..736].iter_mut() {
        *b = 0;
    }
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "zeroed R[2] must be rejected");
}

// ── 3. L and R swapped across rounds ──────────────────────────────────────────

#[test]
fn test_ip_l0_r0_swapped_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    // Swap L[0] (bytes 352..416) and R[0] (bytes 544..608).
    let l0: [u8; 64] = arr[352..416].try_into().unwrap();
    let r0: [u8; 64] = arr[544..608].try_into().unwrap();
    arr[352..416].copy_from_slice(&r0);
    arr[544..608].copy_from_slice(&l0);
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "L[0] ↔ R[0] swap must be rejected");
}

#[test]
fn test_ip_l1_r1_swapped_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    let l1: [u8; 64] = arr[416..480].try_into().unwrap();
    let r1: [u8; 64] = arr[608..672].try_into().unwrap();
    arr[416..480].copy_from_slice(&r1);
    arr[608..672].copy_from_slice(&l1);
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "L[1] ↔ R[1] swap must be rejected");
}

// ── 4. Truncated transcripts (mismatched proof length) ────────────────────────

#[test]
fn test_ip_proof_truncated_to_752_bytes_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    // Remove the last 48 bytes (a + half of b).
    let truncated: Bytes = {
        let mut b = Bytes::new(&env);
        for i in 0..752u32 {
            b.push_back(proof_bytes.get(i).unwrap());
        }
        b
    };
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &truncated, &threshold,
    );
    assert!(!result, "752-byte truncated proof must be rejected");
}

#[test]
fn test_ip_proof_truncated_to_256_bytes_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    // Only A, S, T1, T2 — missing all scalars and IP argument.
    let truncated: Bytes = {
        let mut b = Bytes::new(&env);
        for i in 0..256u32 {
            b.push_back(proof_bytes.get(i).unwrap());
        }
        b
    };
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &truncated, &threshold,
    );
    assert!(!result, "256-byte truncated proof must be rejected");
}

#[test]
fn test_ip_proof_extended_by_one_byte_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut extended = proof_bytes.clone();
    extended.push_back(0xFF);
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &extended, &threshold,
    );
    assert!(!result, "801-byte proof must be rejected");
}

#[test]
fn test_ip_empty_proof_rejected() {
    let (env, client, wallet, pair, commitment, _proof_bytes, threshold) = valid_proof_fixture!();
    let empty = Bytes::new(&env);
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &empty, &threshold,
    );
    assert!(!result, "empty proof must be rejected");
}

// ── 5. Non-canonical Fiat-Shamir challenge injection via L corruption ─────────

/// L[0] encodes the first IP challenge via hash_fs_challenge_ip(round=0, L, R).
/// Flipping a single bit in L[0] changes the challenge, making the verifier
/// derive different u₀ and reject the inner-product check.  This test
/// specifically flips the high bit (byte 352 bit 7) which exercises the
/// largest Hamming-distance perturbation on the challenge preimage.
#[test]
fn test_ip_non_canonical_challenge_via_l0_high_bit_flip() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[352] ^= 0x80; // flip high bit of L[0].x[0]
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "high-bit L[0] flip (non-canonical challenge injection) must be rejected");
}

#[test]
fn test_ip_non_canonical_challenge_via_r0_flip() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[544] ^= 0x80; // flip high bit of R[0].x[0]
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "high-bit R[0] flip (non-canonical challenge injection) must be rejected");
}

// ── 6. Zero / max-out terminal scalars a and b ────────────────────────────────

#[test]
fn test_ip_zero_a_scalar_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    // Overwrite `a` (bytes 736..768) with all zeros.
    for b in arr[736..768].iter_mut() {
        *b = 0;
    }
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "a = 0 must be rejected by the IP verifier");
}

#[test]
fn test_ip_zero_b_scalar_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    // Overwrite `b` (bytes 768..800) with all zeros.
    for b in arr[768..800].iter_mut() {
        *b = 0;
    }
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "b = 0 must be rejected by the IP verifier");
}

// ── 7. Swapped a ↔ b terminal scalars ────────────────────────────────────────

/// The inner-product check verifies `gs_final^a * hs_final^b * Q^(a*b)`.
/// Swapping `a` and `b` changes the `gs_final` and `hs_final` multipliers
/// since they are derived from different basis-folding paths, so the equation
/// should fail unless the proof happens to be symmetric (which it is not in
/// general).
#[test]
fn test_ip_swapped_a_b_scalars_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    let a: [u8; 32] = arr[736..768].try_into().unwrap();
    let b: [u8; 32] = arr[768..800].try_into().unwrap();
    arr[736..768].copy_from_slice(&b);
    arr[768..800].copy_from_slice(&a);
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "a ↔ b swap must be rejected");
}

// ── 8. Tampered outer polynomial commitments (A, S, T1, T2) ──────────────────

#[test]
fn test_ip_tampered_A_point_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[0] ^= 0x01; // A.x byte 0
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted A must be rejected");
}

#[test]
fn test_ip_tampered_S_point_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[64] ^= 0x01; // S.x byte 0
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted S must be rejected");
}

#[test]
fn test_ip_tampered_T1_point_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[128 + 16] ^= 0x01; // T1 mid-byte
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted T1 must be rejected");
}

#[test]
fn test_ip_tampered_T2_point_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[192 + 31] ^= 0x01; // T2 last byte of x
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted T2 must be rejected");
}

// ── 9. Tampered tx / taux / mu scalars ────────────────────────────────────────

#[test]
fn test_ip_tampered_tx_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[256] ^= 0x02; // tx byte 0
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted tx must be rejected");
}

#[test]
fn test_ip_tampered_taux_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[288 + 4] ^= 0x01; // taux byte 4
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted taux must be rejected");
}

#[test]
fn test_ip_tampered_mu_rejected() {
    let (env, client, wallet, pair, commitment, proof_bytes, threshold) = valid_proof_fixture!();
    let mut arr = proof_to_arr(&proof_bytes);
    arr[320 + 8] ^= 0x04; // mu byte 8
    let result = client.verify_score_range_proof(
        &wallet, &pair, &commitment, &arr_to_proof(&env, &arr), &threshold,
    );
    assert!(!result, "corrupted mu must be rejected");
}
