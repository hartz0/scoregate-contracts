//! CLI for the schema-gen tool.
//!
//! Regenerates the committed cross-repo artifacts for all four canonical
//! ScoreGate types in contract-spec (XDR) field order:
//!
//! ```text
//! cargo run -p schema-gen                # native spec source (default)
//! cargo run -p schema-gen -- --wasm target/wasm32-unknown-unknown/release/scoregate_score.wasm
//! cargo run -p schema-gen -- --check     # exit non-zero if committed artifacts are stale
//! ```
//!
//! Extended in issue #274 to emit artifacts for `AggregateRiskScore`,
//! `ScoreSubmission`, and `BatchAttestation` in addition to `RiskScore`.

use anyhow::{bail, Context, Result};
use schema_gen::{
    native_aggregate_risk_score_struct, native_batch_attestation_struct,
    native_risk_score_struct, native_score_submission_struct,
    struct_to_json_schema, struct_to_python, struct_to_typescript,
    wasm_aggregate_risk_score_struct, wasm_batch_attestation_struct,
    wasm_risk_score_struct, wasm_score_submission_struct,
    AGGREGATE_RISK_SCORE_NAME, AGGREGATE_RISK_SCORE_PYTHON_FILE,
    AGGREGATE_RISK_SCORE_SCHEMA_FILE, AGGREGATE_RISK_SCORE_TYPESCRIPT_FILE,
    BATCH_ATTESTATION_NAME, BATCH_ATTESTATION_PYTHON_FILE,
    BATCH_ATTESTATION_SCHEMA_FILE, BATCH_ATTESTATION_TYPESCRIPT_FILE,
    DEFAULT_OUTPUT_DIR, PYTHON_FILE, RISK_SCORE_NAME, SCHEMA_FILE,
    SCORE_SUBMISSION_NAME, SCORE_SUBMISSION_PYTHON_FILE,
    SCORE_SUBMISSION_SCHEMA_FILE, SCORE_SUBMISSION_TYPESCRIPT_FILE,
    TYPESCRIPT_FILE,
};
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut wasm_path: Option<String> = None;
    let mut out_dir = DEFAULT_OUTPUT_DIR.to_string();
    let mut check = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--wasm" => {
                i += 1;
                wasm_path = Some(
                    args.get(i).context("`--wasm` requires a path to the contract WASM")?.clone(),
                );
            }
            "--out" => {
                i += 1;
                out_dir = args.get(i).context("`--out` requires a directory")?.clone();
            }
            "--check" => check = true,
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            unknown => bail!("unknown argument `{unknown}` (see --help)"),
        }
        i += 1;
    }

    // Determine extraction source and load all four structs.
    let (source, risk_score, aggregate, submission, attestation) = match &wasm_path {
        Some(path) => {
            let bytes =
                std::fs::read(path).with_context(|| format!("reading contract WASM {path}"))?;
            (
                format!("contract WASM `{path}` (contractspecv0)"),
                wasm_risk_score_struct(&bytes)?,
                wasm_aggregate_risk_score_struct(&bytes)?,
                wasm_score_submission_struct(&bytes)?,
                wasm_batch_attestation_struct(&bytes)?,
            )
        }
        None => (
            "contracts/scoregate-score/src/types.rs (native spec_xdr())".to_string(),
            native_risk_score_struct()?,
            native_aggregate_risk_score_struct()?,
            native_score_submission_struct()?,
            native_batch_attestation_struct()?,
        ),
    };

    let dir = PathBuf::from(&out_dir);
    std::fs::create_dir_all(&dir)?;

    // Helper: render JSON + TS + Python for one struct and write them if changed.
    let mut any_changed = false;

    let write_type = |schema_file: &str,
                      ts_file: &str,
                      py_file: &str,
                      struct_: &soroban_sdk::xdr::ScSpecUdtStructV0,
                      dir: &Path,
                      changed: &mut bool|
     -> Result<()> {
        let schema_text = {
            let mut t = serde_json::to_string_pretty(&struct_to_json_schema(struct_))?;
            t.push('\n');
            t
        };
        let ts_text = struct_to_typescript(struct_);
        let py_text = struct_to_python(struct_);
        *changed |= write_if_changed(&dir.join(schema_file), &schema_text)?;
        *changed |= write_if_changed(&dir.join(ts_file), &ts_text)?;
        *changed |= write_if_changed(&dir.join(py_file), &py_text)?;
        Ok(())
    };

    write_type(SCHEMA_FILE, TYPESCRIPT_FILE, PYTHON_FILE, &risk_score, &dir, &mut any_changed)?;
    write_type(
        AGGREGATE_RISK_SCORE_SCHEMA_FILE,
        AGGREGATE_RISK_SCORE_TYPESCRIPT_FILE,
        AGGREGATE_RISK_SCORE_PYTHON_FILE,
        &aggregate,
        &dir,
        &mut any_changed,
    )?;
    write_type(
        SCORE_SUBMISSION_SCHEMA_FILE,
        SCORE_SUBMISSION_TYPESCRIPT_FILE,
        SCORE_SUBMISSION_PYTHON_FILE,
        &submission,
        &dir,
        &mut any_changed,
    )?;
    write_type(
        BATCH_ATTESTATION_SCHEMA_FILE,
        BATCH_ATTESTATION_TYPESCRIPT_FILE,
        BATCH_ATTESTATION_PYTHON_FILE,
        &attestation,
        &dir,
        &mut any_changed,
    )?;

    println!("schema-gen: {RISK_SCORE_NAME}, {AGGREGATE_RISK_SCORE_NAME}, {SCORE_SUBMISSION_NAME}, {BATCH_ATTESTATION_NAME} from {source}");
    println!(
        "schema-gen: emitted {} artifact sets under {}/",
        4,
        dir.display()
    );

    if check && any_changed {
        bail!(
            "generated artifacts are stale; \
             run `cargo run -p schema-gen` and commit the changes"
        );
    }
    Ok(())
}

/// Write `contents` to `path` only when it differs; returns whether anything
/// was written. Used both for regeneration and for CI-style drift detection.
fn write_if_changed(path: &Path, contents: &str) -> Result<bool> {
    match std::fs::read_to_string(path) {
        Ok(existing) if existing == contents => Ok(false),
        Ok(_) => {
            std::fs::write(path, contents)?;
            Ok(true)
        }
        Err(_) => {
            std::fs::write(path, contents)?;
            Ok(true)
        }
    }
}

fn print_usage() {
    println!(
        "schema-gen — generate cross-repo bindings from the Soroban contract-spec\n\n\
         Emits JSON Schema, TypeScript, and Python (Pydantic) artifacts for:\n\
         - RiskScore\n\
         - AggregateRiskScore  (issue #274)\n\
         - ScoreSubmission     (issue #274)\n\
         - BatchAttestation    (issue #274)\n\n\
         USAGE:\n    schema-gen [OPTIONS]\n\n\
         OPTIONS:\n    --wasm <path>   Read specs from a built/deployed contract WASM\n\
         \x20                  (default: native spec_xdr() from the source crate)\n\
         \x20  --out <dir>     Output directory (default: schemas/)\n\
         \x20  --check         Fail instead of rewriting when committed artifacts are stale\n\
         \x20  -h, --help      Print this help\n"
    );
}
