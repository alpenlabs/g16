mod config;
mod proof;
mod run_dir;
mod sp1_artifact;
mod steps;

use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use proof::RunTimeInputs;
use run_dir::{RunDir, StepTiming, cleanup_intermediates, update_latest_symlink, write_summary};
use tracing::{error, info};

const EXPECTED_PUBLIC_VALUES_LEN: usize = 36;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a v5c boolean circuit from a 32-byte SP1 program vkey hash.
    /// The resulting circuit is unvalidated; run `validate-proof` once a proof
    /// is available to assert the verifier accepts it.
    Gen {
        /// Path to a binary file containing the 32-byte SP1 program vkey hash
        /// (the raw output of `sp1_sdk::HashableKey::bytes32_raw()`).
        #[arg(long)]
        vkey: PathBuf,
        /// Parent directory under which a timestamped run dir is created.
        #[arg(long, env = "G16_PIPELINE_RUNS", default_value = "pipeline-runs")]
        runs_dir: PathBuf,
        /// Keep the v5a `g16.ckt` intermediate after success (default: delete it).
        #[arg(long)]
        keep_intermediate: bool,
    },
    /// Validate an existing v5c circuit against a raw SP1 v6 prover artifact
    /// (bincode-encoded `SP1ProofWithPublicValues`, the file an SP1 prover emits
    /// via `proof.save(...)`). Runs only the write-input-bits + cleartext-exec
    /// stages — skips the expensive `g16gen generate` + `ckt-lvl prealloc`, so a
    /// `--vkey`-generated circuit can be validated without regeneration. Writes
    /// `inputs.txt` in the format `gobbletest exec` consumes, then runs the
    /// cleartext-exec sanity check.
    ValidateProof {
        /// Path to the v5c circuit to validate.
        #[arg(long)]
        v5c: PathBuf,
        /// Path to the raw SP1 v6 artifact (bincode `SP1ProofWithPublicValues`).
        #[arg(long)]
        proof: PathBuf,
        /// Parent directory under which a timestamped run dir is created.
        #[arg(long, env = "G16_VALIDATION_RUNS", default_value = "validation-runs")]
        runs_dir: PathBuf,
    },
}

#[monoio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Gen {
            vkey,
            runs_dir,
            keep_intermediate,
        } => run_gen(vkey, runs_dir, keep_intermediate).await,
        Cmd::ValidateProof {
            v5c,
            proof,
            runs_dir,
        } => run_validate(v5c, proof, runs_dir).await,
    };

    if let Err(e) = result {
        error!("{e:#}");
        std::process::exit(1);
    }
}

async fn run_gen(vkey_path: PathBuf, runs_dir: PathBuf, keep_intermediate: bool) -> Result<()> {
    let total_start = Instant::now();

    let vkey_path = fs::canonicalize(&vkey_path)
        .with_context(|| format!("failed to resolve --vkey {:?}", vkey_path))?;
    let source_label = vkey_path.display().to_string();

    let runs_dir = prepare_runs_dir(&runs_dir)?;
    let run = RunDir::create(&runs_dir)?;
    info!(run_dir = ?run.root, "created run directory");

    let mut timings: Vec<StepTiming> = Vec::new();

    let success = match drive_gen(&vkey_path, &run, &mut timings).await {
        Ok(()) => true,
        Err(e) => {
            error!(error = %e, "pipeline failed");
            let _ = write_summary(&run, &source_label, &timings, total_start.elapsed(), false);
            return Err(e);
        }
    };

    cleanup_intermediates(&run, keep_intermediate)?;
    write_summary(
        &run,
        &source_label,
        &timings,
        total_start.elapsed(),
        success,
    )?;
    update_latest_symlink(&runs_dir, &run)?;

    info!(v5c = ?run.v5c_ckt(), "pipeline completed");
    Ok(())
}

async fn run_validate(v5c_path: PathBuf, proof_path: PathBuf, runs_dir: PathBuf) -> Result<()> {
    let total_start = Instant::now();

    let v5c_path = fs::canonicalize(&v5c_path)
        .with_context(|| format!("failed to resolve --v5c {:?}", v5c_path))?;
    let proof_path = fs::canonicalize(&proof_path)
        .with_context(|| format!("failed to resolve --proof {:?}", proof_path))?;

    let runs_dir = prepare_runs_dir(&runs_dir)?;
    let run = RunDir::create(&runs_dir)?;
    info!(run_dir = ?run.root, "created run directory");

    let source_label = format!("v5c={}, proof={}", v5c_path.display(), proof_path.display());
    let mut timings: Vec<StepTiming> = Vec::new();

    let success = match drive_validate(&v5c_path, &proof_path, &run, &mut timings).await {
        Ok(()) => true,
        Err(e) => {
            error!(error = %e, "validate failed");
            let _ = write_summary(&run, &source_label, &timings, total_start.elapsed(), false);
            return Err(e);
        }
    };

    write_summary(
        &run,
        &source_label,
        &timings,
        total_start.elapsed(),
        success,
    )?;
    update_latest_symlink(&runs_dir, &run)?;

    info!(v5c = ?v5c_path, "validation passed");
    Ok(())
}

async fn drive_gen(vkey_path: &Path, run: &RunDir, timings: &mut Vec<StepTiming>) -> Result<()> {
    let t = Instant::now();
    let compile = proof::load_from_vkey_file(vkey_path)?;
    config::write_compile_time_json(&run.compile_time_json(), &compile)?;
    timings.push(StepTiming {
        name: "synth-config",
        duration: t.elapsed(),
    });

    let t = Instant::now();
    info!("step 1/3: g16gen generate");
    steps::run_g16gen("generate", &run.compile_time_json(), &run.root)?;
    if !run.v5a_ckt().exists() {
        bail!("g16gen generated no v5a at {:?}", run.v5a_ckt());
    }
    timings.push(StepTiming {
        name: "g16gen-generate",
        duration: t.elapsed(),
    });

    let t = Instant::now();
    info!("step 2/3: verify");
    match steps::verify(&run.v5a_ckt()).await {
        Ok(true) => {
            timings.push(StepTiming {
                name: "verify",
                duration: t.elapsed(),
            });
        }
        Ok(false) => {
            bail!("verification failed for {:?}", run.v5a_ckt());
        }
        Err(_) => {
            bail!(
                "verification could not be completed for {:?}",
                run.v5a_ckt()
            );
        }
    }

    let t = Instant::now();
    info!("step 3/3: ckt-lvl prealloc");
    steps::prealloc_v5c(&run.v5a_ckt(), &run.v5c_ckt()).await?;
    timings.push(StepTiming {
        name: "ckt-lvl-prealloc",
        duration: t.elapsed(),
    });

    Ok(())
}

async fn drive_validate(
    v5c_path: &Path,
    proof_path: &Path,
    run: &RunDir,
    timings: &mut Vec<StepTiming>,
) -> Result<()> {
    let run_time = sp1_artifact::load_runtime_from_sp1_artifact(proof_path)?;
    check_pv_len(&run_time)?;

    info!("step 1/2: g16gen write-input-bits");
    step_write_input_bits(&run_time, run, timings)?;
    info!("step 2/2: cleartext exec sanity check");
    step_sanity_check(v5c_path, &run.inputs_txt(), timings).await?;

    Ok(())
}

// ---- helpers shared by drive_gen and drive_validate ----

fn check_pv_len(run_time: &RunTimeInputs) -> Result<()> {
    if run_time.public_values.len() != EXPECTED_PUBLIC_VALUES_LEN {
        bail!(
            "public values length {} != {} expected by g16gen (hardcoded \
             INPUT_MESSAGE_LEN at g16/g16gen/src/circuit_args.rs); this pipeline \
             currently supports only 36-byte programs",
            run_time.public_values.len(),
            EXPECTED_PUBLIC_VALUES_LEN,
        );
    }
    Ok(())
}

fn step_write_input_bits(
    run_time: &RunTimeInputs,
    run: &RunDir,
    timings: &mut Vec<StepTiming>,
) -> Result<()> {
    config::write_run_time_json(&run.run_time_json(), run_time)?;
    let t = Instant::now();
    steps::run_g16gen("write-input-bits", &run.run_time_json(), &run.root)?;
    if !run.inputs_txt().exists() {
        bail!("g16gen produced no inputs.txt at {:?}", run.inputs_txt());
    }
    timings.push(StepTiming {
        name: "g16gen-inputs",
        duration: t.elapsed(),
    });
    Ok(())
}

async fn step_sanity_check(v5c: &Path, inputs: &Path, timings: &mut Vec<StepTiming>) -> Result<()> {
    let t = Instant::now();
    steps::sanity_check(v5c, inputs).await?;
    timings.push(StepTiming {
        name: "sanity-check",
        duration: t.elapsed(),
    });
    Ok(())
}

fn prepare_runs_dir(runs_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(runs_dir)
        .with_context(|| format!("failed to create --runs-dir {:?}", runs_dir))?;
    fs::canonicalize(runs_dir)
        .with_context(|| format!("failed to resolve --runs-dir {:?}", runs_dir))
}
