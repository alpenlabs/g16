mod config;
mod proof;
mod run_dir;
mod steps;

use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tracing::{error, info};

use run_dir::{RunDir, StepTiming, cleanup_intermediates, update_latest_symlink, write_summary};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a v5c boolean circuit from a 32-byte SP1 program vkey hash.
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

    fs::create_dir_all(&runs_dir)
        .with_context(|| format!("failed to create --runs-dir {:?}", runs_dir))?;
    let runs_dir = fs::canonicalize(&runs_dir)
        .with_context(|| format!("failed to resolve --runs-dir {:?}", runs_dir))?;

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

async fn drive_gen(vkey_path: &Path, run: &RunDir, timings: &mut Vec<StepTiming>) -> Result<()> {
    let t = Instant::now();
    let compile = proof::load_from_vkey_file(vkey_path)?;
    config::write_compile_time_json(&run.compile_time_json(), &compile)?;
    timings.push(StepTiming {
        name: "synth-config",
        duration: t.elapsed(),
    });

    let t = Instant::now();
    info!("step 1/2: g16gen generate");
    steps::run_g16gen("generate", &run.compile_time_json(), &run.root)?;
    if !run.v5a_ckt().exists() {
        bail!("g16gen generated no v5a at {:?}", run.v5a_ckt());
    }
    timings.push(StepTiming {
        name: "g16gen-generate",
        duration: t.elapsed(),
    });

    let t = Instant::now();
    info!("step 2/2: ckt-lvl prealloc");
    steps::prealloc_v5c(&run.v5a_ckt(), &run.v5c_ckt()).await?;
    timings.push(StepTiming {
        name: "ckt-lvl-prealloc",
        duration: t.elapsed(),
    });

    Ok(())
}
