use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::Local;

pub struct RunDir {
    pub root: PathBuf,
}

impl RunDir {
    pub fn create(parent: &Path) -> Result<Self> {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create runs-dir parent {:?}", parent))?;

        let stamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
        let root = parent.join(format!("run-{stamp}"));
        fs::create_dir(&root).with_context(|| format!("failed to create run dir {:?}", root))?;
        Ok(Self { root })
    }

    pub fn compile_time_json(&self) -> PathBuf {
        self.root.join("compile_time.json")
    }

    pub fn run_time_json(&self) -> PathBuf {
        self.root.join("run_time.json")
    }

    pub fn v5a_ckt(&self) -> PathBuf {
        self.root.join("g16.ckt")
    }

    pub fn v5c_ckt(&self) -> PathBuf {
        self.root.join("v5c.ckt")
    }

    pub fn inputs_txt(&self) -> PathBuf {
        self.root.join("inputs.txt")
    }

    pub fn summary_path(&self) -> PathBuf {
        self.root.join("summary.txt")
    }
}

pub struct StepTiming {
    pub name: &'static str,
    pub duration: Duration,
}

pub fn write_summary(
    run: &RunDir,
    source: &str,
    timings: &[StepTiming],
    total: Duration,
    success: bool,
) -> Result<()> {
    let mut out = String::new();
    out.push_str(&format!(
        "status: {}\n",
        if success { "ok" } else { "FAILED" }
    ));
    out.push_str(&format!("source: {}\n", source));
    out.push_str(&format!(
        "started: {}\n",
        Local::now().format("%Y-%m-%d %H:%M:%S %z")
    ));
    out.push_str(&format!("total: {:.2?}\n\n", total));
    out.push_str("steps:\n");
    for t in timings {
        out.push_str(&format!("  {:<18} {:.2?}\n", t.name, t.duration));
    }
    fs::write(run.summary_path(), out).context("failed to write summary.txt")?;
    Ok(())
}

pub fn update_latest_symlink(parent: &Path, run: &RunDir) -> Result<()> {
    let link = parent.join("latest");
    let target = run.root.file_name().context("run dir has no file name")?;

    #[cfg(unix)]
    {
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(target, &link)
            .with_context(|| format!("failed to update 'latest' symlink at {:?}", link))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (link, target);
    }
    Ok(())
}

pub fn cleanup_intermediates(run: &RunDir, keep: bool) -> Result<()> {
    if keep {
        return Ok(());
    }
    let _ = fs::remove_file(run.v5a_ckt());
    Ok(())
}
