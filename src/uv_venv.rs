//! uv virtual environment setup helper

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use crate::{artifact, output};
use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed running uv {}: {}", action, source))]
    Exec { action: String, source: io::Error },

    #[snafu(display("uv {} failed ({}): {}", action, status, stderr.trim()))]
    CommandFailed {
        action: String,
        status: ExitStatus,
        stderr: String,
    },

    #[snafu(display("cannot use virtual environment Python {}: {}", path.display(), source))]
    Environment { path: PathBuf, source: io::Error },
}

pub type Result<T = ()> = std::result::Result<T, Error>;

fn run_uv(args: &[&str]) -> Result<()> {
    let action = args.join(" ");
    output::verbose(format!("running: uv {action}"));
    let result = Command::new("uv")
        .args(args)
        .output()
        .context(ExecSnafu { action: &action })?;
    if result.status.success() {
        output::command_output(&result);
        Ok(())
    } else {
        Err(Error::CommandFailed {
            action,
            status: result.status,
            stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        })
    }
}

/// Ensure a local uv virtual environment exists and has required packages installed.
/// This creates `.venv` if it does not already exist.
pub fn ensure_uv_venv(packages: &[&str]) -> Result {
    let venv_path = Path::new(".venv");
    if artifact::existing(venv_path)
        .context(EnvironmentSnafu { path: venv_path })?
        .is_none()
    {
        output::progress("creating uv virtual environment".cyan().bold());
        run_uv(&["venv", ".venv"])?;
    }
    let python = Path::new(".venv/bin/python");
    artifact::regular_file(python).context(EnvironmentSnafu { path: python })?;

    output::progress("installing packages with uv".cyan().bold());
    let mut args = vec!["pip", "install", "--python", ".venv/bin/python"];
    args.extend_from_slice(packages);
    run_uv(&args)
}
