use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde_json::json;

static QUIET: AtomicBool = AtomicBool::new(false);
static JSON: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicU8 = AtomicU8::new(0);
static WARNINGS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
static DOWNLOADS: OnceLock<MultiProgress> = OnceLock::new();

#[derive(Debug, Clone)]
pub enum StepStatus {
    Completed,
    Skipped,
    Failed,
    /// Would run, but `--dry-run` stopped it.
    Planned,
}

impl StepStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
            Self::Planned => "planned",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Step {
    pub name: String,
    pub status: StepStatus,
    pub detail: String,
    pub required: bool,
}

impl Step {
    pub fn completed(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: StepStatus::Completed,
            detail: detail.into(),
            required: false,
        }
    }

    pub fn skipped(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: StepStatus::Skipped,
            detail: detail.into(),
            required: false,
        }
    }

    pub fn planned(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: StepStatus::Planned,
            detail: detail.into(),
            required: false,
        }
    }

    pub fn failed(name: impl Into<String>, detail: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            status: StepStatus::Failed,
            detail: detail.into(),
            required,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub command: &'static str,
    pub dry_run: bool,
    pub steps: Vec<Step>,
}

impl Summary {
    pub fn new(command: &'static str) -> Self {
        Self {
            command,
            dry_run: false,
            steps: Vec::new(),
        }
    }

    pub fn success(&self) -> bool {
        !self
            .steps
            .iter()
            .any(|step| step.required && matches!(step.status, StepStatus::Failed))
    }

    pub fn push(&mut self, step: Step) {
        self.steps.push(step);
    }
}

pub fn configure(quiet: bool, verbose: u8, json_mode: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
    VERBOSE.store(verbose, Ordering::Relaxed);
    JSON.store(json_mode, Ordering::Relaxed);
    if quiet || json_mode {
        colored::control::set_override(false);
    }
    warnings().lock().expect("warnings lock").clear();
}

fn warnings() -> &'static Mutex<Vec<String>> {
    WARNINGS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn is_json() -> bool {
    JSON.load(Ordering::Relaxed)
}

fn downloads() -> &'static MultiProgress {
    DOWNLOADS.get_or_init(MultiProgress::new)
}

fn download_label(url: &str) -> &str {
    url.split('?')
        .next()
        .unwrap_or(url)
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|label| !label.is_empty())
        .unwrap_or("download")
}

pub fn download_progress(url: &str, total: Option<u64>) -> ProgressBar {
    if QUIET.load(Ordering::Relaxed) || is_json() {
        return ProgressBar::hidden();
    }

    let label = format!("downloading {}", download_label(url));
    let bar = match total {
        Some(total) => ProgressBar::new(total).with_style(
            ProgressStyle::with_template(
                "{msg:.green} [{bar:30.cyan/blue}] {bytes}/{total_bytes} {bytes_per_sec}",
            )
            .expect("valid download progress template")
            .progress_chars("=>-"),
        ),
        None => {
            let bar = ProgressBar::new_spinner().with_style(
                ProgressStyle::with_template(
                    "{spinner:.green} {msg:.green} {bytes} {bytes_per_sec}",
                )
                .expect("valid download spinner template"),
            );
            bar.enable_steady_tick(Duration::from_millis(100));
            bar
        }
    };
    bar.set_message(label);
    downloads().add(bar)
}

pub fn progress(message: impl std::fmt::Display) {
    if !QUIET.load(Ordering::Relaxed) && !is_json() {
        println!("{message}");
    }
}

pub fn verbose(message: impl std::fmt::Display) {
    if VERBOSE.load(Ordering::Relaxed) > 0 && !is_json() {
        eprintln!("{message}");
    }
}

pub fn warning(message: impl Into<String>) {
    let message = message.into();
    if is_json() {
        warnings().lock().expect("warnings lock").push(message);
    } else {
        eprintln!("{}", format!("warning: {message}").magenta().bold());
    }
}

pub fn error(message: impl AsRef<str>) {
    if is_json() {
        println!(
            "{}",
            json!({
                "success": false,
                "error": message.as_ref(),
                "warnings": warnings().lock().expect("warnings lock").clone(),
            })
        );
    } else {
        eprintln!("{}", format!("error: {}", message.as_ref()).red().bold());
    }
}

pub fn render_summary(summary: &Summary) {
    if is_json() {
        let warnings = warnings().lock().expect("warnings lock").clone();
        let steps = summary
            .steps
            .iter()
            .map(|step| {
                json!({
                    "name": step.name,
                    "status": step.status.as_str(),
                    "detail": step.detail,
                    "required": step.required,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            json!({
                "command": summary.command,
                "dry_run": summary.dry_run,
                "success": summary.success(),
                "steps": steps,
                "warnings": warnings,
            })
        );
        return;
    }

    let dry_run = summary.dry_run;

    if !QUIET.load(Ordering::Relaxed) {
        println!();
        if dry_run {
            println!("{}", "plan (dry run, nothing was changed)".bold());
        } else {
            println!("{}", "summary".bold());
        }
        for step in &summary.steps {
            let marker = match step.status {
                StepStatus::Completed => "✓".green(),
                StepStatus::Skipped => "-".yellow(),
                StepStatus::Failed => "✗".red(),
                StepStatus::Planned => "→".cyan(),
            };
            println!("{} {}: {}", marker, step.name, step.detail);
        }
        if dry_run {
            println!();
            println!("Run again without --dry-run to apply.");
        }
    } else if dry_run {
        let planned = summary
            .steps
            .iter()
            .filter(|step| matches!(step.status, StepStatus::Planned))
            .count();
        println!("planned: {planned} (dry run)");
    } else {
        let completed = summary
            .steps
            .iter()
            .filter(|step| matches!(step.status, StepStatus::Completed))
            .count();
        let skipped = summary
            .steps
            .iter()
            .filter(|step| matches!(step.status, StepStatus::Skipped))
            .count();
        let failed = summary
            .steps
            .iter()
            .filter(|step| matches!(step.status, StepStatus::Failed))
            .count();
        println!("completed: {completed}, skipped: {skipped}, failed: {failed}");
    }
}

#[cfg(test)]
mod tests {
    use super::download_label;

    #[test]
    fn download_label_uses_the_last_url_path_segment() {
        assert_eq!(
            download_label("https://example.com/pool/libc6.deb?download=1"),
            "libc6.deb"
        );
        assert_eq!(download_label("https://example.com/pool/glibc/"), "glibc");
    }
}
