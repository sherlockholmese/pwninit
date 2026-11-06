//! Command-line option handling

use crate::cpu_arch::CpuArch;
use crate::elf;
use crate::is_bin;
use crate::is_ld;
use crate::is_libc;
use crate::kernel_image;
use crate::kernel_initramfs;
use crate::output;

use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand, ValueEnum};
use colored::Color;
use colored::Colorize;
use derive_setters::Setters;
use ex::fs;
use ex::io;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchMode {
    Patchelf,
    Manual,
}

/// How to rewrite the binary's interpreter and library paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PatchStrategy {
    /// Use `patchelf` to set RPATH and the interpreter (default).
    Patchelf,
    /// Rewrite ELF bytes in place without `patchelf`.
    Manual,
}

/// An optional setup step that `--skip` can turn off.
///
/// Not every step applies to every command; `validate` rejects a step that
/// does not belong to the command it was given to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SkipStep {
    /// Downloading debug symbols and unstripping libc (pwn).
    Unstrip,
    /// Patching the binary's interpreter / library paths (pwn).
    Patch,
    /// Writing the solve-script / exploit template (pwn, rev, kernel).
    Template,
    /// Extracting `vmlinux` from the kernel image (kernel).
    Vmlinux,
    /// Copying kernel modules out of the initramfs (kernel).
    Modules,
}

impl SkipStep {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unstrip => "unstrip",
            Self::Patch => "patch",
            Self::Template => "template",
            Self::Vmlinux => "vmlinux",
            Self::Modules => "modules",
        }
    }
}

/// Repository used to locate debug symbols while initializing a pwn challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DebugSource {
    /// Select Launchpad for Ubuntu glibc and Debian repositories otherwise.
    Auto,
    Launchpad,
    Debian,
}


#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("ELF detection error: {}", source))]
    ElfDetect { source: elf::detect::Error },

    #[snafu(display("failed reading current directory entry: {}", source))]
    DirEnt { source: io::Error },

    #[snafu(display("failed reading current directory: {}", source))]
    ReadDir { source: io::Error },

    #[snafu(display(
        "multiple {} candidates found: {}; specify one explicitly",
        kind,
        candidates
    ))]
    Ambiguous {
        kind: &'static str,
        candidates: String,
    },

    #[snafu(display(
        "no challenge binary found; use --bin PATH or run from the challenge directory"
    ))]
    MissingBinary,

    #[snafu(display(
        "no x86-64 kernel image or bzImage found; use --kernel PATH or run from the challenge directory"
    ))]
    MissingKernel,

    #[snafu(display(
        "no initramfs archive found; use --initramfs PATH or run from the challenge directory"
    ))]
    MissingInitramfs,

    #[snafu(display("debug initramfs path must differ from the original initramfs"))]
    DebugInitramfsConflict,

    #[snafu(display(
        "kernel paths {} and {} both resolve to {}",
        first,
        second,
        path.display()
    ))]
    KernelPathConflict {
        first: &'static str,
        second: &'static str,
        path: PathBuf,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn fold_current_dir<T, F>(init: T, mut merge: F) -> Result<T>
where
    F: FnMut(T, fs::DirEntry) -> elf::detect::Result<T>,
{
    fs::read_dir(".")
        .context(ReadDirSnafu)?
        .try_fold(init, |acc, dir_ent| {
            let dir_ent = dir_ent.context(DirEntSnafu)?;
            merge(acc, dir_ent).context(ElfDetectSnafu)
        })
}

fn detect_path_if(
    dir_ent: &fs::DirEntry,
    pred: fn(&Path) -> elf::detect::Result<bool>,
) -> elf::detect::Result<Option<PathBuf>> {
    let path = dir_ent.path();
    Ok(if pred(&path)? { Some(path) } else { None })
}

const ROOT_EXAMPLES: &str = "\
Examples:
  pwninit                         Detect the challenge in this folder and set it up
  pwninit --dry-run               Show what would happen without changing anything
  pwninit pwn --uv                Pwn setup plus a .venv with pwntools
  pwninit pwn --skip unstrip      Pwn setup without downloading debug symbols
  pwninit rev                     Reverse-engineering setup (angr + z3 template)
  pwninit kernel                  Kernel setup (unpack initramfs, vmlinux, run-debug.sh)
  pwninit libc launchpad 2.31     Download Ubuntu glibc 2.31 into this folder

Run `pwninit <COMMAND> --help` for the options of one command.";

const PWN_EXAMPLES: &str = "\
Examples:
  pwninit pwn                                  Auto-detect binary, libc and ld
  pwninit pwn -b ./chall -l ./libc.so.6        Name the files explicitly
  pwninit pwn --uv                             Also create .venv with pwntools
  pwninit pwn --skip unstrip,patch             Skip debug symbols and patching
  pwninit pwn --patch-mode manual              Patch without patchelf";

const REV_EXAMPLES: &str = "\
Examples:
  pwninit rev                    Auto-detect the binary, write solve.py
  pwninit rev -b ./crackme --uv  Name the binary, create .venv with angr + z3";

const KERNEL_EXAMPLES: &str = "\
Examples:
  pwninit kernel                                   Auto-detect kernel, initramfs, run script
  pwninit kernel -k bzImage -i rootfs.cpio.gz      Name the inputs explicitly
  pwninit kernel --skip vmlinux,modules            Only unpack and generate scripts

Afterwards:
  ./build-exploit.sh       Compile exploit.c and repack the debug initramfs
  ./run-debug.sh           Boot with nokaslr nopti nosmep nosmap
  GDB=1 ./run-debug.sh     Same, paused with a GDB server";

const LIBC_EXAMPLES: &str = "\
Examples:
  pwninit libc launchpad 2.31 --lib libm.so.6
  pwninit libc docker --image ubuntu:22.04
  pwninit libc docker --distro debian --release bookworm
  pwninit libc debian 2.36 --release bookworm";

/// Set up pwn, rev, and kernel CTF challenges in one command
///
/// Run with no command in a challenge folder and pwninit detects what kind of
/// challenge it is: a kernel image plus an initramfs means `kernel`, anything
/// else means `pwn`. Reverse-engineering challenges need `pwninit rev`.
#[derive(Parser, Clone)]
#[command(version, after_help = ROOT_EXAMPLES)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: Option<Command>,

    /// Suppress progress output
    #[arg(short, long, global = true, conflicts_with = "verbose", help_heading = "Global")]
    pub quiet: bool,

    /// Show additional diagnostic output
    #[arg(short, long, global = true, action = ArgAction::Count, help_heading = "Global")]
    pub verbose: u8,

    /// Emit a machine-readable JSON result
    #[arg(long, global = true, help_heading = "Global")]
    pub json: bool,

    /// Show the planned steps without changing any files
    #[arg(short = 'n', long, global = true, help_heading = "Global")]
    pub dry_run: bool,
}

#[derive(Subcommand, Clone)]
pub enum Command {
    /// Userspace exploitation: patch the binary, fetch ld/debug symbols, write solve.py
    #[command(after_help = PWN_EXAMPLES)]
    Pwn(PwnOpts),

    /// Reverse engineering: write an angr + z3 solve.py
    #[command(after_help = REV_EXAMPLES)]
    Rev(RevOpts),

    /// Kernel exploitation: unpack initramfs, extract vmlinux, write debug QEMU scripts
    #[command(after_help = KERNEL_EXAMPLES)]
    Kernel(KernelOpts),

    /// Download a libc (and companion libraries) from launchpad, docker, or debian
    #[command(after_help = LIBC_EXAMPLES)]
    Libc(LibcCommand),
}

/// Options for pwn challenge initialization
#[derive(Args, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct PwnOpts {
    /// Challenge binary [default: auto-detected]
    #[arg(short = 'b', long, value_name = "PATH", help_heading = "Inputs")]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Challenge libc [default: auto-detected, file name contains "libc"]
    #[arg(short = 'l', long, value_name = "PATH", help_heading = "Inputs")]
    #[setters(generate)]
    pub libc: Option<PathBuf>,

    /// Dynamic linker [default: auto-detected or downloaded to match libc]
    #[arg(short = 'd', long, value_name = "PATH", help_heading = "Inputs")]
    #[setters(generate)]
    pub ld: Option<PathBuf>,

    /// Leave out steps, comma-separated: unstrip, patch, template
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        value_name = "STEP",
        help_heading = "Steps",
        hide_possible_values = true
    )]
    pub skip: Vec<SkipStep>,

    /// How to patch the binary
    #[arg(short = 'p', long, value_enum, value_name = "MODE", default_value = "patchelf", help_heading = "Steps")]
    pub patch_mode: PatchStrategy,

    /// Where to find glibc debug symbols
    #[arg(long, value_enum, value_name = "SOURCE", default_value = "auto", help_heading = "Steps")]
    pub debug_source: DebugSource,

    /// Create .venv with pwntools using uv
    #[arg(short = 'u', long, help_heading = "Steps")]
    pub uv: bool,

    /// Keep going after a step fails
    #[arg(long, help_heading = "Steps")]
    pub best_effort: bool,

    /// Where to write the solve script
    #[arg(short = 's', long, value_name = "PATH", default_value = "solve.py", help_heading = "Solve script")]
    pub solve_path: PathBuf,

    /// Overwrite an existing solve script
    #[arg(short = 'f', long, help_heading = "Solve script")]
    pub force: bool,

    /// Custom solve script template [default: built-in pwntools template]
    #[arg(short = 't', long, value_name = "PATH", help_heading = "Solve script")]
    pub template_path: Option<PathBuf>,

    /// Template variable name for the binary
    #[arg(long, value_name = "NAME", default_value = "exe", help_heading = "Solve script")]
    pub template_bin_name: String,

    /// Template variable name for the libc
    #[arg(long, value_name = "NAME", default_value = "libc", help_heading = "Solve script")]
    pub template_libc_name: String,

    /// Template variable name for the linker
    #[arg(long, value_name = "NAME", default_value = "ld", help_heading = "Solve script")]
    pub template_ld_name: String,
}

/// Options for rev challenge initialization
#[derive(Args, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct RevOpts {
    /// Challenge binary [default: auto-detected]
    #[arg(short = 'b', long, value_name = "PATH", help_heading = "Inputs")]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Leave out steps, comma-separated: template
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        value_name = "STEP",
        help_heading = "Steps",
        hide_possible_values = true
    )]
    pub skip: Vec<SkipStep>,

    /// Create .venv with angr + z3 using uv
    #[arg(short = 'u', long, help_heading = "Steps")]
    pub uv: bool,

    /// Keep going after a step fails
    #[arg(long, help_heading = "Steps")]
    pub best_effort: bool,

    /// Where to write the solve script
    #[arg(short = 's', long, value_name = "PATH", default_value = "solve.py", help_heading = "Solve script")]
    pub solve_path: PathBuf,

    /// Overwrite an existing solve script
    #[arg(short = 'f', long, help_heading = "Solve script")]
    pub force: bool,

    /// Custom solve script template [default: built-in angr template]
    #[arg(short = 't', long, value_name = "PATH", help_heading = "Solve script")]
    pub template_path: Option<PathBuf>,

    /// Template variable name for the binary
    #[arg(long, value_name = "NAME", default_value = "exe", help_heading = "Solve script")]
    pub template_bin_name: String,
}

/// Options for Linux kernel exploitation challenge initialization
#[derive(Args, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct KernelOpts {
    /// x86-64 kernel image or bzImage [default: auto-detected]
    #[arg(short = 'k', long, value_name = "PATH", help_heading = "Inputs")]
    #[setters(generate)]
    pub kernel: Option<PathBuf>,

    /// Initramfs archive [default: auto-detected]
    #[arg(short = 'i', long, value_name = "PATH", help_heading = "Inputs")]
    #[setters(generate)]
    pub initramfs: Option<PathBuf>,

    /// Existing QEMU launch script [default: auto-detected *.sh calling qemu-system]
    #[arg(short = 'r', long, value_name = "PATH", help_heading = "Inputs")]
    #[setters(generate)]
    pub run_script: Option<PathBuf>,

    /// Leave out steps, comma-separated: vmlinux, modules, template
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        value_name = "STEP",
        help_heading = "Steps",
        hide_possible_values = true
    )]
    pub skip: Vec<SkipStep>,

    /// Overwrite previously generated files
    #[arg(short = 'f', long, help_heading = "Steps")]
    pub force: bool,

    /// Keep going after a step fails
    #[arg(long, help_heading = "Steps")]
    pub best_effort: bool,

    /// Custom C exploit template [default: built-in template]
    #[arg(short = 't', long, value_name = "PATH", help_heading = "Steps")]
    pub template_path: Option<PathBuf>,

    /// Exploit source file
    #[arg(short = 's', long, value_name = "PATH", default_value = "exploit.c", help_heading = "Output paths")]
    pub exploit_path: PathBuf,

    /// Writable copy of the initramfs [default: <initramfs>-debug.<ext>]
    #[arg(long, value_name = "PATH", help_heading = "Output paths")]
    #[setters(generate)]
    pub debug_initramfs: Option<PathBuf>,

    /// Unpacked root filesystem directory
    #[arg(long, value_name = "DIR", default_value = "initramfs", help_heading = "Output paths")]
    pub rootfs_dir: PathBuf,

    /// Extracted kernel ELF
    #[arg(long, value_name = "PATH", default_value = "vmlinux", help_heading = "Output paths")]
    pub vmlinux_path: PathBuf,

    /// No-mitigation QEMU launcher
    #[arg(long, value_name = "PATH", default_value = "run-debug.sh", help_heading = "Output paths")]
    pub debug_run_path: PathBuf,

    /// Compile-and-repack helper
    #[arg(long, value_name = "PATH", default_value = "build-exploit.sh", help_heading = "Output paths")]
    pub build_path: PathBuf,

    /// Exported kernel modules directory
    #[arg(long, value_name = "DIR", default_value = "kernel_modules", help_heading = "Output paths")]
    pub modules_dir: PathBuf,
}

/// `pwninit libc <SOURCE>`: each source only takes the flags it understands.
#[derive(Args, Clone)]
pub struct LibcCommand {
    #[command(subcommand)]
    pub source: LibcSource,
}

/// Where to download the libc from
#[derive(Subcommand, Clone)]
pub enum LibcSource {
    /// Ubuntu glibc packages from Launchpad, by version (e.g. 2.31)
    Launchpad(LaunchpadOpts),

    /// Copy the libc out of a Docker image (e.g. ubuntu:22.04)
    Docker(DockerOpts),

    /// Debian glibc packages from a Debian mirror, by version and release
    Debian(DebianOpts),
}

/// Options shared by every libc source
#[derive(Args, Clone)]
pub struct LibcOutputOpts {
    /// Target architecture
    #[arg(short = 'a', long, value_name = "ARCH", default_value = "amd64", value_enum, help_heading = "Output")]
    pub arch: CpuArch,

    /// Directory for everything downloaded
    #[arg(short = 'o', long, value_name = "DIR", default_value = ".", help_heading = "Output")]
    pub output_dir: PathBuf,

    /// File name for the libc, relative to --output-dir
    #[arg(long, value_name = "PATH", default_value = "libc.so.6", help_heading = "Output")]
    pub libc_output: PathBuf,

    /// Also download this library from the libc package, e.g. libm.so.6 (repeatable)
    #[arg(short = 'L', long = "lib", value_name = "NAME", help_heading = "Output")]
    pub extra_libs: Vec<String>,

    /// Also download every glibc library this binary needs
    #[arg(long, value_name = "PATH", help_heading = "Output")]
    pub from_bin: Option<PathBuf>,
}

/// Options for picking one package when several match
#[derive(Args, Clone)]
pub struct PackageSelectOpts {
    /// Fail instead of prompting when several package versions match
    #[arg(long, help_heading = "Version selection")]
    pub non_interactive: bool,

    /// Use this exact package version, e.g. 2.31-0ubuntu9.18
    #[arg(long, value_name = "VERSION", help_heading = "Version selection")]
    pub exact_version: Option<String>,
}

#[derive(Args, Clone)]
pub struct LaunchpadOpts {
    /// glibc version, e.g. 2.31
    pub version: String,

    #[command(flatten)]
    pub select: PackageSelectOpts,

    #[command(flatten)]
    pub output: LibcOutputOpts,
}

#[derive(Args, Clone)]
#[command(group(ArgGroup::new("docker_image").required(true).args(["image", "distro"])))]
pub struct DockerOpts {
    /// Docker image, e.g. ubuntu:22.04
    #[arg(long, conflicts_with_all = ["distro", "release"])]
    pub image: Option<String>,

    /// Distro name, used together with --release, e.g. debian
    #[arg(long, requires = "release")]
    pub distro: Option<String>,

    /// Distro release, used together with --distro, e.g. bookworm
    #[arg(long, requires = "distro")]
    pub release: Option<String>,

    #[command(flatten)]
    pub output: LibcOutputOpts,
}

#[derive(Args, Clone)]
pub struct DebianOpts {
    /// glibc version prefix, e.g. 2.36
    pub version: String,

    /// Debian release, e.g. bookworm
    #[arg(long)]
    pub release: String,

    /// Debian mirror base URL
    #[arg(long, value_name = "URL", default_value = "https://deb.debian.org/debian")]
    pub repo_url: String,

    #[command(flatten)]
    pub select: PackageSelectOpts,

    #[command(flatten)]
    pub output: LibcOutputOpts,
}

impl Default for PwnOpts {
    fn default() -> Self {
        Self {
            bin: None,
            libc: None,
            ld: None,
            template_path: None,
            template_bin_name: "exe".to_string(),
            template_libc_name: "libc".to_string(),
            template_ld_name: "ld".to_string(),
            uv: false,
            patch_mode: PatchStrategy::Patchelf,
            skip: Vec::new(),
            solve_path: PathBuf::from("solve.py"),
            force: false,
            debug_source: DebugSource::Auto,
            best_effort: false,
        }
    }
}

impl Default for RevOpts {
    fn default() -> Self {
        Self {
            bin: None,
            template_path: None,
            template_bin_name: "exe".to_string(),
            uv: false,
            skip: Vec::new(),
            solve_path: PathBuf::from("solve.py"),
            force: false,
            best_effort: false,
        }
    }
}

impl Default for KernelOpts {
    fn default() -> Self {
        Self {
            kernel: None,
            initramfs: None,
            debug_initramfs: None,
            run_script: None,
            rootfs_dir: PathBuf::from("initramfs"),
            vmlinux_path: PathBuf::from("vmlinux"),
            debug_run_path: PathBuf::from("run-debug.sh"),
            exploit_path: PathBuf::from("exploit.c"),
            build_path: PathBuf::from("build-exploit.sh"),
            modules_dir: PathBuf::from("kernel_modules"),
            template_path: None,
            skip: Vec::new(),
            force: false,
            best_effort: false,
        }
    }
}

impl Opts {
    /// Fill in the command for a bare `pwninit` run by looking at the
    /// current directory: a kernel image plus an initramfs means `kernel`,
    /// anything else means `pwn`.
    pub fn with_resolved_command(mut self) -> Self {
        if self.cmd.is_none() {
            self.cmd = Some(autodetect_command());
        }
        self
    }

    /// Short name of the command, as used in summaries and JSON output.
    pub fn command_name(&self) -> &'static str {
        match &self.cmd {
            Some(Command::Pwn(_)) | None => "pwn",
            Some(Command::Rev(_)) => "rev",
            Some(Command::Kernel(_)) => "kernel",
            Some(Command::Libc(_)) => "libc",
        }
    }

    /// Checks that clap cannot express on its own.
    pub fn validate(&self) -> std::result::Result<(), String> {
        match &self.cmd {
            Some(Command::Pwn(opts)) => {
                validate_skips(
                    &opts.skip,
                    &[SkipStep::Unstrip, SkipStep::Patch, SkipStep::Template],
                    "pwn",
                )?;
                validate_template_skip(
                    &opts.skip,
                    opts.template_path.is_some(),
                    &opts.solve_path,
                )?;
                validate_python_identifier(&opts.template_bin_name)?;
                validate_python_identifier(&opts.template_libc_name)?;
                validate_python_identifier(&opts.template_ld_name)?;
                if opts.template_bin_name == opts.template_libc_name
                    || opts.template_bin_name == opts.template_ld_name
                    || opts.template_libc_name == opts.template_ld_name
                {
                    return Err("template variable names must be distinct".to_string());
                }
            }
            Some(Command::Rev(opts)) => {
                validate_skips(&opts.skip, &[SkipStep::Template], "rev")?;
                validate_template_skip(
                    &opts.skip,
                    opts.template_path.is_some(),
                    &opts.solve_path,
                )?;
                validate_python_identifier(&opts.template_bin_name)?;
            }
            Some(Command::Kernel(opts)) => {
                validate_skips(
                    &opts.skip,
                    &[SkipStep::Template, SkipStep::Vmlinux, SkipStep::Modules],
                    "kernel",
                )?;
                if opts.skip.contains(&SkipStep::Template) && opts.template_path.is_some() {
                    return Err("--template-path cannot be used with --skip template".to_string());
                }
                if let Some((first, second, path)) = kernel_path_conflict(opts) {
                    return Err(format!(
                        "kernel paths {first} and {second} both resolve to {}",
                        path.display()
                    ));
                }
            }
            Some(Command::Libc(libc)) => {
                let select = match &libc.source {
                    LibcSource::Launchpad(opts) => Some(&opts.select),
                    LibcSource::Debian(opts) => Some(&opts.select),
                    LibcSource::Docker(_) => None,
                };
                if let Some(select) = select {
                    if self.json && !select.non_interactive && select.exact_version.is_none() {
                        return Err(
                            "--json needs --non-interactive or --exact-version, since it cannot prompt"
                                .to_string(),
                        );
                    }
                }
            }
            None => {}
        }
        Ok(())
    }

    /// Print the locations of known input files
    pub fn print(&self) {
        let f = |opt_path: &Option<PathBuf>, header: &str, color| {
            if let Some(path) = opt_path {
                output::progress(format!(
                    "{}: {}",
                    header.color(color),
                    path.to_string_lossy().bold().color(color)
                ));
            }
        };

        match &self.cmd {
            Some(Command::Pwn(opts)) => {
                f(&opts.bin, "bin", Color::BrightBlue);
                f(&opts.libc, "libc", Color::Yellow);
                f(&opts.ld, "ld", Color::Green);
            }
            Some(Command::Rev(opts)) => {
                f(&opts.bin, "bin", Color::BrightBlue);
            }
            Some(Command::Kernel(opts)) => {
                f(&opts.kernel, "kernel", Color::BrightBlue);
                f(&opts.initramfs, "initramfs", Color::Yellow);
                f(
                    &opts.debug_initramfs,
                    "debug initramfs",
                    Color::BrightYellow,
                );
                f(&opts.run_script, "run", Color::Green);
            }
            Some(Command::Libc(_)) | None => {}
        }
    }

    /// For the unspecified files, try to guess their path
    pub fn find_if_unspec(mut self) -> Result<Self> {
        self.cmd = match self.cmd {
            Some(Command::Pwn(opts)) => Some(Command::Pwn(resolve_pwn(opts)?)),
            Some(Command::Rev(opts)) => Some(Command::Rev(resolve_rev(opts)?)),
            Some(Command::Kernel(opts)) => Some(Command::Kernel(resolve_kernel(opts)?)),
            other => other,
        };
        Ok(self)
    }
}

/// Pick `kernel` when the directory holds a kernel image and an initramfs,
/// otherwise `pwn`.
pub fn autodetect_command() -> Command {
    match scan_kernel_current_dir(true, true, false) {
        Ok(found) if !found.kernel.is_empty() && !found.initramfs.is_empty() => {
            Command::Kernel(KernelOpts::default())
        }
        _ => Command::Pwn(PwnOpts::default()),
    }
}

fn validate_skips(
    skip: &[SkipStep],
    allowed: &[SkipStep],
    command: &str,
) -> std::result::Result<(), String> {
    if let Some(step) = skip.iter().find(|step| !allowed.contains(step)) {
        let allowed = allowed
            .iter()
            .map(|step| step.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "`--skip {}` does not apply to `{command}`; possible steps: {allowed}",
            step.as_str()
        ));
    }
    Ok(())
}

fn validate_template_skip(
    skip: &[SkipStep],
    has_template_path: bool,
    solve_path: &Path,
) -> std::result::Result<(), String> {
    if !skip.contains(&SkipStep::Template) {
        return Ok(());
    }
    if has_template_path {
        return Err("--template-path cannot be used with --skip template".to_string());
    }
    if solve_path != Path::new("solve.py") {
        return Err("--solve-path cannot be used with --skip template".to_string());
    }
    Ok(())
}

impl PwnOpts {
    pub fn skips(&self, step: SkipStep) -> bool {
        self.skip.contains(&step)
    }

    pub fn resolved_patch_mode(&self) -> Option<PatchMode> {
        if self.skips(SkipStep::Patch) {
            return None;
        }
        Some(match self.patch_mode {
            PatchStrategy::Patchelf => PatchMode::Patchelf,
            PatchStrategy::Manual => PatchMode::Manual,
        })
    }

    /// Re-scan the current directory for a linker if one is not already specified.
    pub fn detect_ld(self) -> Result<Self> {
        if self.ld.is_some() {
            return Ok(self);
        }
        let detected = scan_current_dir()?;
        Ok(self.with_ld(select_candidate("linker", detected.ld)?))
    }
}

impl RevOpts {
    pub fn skips(&self, step: SkipStep) -> bool {
        self.skip.contains(&step)
    }
}

impl KernelOpts {
    pub fn skips(&self, step: SkipStep) -> bool {
        self.skip.contains(&step)
    }
}

#[derive(Default)]
struct DetectedPaths {
    bin: Vec<PathBuf>,
    libc: Vec<PathBuf>,
    ld: Vec<PathBuf>,
}

#[derive(Default)]
struct DetectedKernelPaths {
    kernel: Vec<PathBuf>,
    initramfs: Vec<PathBuf>,
    run_script: Vec<PathBuf>,
}

fn scan_current_dir() -> Result<DetectedPaths> {
    fold_current_dir(DetectedPaths::default(), |mut found, dir_ent| {
        if let Some(path) = detect_path_if(&dir_ent, is_bin)? {
            found.bin.push(path);
        }
        if let Some(path) = detect_path_if(&dir_ent, is_libc)? {
            found.libc.push(path);
        }
        if let Some(path) = detect_path_if(&dir_ent, is_ld)? {
            found.ld.push(path);
        }
        Ok(found)
    })
}

fn scan_kernel_current_dir(
    need_kernel: bool,
    need_initramfs: bool,
    need_run_script: bool,
) -> Result<DetectedKernelPaths> {
    let mut found = DetectedKernelPaths::default();
    if !need_kernel && !need_initramfs && !need_run_script {
        return Ok(found);
    }
    for dir_ent in fs::read_dir(".").context(ReadDirSnafu)? {
        let dir_ent = dir_ent.context(DirEntSnafu)?;
        let path = dir_ent.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        let conventional_kernel_name = name.starts_with("vmlinuz")
            || name.starts_with("bzImage")
            || name.starts_with("bzimage")
            || name == "Image";
        if need_kernel && conventional_kernel_name && kernel_image::is_kernel_image(&path) {
            found.kernel.push(path.clone());
        }
        let conventional_initramfs_name = name.contains("initramfs")
            || name.starts_with("initrd")
            || name.contains("rootfs")
            || name.contains(".cpio");
        if need_initramfs
            && conventional_initramfs_name
            && !name.contains("-debug")
            && kernel_initramfs::detect_file_compression(&path).is_ok()
        {
            found.initramfs.push(path.clone());
        }
        let is_shell_script = path.extension().and_then(|ext| ext.to_str()) == Some("sh");
        if need_run_script
            && is_shell_script
            && name != "run-debug.sh"
            && std::fs::read(&path)
                .map(|bytes| {
                    bytes
                        .windows(b"qemu-system".len())
                        .any(|window| window == b"qemu-system")
                })
                .unwrap_or(false)
        {
            found.run_script.push(path);
        }
    }
    Ok(found)
}

fn select_run_script(
    mut candidates: Vec<PathBuf>,
    kernel: Option<&Path>,
    initramfs: Option<&Path>,
) -> Result<Option<PathBuf>> {
    candidates.sort();
    candidates.dedup();
    if candidates.len() <= 1 {
        return Ok(candidates.into_iter().next());
    }

    let referenced = candidates
        .iter()
        .filter(|path| {
            let Ok(contents) = std::fs::read_to_string(path) else {
                return false;
            };
            [kernel, initramfs]
                .into_iter()
                .flatten()
                .filter_map(Path::file_name)
                .filter_map(OsStr::to_str)
                .all(|name| contents.contains(name))
        })
        .cloned()
        .collect::<Vec<_>>();
    if referenced.len() == 1 {
        return Ok(referenced.into_iter().next());
    }
    select_candidate("QEMU launcher", candidates)
}

fn select_candidate(kind: &'static str, mut candidates: Vec<PathBuf>) -> Result<Option<PathBuf>> {
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [] => Ok(None),
        [path] => Ok(Some(path.clone())),
        _ => Err(Error::Ambiguous {
            kind,
            candidates: candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

fn resolve_pwn(mut opts: PwnOpts) -> Result<PwnOpts> {
    let detected = scan_current_dir()?;
    if opts.bin.is_none() {
        opts.bin = select_candidate("binary", detected.bin)?;
    }
    if opts.libc.is_none() {
        opts.libc = select_candidate("libc", detected.libc)?;
    }
    if opts.ld.is_none() {
        opts.ld = select_candidate("linker", detected.ld)?;
    }
    if opts.bin.is_none() {
        return Err(Error::MissingBinary);
    }
    Ok(opts)
}

fn resolve_rev(mut opts: RevOpts) -> Result<RevOpts> {
    if opts.bin.is_none() {
        opts.bin = select_candidate("binary", scan_current_dir()?.bin)?;
    }
    if opts.bin.is_none() {
        return Err(Error::MissingBinary);
    }
    Ok(opts)
}

fn resolve_kernel(mut opts: KernelOpts) -> Result<KernelOpts> {
    let detected = scan_kernel_current_dir(
        opts.kernel.is_none(),
        opts.initramfs.is_none(),
        opts.run_script.is_none(),
    )?;
    if opts.kernel.is_none() {
        opts.kernel = select_candidate("kernel image", detected.kernel)?;
    }
    if opts.initramfs.is_none() {
        opts.initramfs = select_candidate("initramfs", detected.initramfs)?;
    }
    if opts.debug_initramfs.is_none() {
        opts.debug_initramfs = opts.initramfs.as_deref().map(debug_initramfs_path);
    }
    if opts.run_script.is_none() {
        opts.run_script = select_run_script(
            detected.run_script,
            opts.kernel.as_deref(),
            opts.initramfs.as_deref(),
        )?;
    }
    if opts.kernel.is_none() {
        return Err(Error::MissingKernel);
    }
    if opts.initramfs.is_none() {
        return Err(Error::MissingInitramfs);
    }
    if opts.initramfs == opts.debug_initramfs {
        return Err(Error::DebugInitramfsConflict);
    }
    if let Some((first, second, path)) = kernel_path_conflict(&opts) {
        return Err(Error::KernelPathConflict {
            first,
            second,
            path,
        });
    }
    Ok(opts)
}

fn kernel_path_conflict(opts: &KernelOpts) -> Option<(&'static str, &'static str, PathBuf)> {
    let paths = [
        ("--kernel", opts.kernel.as_ref()),
        ("--initramfs", opts.initramfs.as_ref()),
        ("--debug-initramfs", opts.debug_initramfs.as_ref()),
        ("--run-script", opts.run_script.as_ref()),
        ("--template-path", opts.template_path.as_ref()),
        ("--rootfs-dir", Some(&opts.rootfs_dir)),
        ("--vmlinux-path", Some(&opts.vmlinux_path)),
        ("--debug-run-path", Some(&opts.debug_run_path)),
        ("--exploit-path", Some(&opts.exploit_path)),
        ("--build-path", Some(&opts.build_path)),
        ("--modules-dir", Some(&opts.modules_dir)),
    ];
    for (index, (first_label, first_path)) in paths.iter().enumerate() {
        let Some(first_path) = first_path else {
            continue;
        };
        let first_path = comparable_path(first_path);
        for (second_label, second_path) in &paths[index + 1..] {
            let Some(second_path) = second_path else {
                continue;
            };
            let second_path = comparable_path(second_path);
            if first_path == second_path {
                return Some((*first_label, *second_label, first_path));
            }
        }
    }
    None
}

fn comparable_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }

    let mut existing = normalized.as_path();
    let mut suffix = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name() else {
            break;
        };
        suffix.push(name.to_os_string());
        let Some(parent) = existing.parent() else {
            break;
        };
        existing = parent;
    }
    let mut resolved = std::fs::canonicalize(existing).unwrap_or_else(|_| existing.to_path_buf());
    for component in suffix.into_iter().rev() {
        resolved.push(component);
    }
    resolved
}

fn debug_initramfs_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("initramfs");
    let debug_name = match name.find('.') {
        Some(index) if index > 0 => format!("{}-debug{}", &name[..index], &name[index..]),
        _ => format!("{name}-debug"),
    };
    path.with_file_name(debug_name)
}

fn validate_python_identifier(value: &str) -> std::result::Result<(), String> {
    const KEYWORDS: &[&str] = &[
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class",
        "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global",
        "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
        "try", "while", "with", "yield", "match", "case",
    ];
    let mut chars = value.chars();
    let valid_start = chars
        .next()
        .map(|ch| ch == '_' || ch.is_alphabetic())
        .unwrap_or(false);
    if !valid_start || !chars.all(|ch| ch == '_' || ch.is_alphanumeric()) {
        return Err(format!("invalid Python identifier: {value}"));
    }
    if KEYWORDS.contains(&value) {
        return Err(format!(
            "Python keyword cannot be used as an identifier: {value}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Opts {
        let mut full = vec!["pwninit"];
        full.extend_from_slice(args);
        Opts::try_parse_from(&full).expect("arguments should parse")
    }

    fn parse_err(args: &[&str]) -> bool {
        let mut full = vec!["pwninit"];
        full.extend_from_slice(args);
        Opts::try_parse_from(&full).is_err()
    }

    fn pwn(args: &[&str]) -> PwnOpts {
        let mut full = vec!["pwn"];
        full.extend_from_slice(args);
        match parse(&full).cmd {
            Some(Command::Pwn(opts)) => opts,
            _ => panic!("expected pwn command"),
        }
    }

    fn libc(args: &[&str]) -> LibcSource {
        let mut full = vec!["libc"];
        full.extend_from_slice(args);
        match parse(&full).cmd {
            Some(Command::Libc(cmd)) => cmd.source,
            _ => panic!("expected libc command"),
        }
    }

    #[test]
    fn clap_definition_is_consistent() {
        Opts::command().debug_assert();
    }

    // ---- root / autodetect -------------------------------------------------

    #[test]
    fn bare_invocation_has_no_command_until_resolved() {
        assert!(parse(&[]).cmd.is_none());
    }

    #[test]
    fn root_no_longer_accepts_pwn_flags() {
        assert!(parse_err(&["--bin", "chall"]));
        assert!(parse_err(&["--uv"]));
    }

    #[test]
    fn global_flags_work_before_and_after_command() {
        let opts = parse(&["--dry-run", "pwn"]);
        assert!(opts.dry_run);
        let opts = parse(&["pwn", "-n", "--json"]);
        assert!(opts.dry_run && opts.json);
    }

    // ---- pwn ---------------------------------------------------------------

    #[test]
    fn pwn_defaults() {
        let opts = pwn(&[]);
        assert!(opts.skip.is_empty());
        assert_eq!(opts.debug_source, DebugSource::Auto);
        assert_eq!(opts.resolved_patch_mode(), Some(PatchMode::Patchelf));
    }

    #[test]
    fn pwn_skip_accepts_comma_list_and_repeats() {
        let opts = pwn(&["--skip", "unstrip,patch", "--skip", "template"]);
        assert!(opts.skips(SkipStep::Unstrip));
        assert!(opts.skips(SkipStep::Patch));
        assert!(opts.skips(SkipStep::Template));
        assert_eq!(opts.resolved_patch_mode(), None);
    }

    #[test]
    fn pwn_patch_mode_manual() {
        assert_eq!(
            pwn(&["--patch-mode", "manual"]).resolved_patch_mode(),
            Some(PatchMode::Manual)
        );
    }

    #[test]
    fn removed_flags_are_rejected() {
        for flag in [
            "--no-unstrip",
            "--no-template",
            "--no-patchelf",
            "--no-patch-bin",
        ] {
            assert!(parse_err(&["pwn", flag]), "{flag} should be gone");
        }
        assert!(parse_err(&["pwn", "--patch-mode", "none"]));
        assert!(parse_err(&["fetch-libc", "2.31"]));
    }

    #[test]
    fn pwn_debug_source_accepts_explicit_sources() {
        assert_eq!(
            pwn(&["--debug-source", "launchpad"]).debug_source,
            DebugSource::Launchpad
        );
        assert_eq!(
            pwn(&["--debug-source", "debian"]).debug_source,
            DebugSource::Debian
        );
    }

    #[test]
    fn skip_steps_are_checked_per_command() {
        assert!(parse(&["pwn", "--skip", "vmlinux"]).validate().is_err());
        assert!(parse(&["rev", "--skip", "patch"]).validate().is_err());
        assert!(parse(&["kernel", "--skip", "unstrip"]).validate().is_err());
        assert!(parse(&["kernel", "--skip", "vmlinux,modules"]).validate().is_ok());
    }

    #[test]
    fn skip_template_conflicts_with_template_options() {
        assert!(parse(&["pwn", "--skip", "template", "-s", "x.py"])
            .validate()
            .is_err());
        assert!(parse(&["rev", "--skip", "template", "-t", "t.py"])
            .validate()
            .is_err());
        assert!(parse(&["kernel", "--skip", "template", "-t", "t.c"])
            .validate()
            .is_err());
    }

    #[test]
    fn invalid_python_identifiers_are_rejected() {
        assert!(parse(&["pwn", "--template-bin-name", "not-valid"])
            .validate()
            .is_err());
        assert!(parse(&["rev", "--template-bin-name", "class"])
            .validate()
            .is_err());
        assert!(parse(&["pwn", "--template-bin-name", "libc"])
            .validate()
            .is_err());
    }

    #[test]
    fn libc_only_flags_are_not_pwn_or_rev_flags() {
        assert!(parse_err(&["pwn", "--lib", "libm.so.6"]));
        assert!(parse_err(&["pwn", "--arch", "amd64"]));
        assert!(parse_err(&["rev", "--lib", "libm.so.6"]));
    }

    // ---- libc --------------------------------------------------------------

    #[test]
    fn libc_requires_a_source() {
        assert!(parse_err(&["libc"]));
        assert!(parse_err(&["libc", "2.31"]));
    }

    #[test]
    fn libc_launchpad_parses_with_defaults() {
        let LibcSource::Launchpad(opts) = libc(&["launchpad", "2.31"]) else {
            panic!("expected launchpad");
        };
        assert_eq!(opts.version, "2.31");
        assert_eq!(opts.output.arch, CpuArch::Amd64);
        assert_eq!(opts.output.libc_output, PathBuf::from("libc.so.6"));
        assert_eq!(opts.output.output_dir, PathBuf::from("."));
        assert!(opts.output.extra_libs.is_empty());
    }

    #[test]
    fn libc_launchpad_requires_version() {
        assert!(parse_err(&["libc", "launchpad"]));
    }

    #[test]
    fn libc_launchpad_full_flags() {
        let LibcSource::Launchpad(opts) = libc(&[
            "launchpad",
            "2.31",
            "-a",
            "i386",
            "--lib",
            "libm.so.6",
            "-L",
            "libdl.so.2",
            "--libc-output",
            "my.so",
            "--exact-version",
            "2.31-0ubuntu9.18",
        ]) else {
            panic!("expected launchpad");
        };
        assert_eq!(opts.output.arch, CpuArch::I386);
        assert_eq!(opts.output.extra_libs, ["libm.so.6", "libdl.so.2"]);
        assert_eq!(opts.output.libc_output, PathBuf::from("my.so"));
        assert_eq!(opts.select.exact_version.as_deref(), Some("2.31-0ubuntu9.18"));
    }

    #[test]
    fn libc_rejects_invalid_arch() {
        assert!(parse_err(&["libc", "launchpad", "2.31", "--arch", "armhf"]));
    }

    #[test]
    fn libc_sources_reject_each_others_flags() {
        assert!(parse_err(&["libc", "launchpad", "2.31", "--image", "ubuntu"]));
        assert!(parse_err(&["libc", "launchpad", "2.31", "--release", "x"]));
        assert!(parse_err(&["libc", "docker", "--image", "u", "--exact-version", "1"]));
        assert!(parse_err(&["libc", "debian", "2.36", "--release", "b", "--image", "u"]));
    }

    #[test]
    fn libc_docker_needs_image_or_distro_release() {
        assert!(parse_err(&["libc", "docker"]));
        assert!(parse_err(&["libc", "docker", "--distro", "debian"]));
        assert!(parse_err(&["libc", "docker", "--release", "bookworm"]));
        assert!(parse_err(&[
            "libc", "docker", "--image", "u:22.04", "--distro", "debian", "--release", "b"
        ]));

        let LibcSource::Docker(opts) = libc(&["docker", "--image", "ubuntu:22.04"]) else {
            panic!("expected docker");
        };
        assert_eq!(opts.image.as_deref(), Some("ubuntu:22.04"));

        let LibcSource::Docker(opts) =
            libc(&["docker", "--distro", "debian", "--release", "bookworm"])
        else {
            panic!("expected docker");
        };
        assert_eq!(opts.distro.as_deref(), Some("debian"));
        assert_eq!(opts.release.as_deref(), Some("bookworm"));
    }

    #[test]
    fn libc_debian_requires_release() {
        assert!(parse_err(&["libc", "debian", "2.36"]));
        let LibcSource::Debian(opts) = libc(&["debian", "2.36", "--release", "bookworm"]) else {
            panic!("expected debian");
        };
        assert_eq!(opts.release, "bookworm");
        assert_eq!(opts.repo_url, "https://deb.debian.org/debian");
    }

    #[test]
    fn libc_json_needs_non_interactive_selection() {
        assert!(parse(&["--json", "libc", "launchpad", "2.31"]).validate().is_err());
        assert!(parse(&["--json", "libc", "launchpad", "2.31", "--non-interactive"])
            .validate()
            .is_ok());
        assert!(parse(&["--json", "libc", "docker", "--image", "u"]).validate().is_ok());
    }

    // ---- kernel ------------------------------------------------------------

    #[test]
    fn ambiguous_candidates_are_sorted_in_error() {
        let err = select_candidate("binary", vec![PathBuf::from("b"), PathBuf::from("a")])
            .expect_err("multiple candidates should fail");
        assert!(err.to_string().contains("a, b"));
    }

    #[test]
    fn kernel_command_parses_full_development_setup_defaults() {
        let Some(Command::Kernel(kernel)) = parse(&["kernel"]).cmd else {
            panic!("expected kernel command");
        };
        assert_eq!(kernel.rootfs_dir, PathBuf::from("initramfs"));
        assert_eq!(kernel.modules_dir, PathBuf::from("kernel_modules"));
        assert_eq!(kernel.debug_run_path, PathBuf::from("run-debug.sh"));
        assert_eq!(kernel.exploit_path, PathBuf::from("exploit.c"));
        assert_eq!(kernel.build_path, PathBuf::from("build-exploit.sh"));
        assert!(kernel.skip.is_empty());
    }

    #[test]
    fn kernel_command_accepts_bzimage_and_debug_initramfs_paths() {
        let Some(Command::Kernel(kernel)) = parse(&[
            "kernel",
            "-k",
            "bzImage",
            "-i",
            "initramfs.cpio.gz",
            "--debug-initramfs",
            "initramfs-debug.cpio.gz",
        ])
        .cmd
        else {
            panic!("expected kernel command");
        };
        assert_eq!(kernel.kernel, Some(PathBuf::from("bzImage")));
        assert_eq!(
            kernel.debug_initramfs,
            Some(PathBuf::from("initramfs-debug.cpio.gz"))
        );
    }

    #[test]
    fn debug_initramfs_name_is_derived_without_overwriting_original() {
        assert_eq!(
            debug_initramfs_path(Path::new("initramfs.cpio.gz")),
            PathBuf::from("initramfs-debug.cpio.gz")
        );
        assert_eq!(
            debug_initramfs_path(Path::new("challenge/bz-rootfs.xz")),
            PathBuf::from("challenge/bz-rootfs-debug.xz")
        );
    }

    #[test]
    fn kernel_rejects_same_original_and_debug_initramfs() {
        assert!(parse(&[
            "kernel",
            "--initramfs",
            "rootfs.cpio",
            "--debug-initramfs",
            "rootfs.cpio",
        ])
        .validate()
        .is_err());
    }

    #[test]
    fn kernel_rejects_generated_output_path_collisions() {
        assert!(parse(&["kernel", "--exploit-path", "run-debug.sh"])
            .validate()
            .is_err());
    }

    #[test]
    fn kernel_path_collisions_normalize_dot_components() {
        let opts = KernelOpts {
            initramfs: Some(PathBuf::from("./initramfs")),
            rootfs_dir: PathBuf::from("initramfs"),
            ..KernelOpts::default()
        };
        let conflict = kernel_path_conflict(&opts).expect("paths should conflict");
        assert_eq!(conflict.0, "--initramfs");
        assert_eq!(conflict.1, "--rootfs-dir");
    }
}
