use crate::fetch_libc;
use crate::kernel;
use crate::kernel_image;
use crate::kernel_initramfs;
use crate::maybe_visit_libc_report;
use crate::needed_glibc_libraries_result;
use crate::opts::{self, Command, FetchLibcSource, Opts};
use crate::output::{self, Step, Summary};
use crate::patch_bin;
use crate::set_bin_exec_pwn;
use crate::set_bin_exec_rev;
use crate::set_ld_exec;
use crate::solvepy;
use crate::uv_venv;

use ex::fs;
use ex::io;
use snafu::ResultExt;
use snafu::Snafu;

/// Top-level `pwninit` error
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed setting binary executable: {}", source))]
    SetBinExec { source: io::Error },

    #[snafu(display("failed locating provided files (binary, libc, linker): {}", source))]
    Find { source: opts::Error },

    #[snafu(display("failed setting linker executable: {}", source))]
    SetLdExec { source: io::Error },

    #[snafu(display("failed patching binary: {}", source))]
    PatchBin { source: patch_bin::Error },

    #[snafu(display("failed setting up uv virtual environment: {}", source))]
    UvVenv { source: uv_venv::Error },

    #[snafu(display("failed making template solve script: {}", source))]
    Solvepy { source: solvepy::Error },

    #[snafu(display("failed downloading libc: {}", source))]
    FetchLibc { source: fetch_libc::Error },

    #[snafu(display("one or more required setup steps failed"))]
    Incomplete,
}

pub type Result<T = ()> = std::result::Result<T, Error>;

fn run_fetch_libc(fetch_opts: crate::opts::FetchLibcOpts, summary: &mut Summary) -> Result {
    let mut extra_libs = fetch_opts.extra_libs;
    if let Some(bin) = fetch_opts.from_bin {
        let mut pwn_opts = crate::opts::PwnOpts::default();
        pwn_opts.bin = Some(bin);
        match needed_glibc_libraries_result(&pwn_opts) {
            Ok(libs) => extra_libs.extend(libs),
            Err(err) => {
                summary.push(Step::failed(
                    "inspect dependency binary",
                    err.to_string(),
                    true,
                ));
                return Ok(());
            }
        }
    }
    if let Err(err) = fs::create_dir_all(&fetch_opts.output_dir) {
        summary.push(Step::failed(
            "prepare output directory",
            err.to_string(),
            true,
        ));
        return Ok(());
    }
    let libc_output = if fetch_opts.libc_output.is_absolute() {
        fetch_opts.libc_output.clone()
    } else {
        fetch_opts.output_dir.join(&fetch_opts.libc_output)
    };
    if let Some(parent) = libc_output.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            summary.push(Step::failed("prepare libc output", err.to_string(), true));
            return Ok(());
        }
    }

    let result = match fetch_opts.source {
        FetchLibcSource::Launchpad => {
            let Some(version) = fetch_opts.version.as_deref() else {
                return Err(fetch_libc::Error::MissingLaunchpadVersion).context(FetchLibcSnafu);
            };
            fetch_libc::fetch_libc_selected(
                version,
                fetch_opts.arch,
                &libc_output,
                &fetch_opts.output_dir,
                &extra_libs,
                fetch_opts.non_interactive || fetch_opts.exact_version.is_some(),
                fetch_opts.exact_version.as_deref(),
            )
            .context(FetchLibcSnafu)
        }
        FetchLibcSource::Docker => {
            let image = fetch_libc::docker_image_name(
                fetch_opts.image.as_deref(),
                fetch_opts.distro.as_deref(),
                fetch_opts.release.as_deref(),
            )
            .context(FetchLibcSnafu)?;
            fetch_libc::fetch_libc_from_docker_to(
                &image,
                fetch_opts.arch,
                &libc_output,
                &fetch_opts.output_dir,
                &extra_libs,
            )
            .context(FetchLibcSnafu)
        }
        FetchLibcSource::Debian => {
            let Some(version) = fetch_opts.version.as_deref() else {
                return Err(fetch_libc::Error::MissingDebianVersion).context(FetchLibcSnafu);
            };
            let Some(release) = fetch_opts.release.as_deref() else {
                return Err(fetch_libc::Error::MissingDebianRelease).context(FetchLibcSnafu);
            };
            fetch_libc::fetch_libc_from_debian_selected(
                version,
                fetch_opts.arch,
                release,
                &fetch_opts.repo_url,
                &libc_output,
                &fetch_opts.output_dir,
                &extra_libs,
                fetch_opts.non_interactive || fetch_opts.exact_version.is_some(),
                fetch_opts.exact_version.as_deref(),
            )
            .context(FetchLibcSnafu)
        }
    };
    match result {
        Ok(()) => summary.push(Step::completed(
            "fetch libc",
            format!("artifacts written to {}", fetch_opts.output_dir.display()),
        )),
        Err(err) => summary.push(Step::failed("fetch libc", err.to_string(), true)),
    }

    Ok(())
}

fn push_required<T, E: std::fmt::Display>(
    summary: &mut Summary,
    name: &str,
    success_detail: impl Into<String>,
    result: std::result::Result<T, E>,
) -> bool {
    match result {
        Ok(_) => {
            summary.push(Step::completed(name, success_detail));
            true
        }
        Err(err) => {
            summary.push(Step::failed(name, err.to_string(), true));
            false
        }
    }
}

fn record_solve_result(
    summary: &mut Summary,
    path: &std::path::Path,
    result: solvepy::Result<solvepy::WriteStubOutcome>,
) {
    match result {
        Ok(solvepy::WriteStubOutcome::Written) => summary.push(Step::completed(
            "generate solve script",
            format!("wrote {}", path.display()),
        )),
        Ok(solvepy::WriteStubOutcome::Overwritten) => summary.push(Step::completed(
            "generate solve script",
            format!("overwrote {}", path.display()),
        )),
        Ok(solvepy::WriteStubOutcome::SkippedExisting) => summary.push(Step::skipped(
            "generate solve script",
            format!(
                "{} already exists; use --force to overwrite",
                path.display()
            ),
        )),
        Err(err) => summary.push(Step::failed("generate solve script", err.to_string(), true)),
    }
}

fn run_rev_flow(rev_opts: crate::opts::RevOpts, summary: &mut Summary) {
    let binary_ready = push_required(
        summary,
        "prepare binary",
        "binary is executable",
        set_bin_exec_rev(&rev_opts),
    );
    if !binary_ready && !rev_opts.best_effort {
        return;
    }
    if rev_opts.uv {
        let keep_going = push_required(
            summary,
            "create environment",
            "angr and z3 are installed",
            uv_venv::ensure_uv_venv(&["angr[unicorn]", "z3-solver"]),
        );
        if !keep_going && !rev_opts.best_effort {
            return;
        }
    } else {
        summary.push(Step::skipped(
            "create environment",
            "--uv was not requested",
        ));
    }

    if !binary_ready {
        summary.push(Step::skipped(
            "generate solve script",
            "binary preparation failed",
        ));
    } else if !rev_opts.no_template {
        record_solve_result(
            summary,
            &rev_opts.solve_path,
            solvepy::write_stub(&rev_opts),
        );
    } else {
        summary.push(Step::skipped(
            "generate solve script",
            "--no-template was requested",
        ));
    }
}

fn run_pwn_flow(mut pwn_opts: crate::opts::PwnOpts, summary: &mut Summary) {
    if pwn_opts.no_patch_bin {
        output::warning("--no-patch-bin is deprecated; use --patch-mode none");
    }
    if pwn_opts.no_patchelf {
        output::warning("--no-patchelf is deprecated; use --patch-mode manual");
    }
    let binary_ready = push_required(
        summary,
        "prepare binary",
        "binary is executable",
        set_bin_exec_pwn(&pwn_opts),
    );
    if !binary_ready && !pwn_opts.best_effort {
        return;
    }

    let libc_failures = maybe_visit_libc_report(&pwn_opts);
    if libc_failures.is_empty() {
        if pwn_opts.libc.is_some() {
            summary.push(Step::completed(
                "prepare libc",
                "libc-dependent setup completed",
            ));
        } else {
            summary.push(Step::skipped("prepare libc", "no libc was provided"));
        }
    } else {
        for failure in libc_failures {
            summary.push(Step::failed("prepare libc", failure, true));
        }
        if !pwn_opts.best_effort {
            return;
        }
    }

    // Re-scan for a freshly downloaded linker
    match pwn_opts.clone().detect_ld() {
        Ok(opts) => pwn_opts = opts,
        Err(err) => {
            summary.push(Step::failed("detect linker", err.to_string(), true));
            if !pwn_opts.best_effort {
                return;
            }
        }
    }
    if pwn_opts.libc.is_some() && pwn_opts.ld.is_none() {
        summary.push(Step::failed(
            "detect linker",
            "no compatible linker is available",
            true,
        ));
        if !pwn_opts.best_effort {
            return;
        }
    } else if let Some(ld) = &pwn_opts.ld {
        summary.push(Step::completed("detect linker", ld.display().to_string()));
    } else {
        summary.push(Step::skipped("detect linker", "no libc was provided"));
    }

    if pwn_opts.ld.is_some() {
        let keep_going = push_required(
            summary,
            "prepare linker",
            "linker is executable",
            set_ld_exec(&pwn_opts),
        );
        if !keep_going && !pwn_opts.best_effort {
            return;
        }
    } else {
        summary.push(Step::skipped("prepare linker", "no linker was provided"));
    }

    if pwn_opts.uv {
        let keep_going = push_required(
            summary,
            "create environment",
            "pwntools is installed",
            uv_venv::ensure_uv_venv(&["pwntools"]),
        );
        if !keep_going && !pwn_opts.best_effort {
            return;
        }
    } else {
        summary.push(Step::skipped(
            "create environment",
            "--uv was not requested",
        ));
    }

    let patch_ready = if !binary_ready {
        summary.push(Step::skipped("patch binary", "binary preparation failed"));
        false
    } else if pwn_opts.resolved_patch_mode().is_some() {
        let patch_ready = push_required(
            summary,
            "patch binary",
            patch_bin::bin_patched_path(&pwn_opts)
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "binary patched".to_string()),
            patch_bin::patch_bin(&pwn_opts),
        );
        if !patch_ready && !pwn_opts.best_effort {
            return;
        }
        patch_ready
    } else {
        summary.push(Step::skipped(
            "patch binary",
            "--patch-mode none was selected",
        ));
        true
    };

    if !binary_ready {
        summary.push(Step::skipped(
            "generate solve script",
            "binary preparation failed",
        ));
    } else if !patch_ready {
        summary.push(Step::skipped(
            "generate solve script",
            "binary patching failed",
        ));
    } else if !pwn_opts.no_template {
        record_solve_result(
            summary,
            &pwn_opts.solve_path,
            solvepy::write_stub(&pwn_opts),
        );
    } else {
        summary.push(Step::skipped(
            "generate solve script",
            "--no-template was requested",
        ));
    }
}

fn record_kernel_write(
    summary: &mut Summary,
    name: &str,
    path: &std::path::Path,
    result: kernel::Result<kernel::WriteOutcome>,
) -> bool {
    match result {
        Ok(kernel::WriteOutcome::Written) => {
            summary.push(Step::completed(name, format!("wrote {}", path.display())));
            true
        }
        Ok(kernel::WriteOutcome::Overwritten) => {
            summary.push(Step::completed(
                name,
                format!("overwrote {}", path.display()),
            ));
            true
        }
        Ok(kernel::WriteOutcome::SkippedExisting) => {
            summary.push(Step::skipped(
                name,
                format!(
                    "{} already exists; use --force to overwrite",
                    path.display()
                ),
            ));
            true
        }
        Err(err) => {
            summary.push(Step::failed(name, err.to_string(), true));
            false
        }
    }
}

fn run_kernel_flow(kernel_opts: crate::opts::KernelOpts, summary: &mut Summary) {
    let Some(kernel_path) = kernel_opts.kernel.as_deref() else {
        summary.push(Step::failed(
            "inspect kernel image",
            "kernel path was not resolved",
            true,
        ));
        return;
    };
    let kernel_ready = push_required(
        summary,
        "inspect kernel image",
        format!("detected x86-64 kernel image {}", kernel_path.display()),
        kernel_image::inspect(kernel_path),
    );
    if !kernel_ready && !kernel_opts.best_effort {
        return;
    }

    let Some(initramfs_path) = kernel_opts.initramfs.as_deref() else {
        summary.push(Step::failed(
            "inspect initramfs",
            "initramfs path was not resolved",
            true,
        ));
        return;
    };
    let archive_compression = match kernel_initramfs::detect_file_compression(initramfs_path) {
        Ok(compression) => {
            summary.push(Step::completed(
                "inspect initramfs",
                format!("detected {} initramfs candidate", compression.name()),
            ));
            Some(compression)
        }
        Err(err) => {
            summary.push(Step::failed("inspect initramfs", err.to_string(), true));
            if !kernel_opts.best_effort {
                return;
            }
            None
        }
    };

    let mut rootfs_ready = false;
    let mut extracted_compression = archive_compression;
    if archive_compression.is_some() {
        match kernel::extract_rootfs(&kernel_opts) {
            Ok(kernel::ExtractOutcome::Extracted(compression)) => {
                extracted_compression = Some(compression);
                rootfs_ready = true;
                summary.push(Step::completed(
                    "extract initramfs",
                    format!("wrote {}", kernel_opts.rootfs_dir.display()),
                ));
            }
            Ok(kernel::ExtractOutcome::Replaced(compression)) => {
                extracted_compression = Some(compression);
                rootfs_ready = true;
                summary.push(Step::completed(
                    "extract initramfs",
                    format!("replaced {}", kernel_opts.rootfs_dir.display()),
                ));
            }
            Ok(kernel::ExtractOutcome::SkippedExisting(compression)) => {
                extracted_compression = Some(compression);
                rootfs_ready = true;
                summary.push(Step::skipped(
                    "extract initramfs",
                    format!(
                        "{} already exists; use --force to replace",
                        kernel_opts.rootfs_dir.display()
                    ),
                ));
            }
            Err(err) => {
                summary.push(Step::failed("extract initramfs", err.to_string(), true));
                if !kernel_opts.best_effort {
                    return;
                }
            }
        }
    } else {
        summary.push(Step::skipped(
            "extract initramfs",
            "initramfs inspection failed",
        ));
    }

    let debug_initramfs_ready = if let Some(path) = kernel_opts.debug_initramfs.as_deref() {
        let ready = record_kernel_write(
            summary,
            "prepare debug initramfs",
            path,
            kernel::initialize_debug_initramfs(&kernel_opts),
        );
        if !ready && !kernel_opts.best_effort {
            return;
        }
        ready
    } else {
        summary.push(Step::failed(
            "prepare debug initramfs",
            "debug initramfs path was not resolved",
            true,
        ));
        if !kernel_opts.best_effort {
            return;
        }
        false
    };

    if kernel_opts.no_export_modules {
        summary.push(Step::skipped(
            "export kernel modules",
            "--no-export-modules was requested",
        ));
    } else if !rootfs_ready {
        summary.push(Step::skipped(
            "export kernel modules",
            "initramfs extraction failed",
        ));
    } else {
        match kernel::export_modules(&kernel_opts) {
            Ok((0, _)) => summary.push(Step::skipped(
                "export kernel modules",
                "no .ko files were found",
            )),
            Ok((copied, skipped)) => summary.push(Step::completed(
                "export kernel modules",
                format!(
                    "copied {copied} module(s) to {}; preserved {skipped}",
                    kernel_opts.modules_dir.display()
                ),
            )),
            Err(err) => {
                summary.push(Step::failed("export kernel modules", err.to_string(), true));
                if !kernel_opts.best_effort {
                    return;
                }
            }
        }
    }

    if kernel_opts.no_vmlinux {
        summary.push(Step::skipped(
            "extract vmlinux",
            "--no-vmlinux was requested",
        ));
    } else if !kernel_ready {
        summary.push(Step::skipped(
            "extract vmlinux",
            "kernel image inspection failed",
        ));
    } else {
        let ready = record_kernel_write(
            summary,
            "extract vmlinux",
            &kernel_opts.vmlinux_path,
            kernel::extract_vmlinux(&kernel_opts),
        );
        if !ready && !kernel_opts.best_effort {
            return;
        }
    }

    match kernel::create_placeholder_flags(&kernel_opts) {
        Ok((0, 0)) => summary.push(Step::skipped(
            "create local flag",
            "no missing relative flag disk was referenced",
        )),
        Ok((written, skipped)) => summary.push(Step::completed(
            "create local flag",
            format!("created {written} placeholder(s); preserved {skipped}"),
        )),
        Err(err) => {
            summary.push(Step::failed("create local flag", err.to_string(), true));
            if !kernel_opts.best_effort {
                return;
            }
        }
    }

    if debug_initramfs_ready {
        let ready = record_kernel_write(
            summary,
            "generate debug launcher",
            &kernel_opts.debug_run_path,
            kernel::generate_debug_launcher(&kernel_opts),
        );
        if !ready && !kernel_opts.best_effort {
            return;
        }
    } else {
        summary.push(Step::skipped(
            "generate debug launcher",
            "debug initramfs preparation failed",
        ));
    }

    if kernel_opts.no_template {
        summary.push(Step::skipped(
            "generate exploit",
            "--no-template was requested",
        ));
    } else if !rootfs_ready {
        summary.push(Step::skipped(
            "generate exploit",
            "initramfs extraction failed",
        ));
    } else {
        let ready = record_kernel_write(
            summary,
            "generate exploit",
            &kernel_opts.exploit_path,
            kernel::generate_exploit(&kernel_opts),
        );
        if !ready && !kernel_opts.best_effort {
            return;
        }
    }

    if !rootfs_ready {
        summary.push(Step::skipped(
            "generate build helper",
            "initramfs extraction failed",
        ));
    } else if !debug_initramfs_ready {
        summary.push(Step::skipped(
            "generate build helper",
            "debug initramfs preparation failed",
        ));
    } else if let Some(compression) = extracted_compression {
        let _ = record_kernel_write(
            summary,
            "generate build helper",
            &kernel_opts.build_path,
            kernel::generate_build_helper(&kernel_opts, compression),
        );
    } else {
        summary.push(Step::skipped(
            "generate build helper",
            "initramfs compression could not be determined",
        ));
    }
}

pub fn run_with_summary(opts: Opts) -> Result<Summary> {
    let mut summary = match &opts.cmd {
        Some(Command::FetchLibc(_)) => Summary::new("fetch-libc"),
        Some(Command::Rev(_)) => Summary::new("rev"),
        Some(Command::Kernel(_)) => Summary::new("kernel"),
        Some(Command::Pwn(_)) | None => Summary::new("pwn"),
    };
    let opts = match opts.find_if_unspec() {
        Ok(opts) => opts,
        Err(err) => {
            summary.push(Step::failed("resolve inputs", err.to_string(), true));
            return Ok(summary);
        }
    };

    // Print detected files
    opts.print();
    output::verbose(format!(
        "resolved command: {}",
        match &opts.cmd {
            Some(Command::FetchLibc(_)) => "fetch-libc",
            Some(Command::Rev(_)) => "rev",
            Some(Command::Kernel(_)) => "kernel",
            Some(Command::Pwn(_)) | None => "pwn",
        }
    ));

    match opts.cmd {
        Some(Command::FetchLibc(fetch_opts)) => run_fetch_libc(fetch_opts, &mut summary)?,
        Some(Command::Rev(rev_opts)) => run_rev_flow(rev_opts, &mut summary),
        Some(Command::Kernel(kernel_opts)) => run_kernel_flow(kernel_opts, &mut summary),
        Some(Command::Pwn(pwn_opts)) => run_pwn_flow(pwn_opts, &mut summary),
        None => run_pwn_flow(opts.pwn, &mut summary),
    }
    Ok(summary)
}

/// Run `pwninit` with specified options
pub fn run(opts: Opts) -> Result {
    let summary = run_with_summary(opts)?;
    if summary.success() {
        Ok(())
    } else {
        Err(Error::Incomplete)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use clap::Parser;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    use super::*;
    use crate::kernel_initramfs;
    use crate::opts::KernelOpts;

    fn synthetic_bzimage() -> Vec<u8> {
        let elf = std::fs::read("/bin/true").expect("read x86-64 ELF fixture");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&elf).expect("compress ELF fixture");
        let compressed = encoder.finish().expect("finish compressed ELF");

        let mut image = vec![0; 0x300];
        image[0x1fe..0x200].copy_from_slice(&[0x55, 0xaa]);
        image[0x202..0x206].copy_from_slice(b"HdrS");
        image.extend_from_slice(&compressed);
        image
    }

    #[test]
    fn kernel_flow_creates_development_layout_and_preserves_original_archive() {
        let workspace = tempfile::TempDir::new().expect("workspace");
        let source_root = tempfile::TempDir::new().expect("source rootfs");
        std::fs::create_dir_all(source_root.path().join("etc/init.d"))
            .expect("create init scripts");
        std::fs::write(
            source_root.path().join("etc/init.d/rcS"),
            "chmod 666 /dev/hackme\n",
        )
        .expect("write rcS");
        std::fs::write(source_root.path().join("hackme.ko"), b"module").expect("write module");

        let initramfs = workspace.path().join("initramfs.cpio.gz");
        kernel_initramfs::pack(
            source_root.path(),
            &initramfs,
            kernel_initramfs::Compression::Gzip,
        )
        .expect("pack initramfs");
        let original = std::fs::read(&initramfs).expect("read original initramfs");

        let bzimage = workspace.path().join("bzImage");
        std::fs::write(&bzimage, synthetic_bzimage()).expect("write bzImage");
        let run_script = workspace.path().join("run.sh");
        std::fs::write(
            &run_script,
            format!(
                "#!/bin/sh\nqemu-system-x86_64 -kernel {} -initrd {} -append \"console=ttyS0 kaslr kpti=1\"\n",
                bzimage.display(),
                initramfs.display()
            ),
        )
        .expect("write run script");

        let debug_initramfs = workspace.path().join("initramfs-debug.cpio.gz");
        let rootfs = workspace.path().join("initramfs");
        let modules = workspace.path().join("kernel_modules");
        let vmlinux = workspace.path().join("vmlinux");
        let debug_run = workspace.path().join("run-debug.sh");
        let exploit = workspace.path().join("exploit.c");
        let build = workspace.path().join("build-exploit.sh");
        let opts = Opts {
            pwn: crate::opts::PwnOpts::default(),
            cmd: Some(Command::Kernel(KernelOpts {
                kernel: Some(bzimage),
                initramfs: Some(initramfs.clone()),
                debug_initramfs: Some(debug_initramfs.clone()),
                run_script: Some(run_script),
                rootfs_dir: rootfs.clone(),
                vmlinux_path: vmlinux.clone(),
                debug_run_path: debug_run.clone(),
                exploit_path: exploit.clone(),
                build_path: build.clone(),
                modules_dir: modules.clone(),
                ..KernelOpts::default()
            })),
            quiet: false,
            verbose: 0,
            json: false,
        };

        let summary = run_with_summary(opts).expect("run kernel flow");
        assert!(summary.success(), "{:?}", summary.steps);
        assert_eq!(
            std::fs::read(&initramfs).expect("read preserved initramfs"),
            original
        );
        assert_eq!(
            std::fs::read(&debug_initramfs).expect("read debug initramfs"),
            original
        );
        assert!(rootfs.join("hackme.ko").is_file());
        assert!(modules.join("hackme.ko").is_file());
        assert!(vmlinux.is_file());
        assert!(debug_run.is_file());
        assert!(exploit.is_file());
        assert!(build.is_file());
    }

    #[test]
    fn clap_kernel_command_does_not_require_userspace_binary() {
        let opts = Opts::try_parse_from([
            "pwninit",
            "kernel",
            "--kernel",
            "bzImage",
            "--initramfs",
            "initramfs.cpio.gz",
        ])
        .expect("kernel CLI should parse independently");
        assert!(matches!(opts.cmd, Some(Command::Kernel(_))));
    }
}
