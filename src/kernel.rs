use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use snafu::Snafu;

use crate::kernel_image;
use crate::kernel_initramfs::{self, Compression};
use crate::opts::KernelOpts;
use crate::output;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    Written,
    Overwritten,
    SkippedExisting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractOutcome {
    Extracted(Compression),
    Replaced(Compression),
    SkippedExisting(Compression),
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("kernel path was not resolved"))]
    MissingKernel,

    #[snafu(display("initramfs path was not resolved"))]
    MissingInitramfs,

    #[snafu(display("debug initramfs path was not resolved"))]
    MissingDebugInitramfs,

    #[snafu(display("failed inspecting initramfs: {}", source))]
    InitramfsInspect { source: kernel_initramfs::Error },

    #[snafu(display("failed extracting initramfs: {}", source))]
    InitramfsExtract { source: kernel_initramfs::Error },

    #[snafu(display("failed extracting vmlinux: {}", source))]
    Vmlinux { source: kernel_image::Error },

    #[snafu(display("failed reading {}: {}", path.display(), source))]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed writing {}: {}", path.display(), source))]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed creating directory {}: {}", path.display(), source))]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed replacing {}: {}", path.display(), source))]
    Replace {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed parsing QEMU launcher {}: {}", path.display(), message))]
    LauncherParse { path: PathBuf, message: String },

    #[snafu(display("kernel module name collision for {}", name.to_string_lossy()))]
    ModuleCollision { name: OsString },

    #[snafu(display("generated output path traverses symlink {}", path.display()))]
    UnsafeOutputSymlink { path: PathBuf },

    #[snafu(display(
        "existing rootfs {} does not contain init, linuxrc, or sbin/init",
        path.display()
    ))]
    InvalidRootfs { path: PathBuf },
}

pub type Result<T> = std::result::Result<T, Error>;

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        reject_symlink_components(parent)?;
        std::fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::UnsafeOutputSymlink { path: current });
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(Error::Read {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn temp_file_for(path: &Path) -> Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    tempfile::NamedTempFile::new_in(parent).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn persist_generated(
    temporary: tempfile::NamedTempFile,
    path: &Path,
    force: bool,
    existed: bool,
) -> Result<WriteOutcome> {
    if force {
        temporary.persist(path).map_err(|err| Error::Write {
            path: path.to_path_buf(),
            source: err.error,
        })?;
        return Ok(if existed {
            WriteOutcome::Overwritten
        } else {
            WriteOutcome::Written
        });
    }

    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(WriteOutcome::Written),
        Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(WriteOutcome::SkippedExisting)
        }
        Err(err) => Err(Error::Write {
            path: path.to_path_buf(),
            source: err.error,
        }),
    }
}

fn write_generated(
    path: &Path,
    bytes: &[u8],
    force: bool,
    executable: bool,
) -> Result<WriteOutcome> {
    if path.exists() && !force {
        return Ok(WriteOutcome::SkippedExisting);
    }
    ensure_parent(path)?;
    let existed = path.exists();
    let mut temporary = temp_file_for(path)?;
    temporary.write_all(bytes).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source,
    })?;
    temporary.flush().map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source,
    })?;
    let outcome = persist_generated(temporary, path, force, existed)?;
    if executable && outcome != WriteOutcome::SkippedExisting {
        let metadata = std::fs::metadata(path).map_err(|source| Error::Write {
            path: path.to_path_buf(),
            source,
        })?;
        let mode = metadata.permissions().mode() | 0o111;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(
            |source| Error::Write {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }
    Ok(outcome)
}

fn replace_directory(temporary: &Path, output: &Path) -> Result<bool> {
    ensure_parent(output)?;
    if !output.exists() {
        std::fs::rename(temporary, output).map_err(|source| Error::Replace {
            path: output.to_path_buf(),
            source,
        })?;
        return Ok(false);
    }

    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let backup = tempfile::Builder::new()
        .prefix(".pwninit-kernel-backup-")
        .tempdir_in(parent)
        .map_err(|source| Error::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    let previous = backup.path().join("previous");
    std::fs::rename(output, &previous).map_err(|source| Error::Replace {
        path: output.to_path_buf(),
        source,
    })?;
    if let Err(source) = std::fs::rename(temporary, output) {
        let _ = std::fs::rename(&previous, output);
        return Err(Error::Replace {
            path: output.to_path_buf(),
            source,
        });
    }
    Ok(true)
}

pub fn extract_rootfs(opts: &KernelOpts) -> Result<ExtractOutcome> {
    let initramfs = opts.initramfs.as_deref().ok_or(Error::MissingInitramfs)?;
    reject_symlink_components(&opts.rootfs_dir)?;
    if opts.rootfs_dir.exists() && !opts.force {
        let metadata =
            std::fs::symlink_metadata(&opts.rootfs_dir).map_err(|source| Error::Read {
                path: opts.rootfs_dir.clone(),
                source,
            })?;
        if !metadata.is_dir()
            || !["init", "linuxrc", "sbin/init"]
                .into_iter()
                .any(|path| opts.rootfs_dir.join(path).exists())
        {
            return Err(Error::InvalidRootfs {
                path: opts.rootfs_dir.clone(),
            });
        }
        let compression = kernel_initramfs::inspect(initramfs)
            .map_err(|source| Error::InitramfsInspect { source })?;
        return Ok(ExtractOutcome::SkippedExisting(compression));
    }

    let parent = opts
        .rootfs_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
        path: parent.to_path_buf(),
        source,
    })?;
    let temporary = tempfile::Builder::new()
        .prefix(".pwninit-initramfs-")
        .tempdir_in(parent)
        .map_err(|source| Error::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    let extracted = temporary.path().join("rootfs");
    let compression = kernel_initramfs::extract(initramfs, &extracted)
        .map_err(|source| Error::InitramfsExtract { source })?;
    let replaced = replace_directory(&extracted, &opts.rootfs_dir)?;
    Ok(if replaced {
        ExtractOutcome::Replaced(compression)
    } else {
        ExtractOutcome::Extracted(compression)
    })
}

pub fn extract_vmlinux(opts: &KernelOpts) -> Result<WriteOutcome> {
    let kernel = opts.kernel.as_deref().ok_or(Error::MissingKernel)?;
    if opts.vmlinux_path.exists() && !opts.force {
        return Ok(WriteOutcome::SkippedExisting);
    }
    ensure_parent(&opts.vmlinux_path)?;
    let existed = opts.vmlinux_path.exists();
    let temporary = temp_file_for(&opts.vmlinux_path)?;
    kernel_image::extract_vmlinux(kernel, temporary.path())
        .map_err(|source| Error::Vmlinux { source })?;
    persist_generated(temporary, &opts.vmlinux_path, opts.force, existed)
}

pub fn initialize_debug_initramfs(opts: &KernelOpts) -> Result<WriteOutcome> {
    let source = opts.initramfs.as_deref().ok_or(Error::MissingInitramfs)?;
    let destination = opts
        .debug_initramfs
        .as_deref()
        .ok_or(Error::MissingDebugInitramfs)?;
    if destination.exists() && !opts.force {
        kernel_initramfs::inspect(destination)
            .map_err(|source| Error::InitramfsInspect { source })?;
        return Ok(WriteOutcome::SkippedExisting);
    }
    ensure_parent(destination)?;
    let existed = destination.exists();
    let mut input = std::fs::File::open(source).map_err(|source_err| Error::Read {
        path: source.to_path_buf(),
        source: source_err,
    })?;
    let mut temporary = temp_file_for(destination)?;
    std::io::copy(&mut input, &mut temporary).map_err(|source| Error::Write {
        path: destination.to_path_buf(),
        source,
    })?;
    temporary.flush().map_err(|source| Error::Write {
        path: destination.to_path_buf(),
        source,
    })?;
    persist_generated(temporary, destination, opts.force, existed)
}

fn collect_modules(directory: &Path, modules: &mut Vec<PathBuf>) -> Result<()> {
    let mut children = std::fs::read_dir(directory)
        .map_err(|source| Error::Read {
            path: directory.to_path_buf(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| Error::Read {
            path: directory.to_path_buf(),
            source,
        })?;
    children.sort_by_cached_key(|entry| entry.file_name().as_bytes().to_vec());
    for child in children {
        let path = child.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| Error::Read {
            path: path.clone(),
            source,
        })?;
        if metadata.is_dir() {
            collect_modules(&path, modules)?;
        } else if metadata.is_file() && path.extension() == Some(OsStr::new("ko")) {
            modules.push(path);
        }
    }
    Ok(())
}

pub fn export_modules(opts: &KernelOpts) -> Result<(usize, usize)> {
    reject_symlink_components(&opts.modules_dir)?;
    let mut modules = Vec::new();
    collect_modules(&opts.rootfs_dir, &mut modules)?;

    let mut names = HashMap::<OsString, PathBuf>::new();
    for module in &modules {
        let Some(name) = module.file_name() else {
            continue;
        };
        if names.insert(name.to_os_string(), module.clone()).is_some() {
            return Err(Error::ModuleCollision {
                name: name.to_os_string(),
            });
        }
    }
    if modules.is_empty() {
        return Ok((0, 0));
    }

    std::fs::create_dir_all(&opts.modules_dir).map_err(|source| Error::CreateDir {
        path: opts.modules_dir.clone(),
        source,
    })?;
    let mut copied = 0;
    let mut skipped = 0;
    for module in modules {
        let destination = opts
            .modules_dir
            .join(module.file_name().expect("collected module has a name"));
        if destination.exists() && !opts.force {
            skipped += 1;
            continue;
        }
        std::fs::copy(&module, &destination).map_err(|source| Error::Write {
            path: destination,
            source,
        })?;
        copied += 1;
    }
    Ok((copied, skipped))
}

fn read_launcher_command(path: &Path) -> Result<Vec<String>> {
    let script = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut logical = String::new();
    let mut collecting = false;
    for raw_line in script.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !collecting && line.contains("qemu-system") {
            collecting = true;
        }
        if !collecting {
            continue;
        }
        if let Some(prefix) = line.strip_suffix('\\') {
            logical.push_str(prefix);
            logical.push(' ');
        } else {
            logical.push_str(line);
            break;
        }
    }
    if logical.is_empty() {
        return Err(Error::LauncherParse {
            path: path.to_path_buf(),
            message: "no QEMU command found".to_string(),
        });
    }
    let mut tokens = shell_words::split(&logical).map_err(|err| Error::LauncherParse {
        path: path.to_path_buf(),
        message: err.to_string(),
    })?;
    if tokens.iter().any(|token| {
        token.contains('$')
            || token.contains('`')
            || matches!(
                token.as_str(),
                "|" | "||" | "&" | "&&" | ">" | ">>" | "<" | "<<"
            )
    }) {
        return Err(Error::LauncherParse {
            path: path.to_path_buf(),
            message: "shell expansions, pipelines, and redirections are unsupported".to_string(),
        });
    }
    if tokens.first().map(String::as_str) == Some("exec") {
        tokens.remove(0);
    }
    if tokens.first().map(|token| token.contains("qemu-system")) != Some(true) {
        return Err(Error::LauncherParse {
            path: path.to_path_buf(),
            message: "QEMU command must start with qemu-system".to_string(),
        });
    }
    Ok(tokens)
}

fn debug_kernel_command_line(value: &str) -> String {
    let mut tokens = value
        .split_whitespace()
        .filter(|token| {
            !matches!(
                token.split('=').next().unwrap_or(*token),
                "kaslr"
                    | "nokaslr"
                    | "pti"
                    | "nopti"
                    | "kpti"
                    | "smep"
                    | "nosmep"
                    | "smap"
                    | "nosmap"
            )
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    tokens.extend(
        ["nokaslr", "nopti", "nosmep", "nosmap"]
            .into_iter()
            .map(str::to_string),
    );
    tokens.join(" ")
}

fn debug_qemu_args(opts: &KernelOpts) -> Result<Vec<String>> {
    let default_args = || -> Result<Vec<String>> {
        Ok(vec![
            "qemu-system-x86_64".to_string(),
            "-m".to_string(),
            "128M".to_string(),
            "-cpu".to_string(),
            "kvm64,+smep,+smap".to_string(),
            "-kernel".to_string(),
            opts.kernel
                .as_ref()
                .ok_or(Error::MissingKernel)?
                .to_string_lossy()
                .into_owned(),
            "-initrd".to_string(),
            opts.debug_initramfs
                .as_ref()
                .ok_or(Error::MissingDebugInitramfs)?
                .to_string_lossy()
                .into_owned(),
            "-snapshot".to_string(),
            "-nographic".to_string(),
            "-monitor".to_string(),
            "/dev/null".to_string(),
            "-no-reboot".to_string(),
            "-append".to_string(),
            "console=ttyS0 quiet panic=1".to_string(),
        ])
    };
    let mut args = if let Some(run_script) = &opts.run_script {
        match read_launcher_command(run_script) {
            Ok(args) => args,
            Err(err) => {
                output::warning(format!(
                    "{}; generating a conservative QEMU launcher instead",
                    err
                ));
                default_args()?
            }
        }
    } else {
        default_args()?
    };

    let append = args.iter().position(|arg| arg == "-append");
    if let Some(index) = append {
        let value = args
            .get(index + 1)
            .cloned()
            .ok_or_else(|| Error::LauncherParse {
                path: opts
                    .run_script
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("<generated>")),
                message: "-append has no value".to_string(),
            })?;
        args[index + 1] = debug_kernel_command_line(&value);
    } else {
        args.push("-append".to_string());
        args.push(debug_kernel_command_line("console=ttyS0 quiet panic=1"));
    }
    let debug_initramfs = opts
        .debug_initramfs
        .as_ref()
        .ok_or(Error::MissingDebugInitramfs)?
        .to_string_lossy()
        .into_owned();
    if let Some(index) = args.iter().position(|arg| arg == "-initrd") {
        if args.get(index + 1).is_none() {
            return Err(Error::LauncherParse {
                path: opts
                    .run_script
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("<generated>")),
                message: "-initrd has no value".to_string(),
            });
        }
        args[index + 1] = debug_initramfs;
    } else {
        args.push("-initrd".to_string());
        args.push(debug_initramfs);
    }
    Ok(args)
}

fn shell_join(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|token| shell_words::quote(token).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn generate_debug_launcher(opts: &KernelOpts) -> Result<WriteOutcome> {
    let command = shell_join(&debug_qemu_args(opts)?);
    let script = format!(
        "#!/bin/sh\nset -eu\n\nif [ \"${{GDB:-0}}\" = 1 ]; then\n    set -- -s -S \"$@\"\nfi\n\nexec {command} \"$@\"\n"
    );
    write_generated(&opts.debug_run_path, script.as_bytes(), opts.force, true)
}

fn relative_flag_paths(opts: &KernelOpts) -> Result<Vec<PathBuf>> {
    let Some(run_script) = &opts.run_script else {
        return Ok(Vec::new());
    };
    let Ok(tokens) = read_launcher_command(run_script) else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token.as_str(), "-hda" | "-hdb" | "-hdc" | "-hdd") {
            if let Some(value) = tokens.get(index + 1) {
                let path = PathBuf::from(value);
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                let is_top_level = path
                    .components()
                    .filter(|component| matches!(component, std::path::Component::Normal(_)))
                    .count()
                    == 1;
                if !path.is_absolute() && is_top_level && name.contains("flag") {
                    paths.push(path);
                }
            }
        }
    }
    Ok(paths)
}

pub fn create_placeholder_flags(opts: &KernelOpts) -> Result<(usize, usize)> {
    let mut written = 0;
    let mut skipped = 0;
    for path in relative_flag_paths(opts)? {
        match write_generated(&path, b"flag{local_kernel_pwn_test_flag}\n", false, false)? {
            WriteOutcome::Written => written += 1,
            WriteOutcome::SkippedExisting => skipped += 1,
            WriteOutcome::Overwritten => unreachable!("placeholder flags are never overwritten"),
        }
    }
    Ok((written, skipped))
}

pub fn detect_device(rootfs: &Path) -> Option<String> {
    let mut candidates = Vec::new();
    let init_dir = rootfs.join("etc/init.d");
    let Ok(entries) = std::fs::read_dir(init_dir) else {
        return None;
    };
    for entry in entries.flatten() {
        let Ok(contents) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        for word in contents.split(|ch: char| ch.is_whitespace() || matches!(ch, '\'' | '"' | ';'))
        {
            if let Some(path) = word.strip_prefix("/dev/") {
                let name = path
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-');
                if !name.is_empty() {
                    let device = format!("/dev/{name}");
                    if !candidates.contains(&device) {
                        candidates.push(device);
                    }
                }
            }
        }
    }
    match candidates.as_slice() {
        [device] => Some(device.clone()),
        _ => None,
    }
}

pub fn generate_exploit(opts: &KernelOpts) -> Result<WriteOutcome> {
    let template = match &opts.template_path {
        Some(path) => std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.clone(),
            source,
        })?,
        None => include_str!("template_kernel.c").to_string(),
    };
    let device = detect_device(&opts.rootfs_dir).unwrap_or_else(|| "/dev/vuln".to_string());
    let source = template.replace("{device_path}", &device);
    write_generated(&opts.exploit_path, source.as_bytes(), opts.force, false)
}

fn compression_command(compression: Compression) -> &'static str {
    match compression {
        Compression::None => "cat",
        Compression::Gzip => "gzip -9",
        Compression::Xz => "xz -9",
        Compression::Lzma => "xz --format=lzma -9",
        Compression::Bzip2 => "bzip2 -9",
        Compression::Zstd => "zstd -19 -q",
        Compression::Lz4 => "lz4 -9 -q",
        Compression::Lz4Legacy => "lz4 -l -9 -q",
    }
}

fn compression_program(compression: Compression) -> &'static str {
    match compression {
        Compression::None => "cat",
        Compression::Gzip => "gzip",
        Compression::Xz => "xz",
        Compression::Lzma => "xz",
        Compression::Bzip2 => "bzip2",
        Compression::Zstd => "zstd",
        Compression::Lz4 => "lz4",
        Compression::Lz4Legacy => "lz4",
    }
}

fn shell_quote_path(path: &Path) -> String {
    shell_words::quote(&path.to_string_lossy()).into_owned()
}

pub fn generate_build_helper(opts: &KernelOpts, compression: Compression) -> Result<WriteOutcome> {
    let exploit = shell_quote_path(&opts.exploit_path);
    let rootfs = shell_quote_path(&opts.rootfs_dir);
    let initramfs = shell_quote_path(
        opts.debug_initramfs
            .as_deref()
            .ok_or(Error::MissingDebugInitramfs)?,
    );
    let compressor = compression_command(compression);
    let compressor_program = compression_program(compression);
    let script = format!(
        r#"#!/bin/sh
set -eu

CC=${{CC:-gcc}}
CFLAGS=${{CFLAGS:--static}}
EXPLOIT_NAME=${{EXPLOIT_NAME:-exploit}}

case "$EXPLOIT_NAME" in
    ""|"."|".."|*/*)
        echo "error: EXPLOIT_NAME must be a single file name" >&2
        exit 1
        ;;
esac

command -v "$CC" >/dev/null 2>&1 || {{
    echo "error: compiler not found: $CC" >&2
    exit 1
}}
command -v cpio >/dev/null 2>&1 || {{
    echo "error: cpio is required to rebuild the initramfs" >&2
    exit 1
}}
command -v {compressor_program} >/dev/null 2>&1 || {{
    echo "error: {compressor_program} is required to rebuild the initramfs" >&2
    exit 1
}}

source_path={exploit}
rootfs={rootfs}
archive={initramfs}
binary="$rootfs/$EXPLOIT_NAME"
temporary="$archive.pwninit-new.$$"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

# CFLAGS is intentionally split so callers can override it like normal compiler flags.
# shellcheck disable=SC2086
"$CC" $CFLAGS "$source_path" -o "$binary"

(
    cd "$rootfs"
    find . -print0 | cpio --null --format=newc -o 2>/dev/null
) | {compressor} > "$temporary"

mv "$temporary" "$archive"
trap - EXIT HUP INT TERM
echo "rebuilt $archive with $binary"
"#
    );
    write_generated(&opts.build_path, script.as_bytes(), opts.force, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disables_kernel_mitigations_without_duplicates() {
        let args =
            debug_kernel_command_line("console=ttyS0 kaslr kpti=1 smep smap quiet nokaslr panic=1");
        assert_eq!(
            args,
            "console=ttyS0 quiet panic=1 nokaslr nopti nosmep nosmap"
        );
    }

    #[test]
    fn detects_single_device_from_init_script() {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("etc/init.d")).expect("create init dir");
        std::fs::write(
            root.path().join("etc/init.d/rcS"),
            "insmod /hackme.ko\nchmod 666 /dev/hackme\n",
        )
        .expect("write rcS");
        assert_eq!(detect_device(root.path()).as_deref(), Some("/dev/hackme"));
    }

    #[test]
    fn preserves_launcher_and_generates_debug_copy() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let run = root.path().join("run.sh");
        std::fs::write(
            &run,
            "#!/bin/sh\nqemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio.gz -append \"console=ttyS0 kaslr kpti=1\"\n",
        )
        .expect("write run");
        let original = std::fs::read(&run).expect("read original");

        let opts = KernelOpts {
            kernel: Some(PathBuf::from("bzImage")),
            initramfs: Some(PathBuf::from("initramfs.cpio.gz")),
            debug_initramfs: Some(PathBuf::from("initramfs-debug.cpio.gz")),
            run_script: Some(run.clone()),
            debug_run_path: root.path().join("run-debug.sh"),
            ..KernelOpts::default()
        };
        assert_eq!(
            generate_debug_launcher(&opts).expect("generate launcher"),
            WriteOutcome::Written
        );
        assert_eq!(std::fs::read(&run).expect("read run"), original);
        let debug = std::fs::read_to_string(&opts.debug_run_path).expect("read debug");
        assert!(debug.contains("nokaslr nopti nosmep nosmap"));
        assert!(!debug.contains("kpti=1"));
        assert!(debug.contains("initramfs-debug.cpio.gz"));
        assert!(!debug.contains("-initrd initramfs.cpio.gz"));
    }

    #[test]
    fn exports_modules_into_kernel_modules_directory() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let rootfs = root.path().join("initramfs");
        std::fs::create_dir_all(rootfs.join("lib/modules")).expect("create modules");
        std::fs::write(rootfs.join("lib/modules/hackme.ko"), b"module").expect("write module");
        let modules_dir = root.path().join("kernel_modules");
        let opts = KernelOpts {
            rootfs_dir: rootfs,
            modules_dir: modules_dir.clone(),
            ..KernelOpts::default()
        };
        assert_eq!(export_modules(&opts).expect("export"), (1, 0));
        assert_eq!(
            std::fs::read(modules_dir.join("hackme.ko")).expect("read module"),
            b"module"
        );
    }

    #[test]
    fn creates_debug_initramfs_without_modifying_original() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let original = root.path().join("initramfs.cpio.gz");
        let debug = root.path().join("initramfs-debug.cpio.gz");
        std::fs::write(&original, b"original archive").expect("write original");
        let opts = KernelOpts {
            initramfs: Some(original.clone()),
            debug_initramfs: Some(debug.clone()),
            ..KernelOpts::default()
        };

        assert_eq!(
            initialize_debug_initramfs(&opts).expect("initialize debug archive"),
            WriteOutcome::Written
        );
        assert_eq!(
            std::fs::read(&original).expect("read original"),
            b"original archive"
        );
        assert_eq!(
            std::fs::read(&debug).expect("read debug"),
            b"original archive"
        );

        std::fs::write(&debug, b"user debug archive").expect("modify debug");
        assert!(initialize_debug_initramfs(&opts).is_err());
        assert_eq!(
            std::fs::read(&debug).expect("read invalid debug"),
            b"user debug archive"
        );
    }

    #[test]
    fn build_helper_targets_only_debug_initramfs() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let opts = KernelOpts {
            initramfs: Some(root.path().join("initramfs.cpio.gz")),
            debug_initramfs: Some(root.path().join("initramfs-debug.cpio.gz")),
            rootfs_dir: root.path().join("initramfs"),
            exploit_path: root.path().join("exploit.c"),
            build_path: root.path().join("build-exploit.sh"),
            ..KernelOpts::default()
        };
        generate_build_helper(&opts, Compression::Gzip).expect("build helper");
        let script = std::fs::read_to_string(&opts.build_path).expect("read helper");
        assert!(script.contains("initramfs-debug.cpio.gz"));
        assert!(!script.contains(&format!(
            "archive={}",
            opts.initramfs.as_deref().expect("original path").display()
        )));
        assert!(script.contains("CFLAGS=${CFLAGS:--static}"));
        assert!(!script.contains("-O2"));
        assert!(!script.contains("-masm=intel"));
    }

    #[test]
    fn generated_exploit_uses_intel_syntax_and_empty_parameter_lists() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let rootfs = root.path().join("initramfs");
        std::fs::create_dir_all(rootfs.join("etc/init.d")).expect("create init dir");
        std::fs::write(rootfs.join("etc/init.d/rcS"), "chmod 666 /dev/hackme\n")
            .expect("write rcS");
        let opts = KernelOpts {
            rootfs_dir: rootfs,
            exploit_path: root.path().join("exploit.c"),
            ..KernelOpts::default()
        };
        generate_exploit(&opts).expect("generate exploit");
        let source = std::fs::read_to_string(&opts.exploit_path).expect("read exploit");
        assert!(source.contains("save_userland_state()"));
        assert!(source.contains("int main()"));
        assert!(source.contains(".intel_syntax noprefix"));
        assert!(!source.contains("(void)"));
        assert!(source.contains(".att_syntax prefix"));
    }

    #[test]
    fn module_export_rejects_symlinked_output_directory() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let rootfs = root.path().join("initramfs");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&rootfs).expect("create rootfs");
        std::fs::create_dir_all(&outside).expect("create outside");
        std::fs::write(rootfs.join("hackme.ko"), b"module").expect("write module");
        let modules_dir = root.path().join("kernel_modules");
        std::os::unix::fs::symlink(&outside, &modules_dir).expect("symlink modules directory");
        let opts = KernelOpts {
            rootfs_dir: rootfs,
            modules_dir,
            ..KernelOpts::default()
        };
        assert!(matches!(
            export_modules(&opts),
            Err(Error::UnsafeOutputSymlink { .. })
        ));
        assert!(!outside.join("hackme.ko").exists());
    }

    #[test]
    fn nested_flag_disk_paths_do_not_create_placeholders() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let run = root.path().join("run.sh");
        std::fs::write(&run, "#!/bin/sh\nqemu-system-x86_64 -hdb nested/flag.txt\n")
            .expect("write run script");
        let opts = KernelOpts {
            run_script: Some(run),
            ..KernelOpts::default()
        };
        assert!(relative_flag_paths(&opts)
            .expect("inspect flag paths")
            .is_empty());
    }

    #[test]
    fn shell_variable_launchers_fall_back_to_literal_paths() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let run = root.path().join("run.sh");
        std::fs::write(
            &run,
            "#!/bin/sh\nKERNEL=bzImage\nqemu-system-x86_64 -kernel \"$KERNEL\" -initrd initramfs.cpio.gz\n",
        )
        .expect("write run script");
        let opts = KernelOpts {
            kernel: Some(PathBuf::from("bzImage")),
            initramfs: Some(PathBuf::from("initramfs.cpio.gz")),
            debug_initramfs: Some(PathBuf::from("initramfs-debug.cpio.gz")),
            run_script: Some(run),
            debug_run_path: root.path().join("run-debug.sh"),
            ..KernelOpts::default()
        };
        generate_debug_launcher(&opts).expect("generate fallback launcher");
        let debug = std::fs::read_to_string(&opts.debug_run_path).expect("read launcher");
        assert!(debug.contains("-kernel bzImage"));
        assert!(!debug.contains("$KERNEL"));
    }
}
