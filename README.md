# pwninit

[![Build Status](https://github.com/sherlockholmestech/pwninit/workflows/Build/badge.svg)](https://github.com/sherlockholmestech/pwninit/actions)
[![Crates.io](https://img.shields.io/crates/v/pwninit)](https://crates.io/crates/pwninit)
[![Docs.rs](https://docs.rs/pwninit/badge.svg)](https://docs.rs/pwninit)

A tool for automating userspace and Linux kernel exploit challenges, as well as reverse engineering ones.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Features](#features)
- [Commands at a Glance](#commands-at-a-glance)
- [Usage](#usage)
  - [Pwn Challenges](#pwn-challenges)
  - [Kernel Pwn Challenges](#kernel-pwn-challenges)
  - [Reverse Engineering Challenges](#reverse-engineering-challenges)
  - [Downloading a libc](#downloading-a-libc)
- [Advanced Configuration](#advanced-configuration)
  - [Skipping Steps](#skipping-steps)
  - [Virtual Environments](#virtual-environments)
  - [Patching Modes](#patching-modes)
  - [Custom Templates](#custom-templates)
  - [Output and Automation](#output-and-automation)
- [Migrating from v4](#migrating-from-v4)

## Installation

You can build `pwninit` from source using `cargo`. Note that `openssl`, `liblzma`, and `pkg-config` are required system dependencies for the build process.

```sh
cargo build --release
```

The compiled binary will be available in the `target/release` directory.

## Quick Start

Run `pwninit` in the folder that holds your challenge files. It works out what
kind of challenge it is (a kernel image plus an initramfs means a kernel
challenge, anything else a userspace pwn challenge) and sets it up.

Not sure what it will do? Add `--dry-run` (`-n`) to see the plan first. Nothing
is changed:

```text
$ ls
chall  libc.so.6

$ pwninit --dry-run
bin: ./chall
libc: ./libc.so.6

plan (dry run, nothing was changed)
→ prepare binary: make ./chall executable
→ prepare libc: inspect ./libc.so.6, download a matching linker, download debug symbols and unstrip
→ prepare linker: make the downloaded linker executable
- create environment: --uv was not requested
→ patch binary: write ./chall_patched using patchelf
→ generate solve script: write solve.py

Run again without --dry-run to apply.

$ pwninit
```

Every command has examples at the bottom of its help: `pwninit --help`,
`pwninit pwn --help`, `pwninit libc docker --help`, and so on.

## Features

- Automatically sets challenge binaries as executable.
- Downloads a matching linker (`ld-linux.so.*`) to segfaultlessly load the provided libc.
- Fetches debug symbols and unstrips libc plus related glibc shared libraries in the challenge directory automatically.
- Patches binaries using `patchelf` (or natively) to set the correct `RPATH` and `PT_INTERP`.
- Unpacks kernel initramfs archives, extracts `vmlinux`, exports kernel modules, and generates a no-mitigation QEMU development setup.
- Downloads additional libraries from the same libc package on demand.
- Generates template solve scripts for both `pwntools` and `angr` / `z3`.
- Supports creating local `uv` virtual environments (`.venv`) for python dependencies.

## Commands at a Glance

```text
pwninit                      detect the challenge type here and set it up
pwninit pwn                  userspace exploitation
pwninit rev                  reverse engineering
pwninit kernel               kernel exploitation
pwninit libc launchpad VER   download Ubuntu glibc VER
pwninit libc docker ...      copy libc out of a Docker image
pwninit libc debian VER ...  download Debian glibc VER

Global flags (any command): -n/--dry-run  -q/--quiet  -v/--verbose  --json
```

Flags are grouped in each command's help as **Inputs** (files pwninit reads),
**Steps** (what it does), and **Solve script** / **Output paths** (what it
writes). Short flags mean the same thing everywhere: `-b` binary, `-t` template,
`-s` main output file, `-f` force, `-u` uv, `-o` output directory.

## Usage

### Pwn Challenges

```sh
pwninit pwn
```

Bare `pwninit` does the same when the folder has no kernel files. pwninit finds
the binary, libc, and linker by name: the libc contains `libc`, the linker
contains `ld-`, and the binary is any other ELF. Name them yourself if detection
picks the wrong file or finds more than one:

```sh
pwninit pwn -b ./challenge_bin -l ./libc.so.6 -d ./ld-linux.so.2
```

Debug symbols are chosen from the detected glibc package and applied to every
local `.so` file. Pick the repository with `--debug-source`:

```sh
pwninit pwn --debug-source launchpad
pwninit pwn --debug-source debian
```

If the exact debug package is unavailable, pwninit falls back to the
distribution's debuginfod service and looks up symbols by ELF build ID. Use
`--skip unstrip` to skip debug symbols entirely.

### Kernel Pwn Challenges

```sh
pwninit kernel
```

Bare `pwninit` does the same when it finds an x86-64 `vmlinuz`/`bzImage` and an
initramfs. The kernel workflow creates a development layout without modifying
the supplied kernel, initramfs, or QEMU launcher:

```text
vmlinuz                       original kernel image
initramfs.cpio.gz             original initramfs, never rewritten
initramfs-debug.cpio.gz       writable debug initramfs
initramfs/                    unpacked root filesystem
kernel_modules/               exported .ko files for analysis
vmlinux                       extracted x86-64 kernel ELF
run-debug.sh                  QEMU launcher with mitigations disabled
exploit.c                     static C exploit template
build-exploit.sh              compile and repack helper
```

`run-debug.sh` keeps the challenge's QEMU options where possible, switches the
initrd to the debug archive, and adds `nokaslr nopti nosmep nosmap`. Set `GDB=1`
to start QEMU paused with a GDB server:

```sh
./run-debug.sh
GDB=1 ./run-debug.sh
```

Build the generated Intel-syntax exploit and repack only the debug initramfs:

```sh
./build-exploit.sh
```

The helper defaults to `gcc -static`. Override `CC`, `CFLAGS`, or
`EXPLOIT_NAME` through the environment. It requires `cpio` and the compressor
used by the original archive.

Plain newc CPIO and gzip, xz, legacy lzma, bzip2, zstd, modern lz4, and legacy
lz4 compression are supported. Existing generated files are kept unless
`--force` is given.

Name ambiguous or non-standard inputs explicitly:

```sh
pwninit kernel -k ./bzImage -i ./rootfs.cpio.xz -r ./start.sh
```

Use `--skip vmlinux,modules,template` to leave out optional artifacts. Every
output location can be changed; see the **Output paths** section of
`pwninit kernel --help`.

### Reverse Engineering Challenges

pwn and rev binaries look the same, so rev always needs its command:

```sh
pwninit rev
pwninit rev -b ./challenge_bin
```

This makes the binary executable and writes an `angr` + `z3` `solve.py`.

### Downloading a libc

`pwninit libc` takes the source as a subcommand, and each source only accepts
its own flags:

```sh
pwninit libc launchpad 2.31 --lib libm.so.6
pwninit libc docker --image ubuntu:22.04
pwninit libc docker --distro debian --release bookworm
pwninit libc debian 2.36 --release bookworm
```

These options work with every source:

| Flag | Meaning |
|---|---|
| `-a, --arch` | `amd64` (default) or `i386` |
| `-o, --output-dir` | directory for everything downloaded (default `.`) |
| `--libc-output` | libc file name inside that directory (default `libc.so.6`) |
| `-L, --lib NAME` | also download this library from the libc package; repeatable. Accepts sonames (`libm.so.6`) and aliases (`libm`, `libpthread`) |
| `--from-bin PATH` | also download every glibc library this binary needs |

When several package versions match, `launchpad` and `debian` prompt for one.
For scripts, disable the prompt or pick the exact version:

```sh
pwninit libc launchpad 2.31 --non-interactive
pwninit libc launchpad 2.31 --exact-version 2.31-0ubuntu9.18
```

An ambiguous `--non-interactive` lookup fails and lists the available versions.
`pwninit libc` only downloads runtime files; it does not unstrip them.

## Advanced Configuration

### Skipping Steps

Every optional step is turned off the same way, with `--skip` and a
comma-separated list:

| Command | Steps you can skip |
|---|---|
| `pwn` | `unstrip`, `patch`, `template` |
| `rev` | `template` |
| `kernel` | `vmlinux`, `modules`, `template` |

```sh
pwninit pwn --skip unstrip,patch
pwninit kernel --skip modules
```

### Virtual Environments

`--uv` (`-u`) creates a local `uv` virtual environment in `.venv` and installs
`pwntools` (pwn) or `angr` + `z3-solver` (rev). By default, no environment is
created.

```sh
pwninit pwn --uv
```

### Patching Modes

```sh
pwninit pwn --patch-mode patchelf   # default
pwninit pwn --patch-mode manual
pwninit pwn --skip patch            # don't patch at all
```

`patchelf` mode sets the `RPATH` to `.` whenever local shared libraries are
present and sets the interpreter to `./ld`. Manual mode rewrites every
`DT_NEEDED` entry with a matching local `.so` file to a short local alias such
as `./libm` or `./plugin` and rewrites `PT_INTERP` to `./ld`. Shared-object
names do not need a `lib` prefix.

Both modes create the necessary symlinks. Manual replacements must fit within
the original ELF string slot; oversized or unresolved entries are skipped with a
warning.

### Custom Templates

Use your own `solve.py` boilerplate with `--template-path` (`-t`), and rename
the `exe`, `libc`, and `ld` variables if you like:

```sh
pwninit pwn -t ~/.config/pwninit-template.py \
        --template-bin-name exe \
        --template-libc-name libc \
        --template-ld-name ld
```

Variable names must be valid, distinct Python identifiers and cannot be Python
keywords. See [`src/template.py`](src/template.py) for the template format and
available placeholders.

The solve script goes to `solve.py` by default. Existing files are kept and
reported as skipped unless `--force` (`-f`) is given:

```sh
pwninit pwn -s scripts/solve.py
pwninit pwn -s scripts/solve.py -f
```

To use your template on every run, add a shell alias:

```bash
alias pwninit-pwn='pwninit pwn -t ~/.config/pwninit-template.py --template-bin-name e'
```

### Output and Automation

Every run ends with a summary of completed, skipped, and failed steps. A failed
required step gives a nonzero exit status. `--best-effort` keeps going with
independent steps after a failure, but still exits nonzero.

| Flag | Effect |
|---|---|
| `-n, --dry-run` | print the plan and change nothing |
| `-q, --quiet` | print only step counts |
| `-v, --verbose` | print extra diagnostics |
| `--json` | print one machine-readable JSON result on stdout (includes `"dry_run"`) |

Global flags work before or after the command (`pwninit -n pwn` or
`pwninit pwn -n`). With `--json`, `pwninit libc launchpad`/`debian` need
`--non-interactive` or `--exact-version`, since they cannot prompt.

## Migrating from v4

v5 reorganizes the command line. Old flags are gone, not aliased:

| v4 | v5 |
|---|---|
| `pwninit --bin x` (pwn flags with no command) | `pwninit pwn --bin x` |
| bare `pwninit` always ran pwn | bare `pwninit` detects kernel vs pwn |
| `pwninit fetch-libc 2.31` | `pwninit libc launchpad 2.31` |
| `fetch-libc --source docker --image u:22.04` | `pwninit libc docker --image u:22.04` |
| `fetch-libc 2.36 --source debian --release b` | `pwninit libc debian 2.36 --release b` |
| `fetch-libc -b ./bin` / `-i img` / `-r rel` | `--from-bin` / `--image` / `--release` (long only) |
| `fetch-libc --output f` / `-O f` | `--libc-output f` |
| `--no-unstrip` | `--skip unstrip` |
| `--no-template` | `--skip template` |
| `--patch-mode none`, `--no-patch-bin` | `--skip patch` |
| `--no-patchelf` | `--patch-mode manual` |
| `--no-vmlinux`, `--no-export-modules` | `--skip vmlinux`, `--skip modules` |
