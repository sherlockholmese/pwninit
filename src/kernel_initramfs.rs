use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use lz4_flex::frame::FrameDecoder;
use snafu::Snafu;
use xz2::stream::Stream;

#[cfg(test)]
use std::ffi::OsStr;
#[cfg(test)]
use std::io::{Cursor, Write};
#[cfg(test)]
use std::os::unix::ffi::OsStrExt;
#[cfg(test)]
use std::os::unix::fs::MetadataExt;

#[cfg(test)]
use bzip2::write::BzEncoder;
#[cfg(test)]
use bzip2::Compression as BzCompression;
#[cfg(test)]
use flate2::write::GzEncoder;
#[cfg(test)]
use flate2::Compression as GzCompression;
#[cfg(test)]
use lz4_flex::frame::FrameEncoder;
#[cfg(test)]
use xz2::stream::LzmaOptions;
#[cfg(test)]
use xz2::write::XzEncoder;

const CPIO_MAGIC_NEWC: &[u8; 6] = b"070701";
const CPIO_MAGIC_CRC: &[u8; 6] = b"070702";
const CPIO_HEADER_LEN: usize = 110;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Xz,
    Lzma,
    Bzip2,
    Zstd,
    Lz4,
    Lz4Legacy,
}

impl Compression {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "cpio",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Lzma => "lzma",
            Self::Bzip2 => "bzip2",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
            Self::Lz4Legacy => "legacy lz4",
        }
    }

    pub fn signatures() -> &'static [(&'static [u8], Compression)] {
        &[
            (CPIO_MAGIC_NEWC, Compression::None),
            (CPIO_MAGIC_CRC, Compression::None),
            (&[0x1f, 0x8b, 0x08], Compression::Gzip),
            (&[0xfd, b'7', b'z', b'X', b'Z', 0x00], Compression::Xz),
            (&[0x5d, 0x00, 0x00], Compression::Lzma),
            (b"BZh", Compression::Bzip2),
            (&[0x28, 0xb5, 0x2f, 0xfd], Compression::Zstd),
            (&[0x04, 0x22, 0x4d, 0x18], Compression::Lz4),
            (&[0x02, 0x21, 0x4c, 0x18], Compression::Lz4Legacy),
        ]
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
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

    #[snafu(display("failed inspecting {}: {}", path.display(), source))]
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed creating directory {}: {}", path.display(), source))]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed setting permissions on {}: {}", path.display(), source))]
    Permissions {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed creating symlink {}: {}", path.display(), source))]
    Symlink {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display(
        "failed creating hard link {} to {}: {}",
        path.display(),
        target.display(),
        source
    ))]
    HardLink {
        path: PathBuf,
        target: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed decoding {} data: {}", compression, message))]
    Decompress {
        compression: &'static str,
        message: String,
    },

    #[snafu(display("failed encoding {} data: {}", compression, message))]
    Compress {
        compression: &'static str,
        message: String,
    },

    #[snafu(display("unsupported initramfs compression or archive format"))]
    UnknownFormat,

    #[snafu(display("malformed newc archive: {}", message))]
    Malformed { message: String },

    #[snafu(display("unsafe archive path: {}", path.display()))]
    UnsafePath { path: PathBuf },

    #[snafu(display("duplicate archive path: {}", path.display()))]
    DuplicatePath { path: PathBuf },

    #[snafu(display(
        "archive path {} traverses the symlink {}",
        path.display(),
        symlink.display()
    ))]
    SymlinkEscape { path: PathBuf, symlink: PathBuf },

    #[snafu(display("unsupported archive entry type {:o} at {}", mode, path.display()))]
    UnsupportedEntry { path: PathBuf, mode: u32 },

    #[snafu(display("{} is too large for the newc archive format", path.display()))]
    TooLarge { path: PathBuf },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
struct Entry<'a> {
    path: PathBuf,
    inode: u32,
    mode: u32,
    nlink: u32,
    dev_major: u32,
    dev_minor: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    data: &'a [u8],
}

fn align4(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| Error::Malformed {
            message: "archive offset overflow".to_string(),
        })
}

fn parse_hex(field: &[u8], name: &str) -> Result<u32> {
    let text = std::str::from_utf8(field).map_err(|_| Error::Malformed {
        message: format!("{name} is not ASCII"),
    })?;
    u32::from_str_radix(text, 16).map_err(|_| Error::Malformed {
        message: format!("{name} is not hexadecimal"),
    })
}

fn checked_slice<'a>(bytes: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start.checked_add(len).ok_or_else(|| Error::Malformed {
        message: format!("{what} offset overflow"),
    })?;
    bytes.get(start..end).ok_or_else(|| Error::Malformed {
        message: format!("truncated {what}"),
    })
}

fn normalized_path(bytes: &[u8]) -> Result<PathBuf> {
    let raw = PathBuf::from(OsString::from_vec(bytes.to_vec()));
    if raw.is_absolute() {
        return Err(Error::UnsafePath { path: raw });
    }

    let mut normalized = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::UnsafePath { path: raw });
            }
        }
    }
    if normalized.as_os_str().is_empty() && raw != Path::new(".") {
        return Err(Error::UnsafePath { path: raw });
    }
    Ok(normalized)
}

fn parse_newc(bytes: &[u8]) -> Result<Vec<Entry<'_>>> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut offset = 0usize;

    loop {
        let header = checked_slice(bytes, offset, CPIO_HEADER_LEN, "cpio header")?;
        let magic = &header[..6];
        if magic != CPIO_MAGIC_NEWC && magic != CPIO_MAGIC_CRC {
            return Err(Error::Malformed {
                message: format!("invalid magic at offset {offset}"),
            });
        }

        let inode = parse_hex(&header[6..14], "inode")?;
        let mode = parse_hex(&header[14..22], "mode")?;
        let uid = parse_hex(&header[22..30], "uid")?;
        let gid = parse_hex(&header[30..38], "gid")?;
        let nlink = parse_hex(&header[38..46], "link count")?;
        let mtime = parse_hex(&header[46..54], "mtime")?;
        let file_size = parse_hex(&header[54..62], "file size")? as usize;
        let dev_major = parse_hex(&header[62..70], "device major")?;
        let dev_minor = parse_hex(&header[70..78], "device minor")?;
        let name_size = parse_hex(&header[94..102], "name size")? as usize;
        let checksum = parse_hex(&header[102..110], "checksum")?;
        if name_size == 0 {
            return Err(Error::Malformed {
                message: "zero-length entry name".to_string(),
            });
        }

        let name_start = offset + CPIO_HEADER_LEN;
        let name = checked_slice(bytes, name_start, name_size, "entry name")?;
        if name.last() != Some(&0) {
            return Err(Error::Malformed {
                message: "entry name is not NUL-terminated".to_string(),
            });
        }
        let name = &name[..name.len() - 1];
        if name.contains(&0) {
            return Err(Error::Malformed {
                message: "entry name contains an embedded NUL".to_string(),
            });
        }
        let data_start = align4(name_start + name_size)?;
        let data = checked_slice(bytes, data_start, file_size, "entry data")?;
        offset = align4(data_start + file_size)?;
        if name == b"TRAILER!!!" {
            while bytes.get(offset) == Some(&0) {
                offset += 1;
            }
            if offset == bytes.len() {
                return Ok(entries);
            }
            let next = bytes.get(offset..offset + CPIO_MAGIC_NEWC.len());
            if next == Some(CPIO_MAGIC_NEWC) || next == Some(CPIO_MAGIC_CRC) {
                continue;
            }
            return Err(Error::Malformed {
                message: format!("unexpected data after trailer at offset {offset}"),
            });
        }

        let path = normalized_path(name)?;
        if !path.as_os_str().is_empty() && !seen.insert(path.clone()) {
            return Err(Error::DuplicatePath { path });
        }

        if magic == CPIO_MAGIC_CRC {
            let actual = data
                .iter()
                .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
            if actual != checksum {
                return Err(Error::Malformed {
                    message: format!("checksum mismatch for {}", path.display()),
                });
            }
        }
        entries.push(Entry {
            path,
            inode,
            mode,
            nlink,
            dev_major,
            dev_minor,
            uid,
            gid,
            mtime,
            data,
        });
    }
}

pub fn detect_compression(bytes: &[u8]) -> Option<Compression> {
    Compression::signatures()
        .iter()
        .find_map(|(signature, compression)| bytes.starts_with(signature).then_some(*compression))
}

fn read_to_end(mut reader: impl Read, compression: Compression) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .read_to_end(&mut output)
        .map_err(|err| Error::Decompress {
            compression: compression.name(),
            message: err.to_string(),
        })?;
    Ok(output)
}

fn decompress_lz4_legacy(bytes: &[u8]) -> Result<Vec<u8>> {
    const MAGIC_LEN: usize = 4;
    const MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;
    let mut offset = MAGIC_LEN;
    let mut output = Vec::new();
    while offset < bytes.len() {
        let size_bytes = checked_slice(bytes, offset, 4, "legacy lz4 block size")?;
        let block_size =
            u32::from_le_bytes(size_bytes.try_into().expect("four-byte block size")) as usize;
        offset += 4;
        if block_size == 0 {
            break;
        }
        if block_size > MAX_BLOCK_SIZE + 64 * 1024 {
            return Err(Error::Decompress {
                compression: Compression::Lz4Legacy.name(),
                message: format!("implausible block size {block_size}"),
            });
        }
        let block = checked_slice(bytes, offset, block_size, "legacy lz4 block")?;
        offset += block_size;
        let decompressed = lz4_flex::block::decompress(block, MAX_BLOCK_SIZE).map_err(|err| {
            Error::Decompress {
                compression: Compression::Lz4Legacy.name(),
                message: err.to_string(),
            }
        })?;
        output.extend_from_slice(&decompressed);
    }
    Ok(output)
}

#[cfg(test)]
fn compress_lz4_legacy(bytes: &[u8]) -> Result<Vec<u8>> {
    const BLOCK_SIZE: usize = 8 * 1024 * 1024;
    let mut output = vec![0x02, 0x21, 0x4c, 0x18];
    for chunk in bytes.chunks(BLOCK_SIZE) {
        let compressed = lz4_flex::block::compress(chunk);
        let size = u32::try_from(compressed.len()).map_err(|_| Error::Compress {
            compression: Compression::Lz4Legacy.name(),
            message: "compressed block is too large".to_string(),
        })?;
        output.extend_from_slice(&size.to_le_bytes());
        output.extend_from_slice(&compressed);
    }
    Ok(output)
}

pub fn decompress(bytes: &[u8], compression: Compression) -> Result<Vec<u8>> {
    match compression {
        Compression::None => Ok(bytes.to_vec()),
        Compression::Gzip => read_to_end(GzDecoder::new(bytes), compression),
        Compression::Xz => read_to_end(xz2::read::XzDecoder::new(bytes), compression),
        Compression::Lzma => {
            let stream = Stream::new_lzma_decoder(u64::MAX).map_err(|err| Error::Decompress {
                compression: compression.name(),
                message: err.to_string(),
            })?;
            read_to_end(xz2::read::XzDecoder::new_stream(bytes, stream), compression)
        }
        Compression::Bzip2 => read_to_end(BzDecoder::new(bytes), compression),
        Compression::Zstd => zstd::stream::decode_all(bytes).map_err(|err| Error::Decompress {
            compression: compression.name(),
            message: err.to_string(),
        }),
        Compression::Lz4 => read_to_end(FrameDecoder::new(bytes), compression),
        Compression::Lz4Legacy => decompress_lz4_legacy(bytes),
    }
}

#[cfg(test)]
pub fn compress(bytes: &[u8], compression: Compression) -> Result<Vec<u8>> {
    match compression {
        Compression::None => Ok(bytes.to_vec()),
        Compression::Gzip => {
            let mut writer = GzEncoder::new(Vec::new(), GzCompression::best());
            writer.write_all(bytes).map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })?;
            writer.finish().map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })
        }
        Compression::Xz => {
            let mut writer = XzEncoder::new(Vec::new(), 9);
            writer.write_all(bytes).map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })?;
            writer.finish().map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })
        }
        Compression::Lzma => {
            let options = LzmaOptions::new_preset(9).map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })?;
            let stream = Stream::new_lzma_encoder(&options).map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })?;
            let mut writer = XzEncoder::new_stream(Vec::new(), stream);
            writer.write_all(bytes).map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })?;
            writer.finish().map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })
        }
        Compression::Bzip2 => {
            let mut writer = BzEncoder::new(Vec::new(), BzCompression::best());
            writer.write_all(bytes).map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })?;
            writer.finish().map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })
        }
        Compression::Zstd => {
            zstd::stream::encode_all(Cursor::new(bytes), 19).map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })
        }
        Compression::Lz4 => {
            let mut writer = FrameEncoder::new(Vec::new());
            writer.write_all(bytes).map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })?;
            writer.finish().map_err(|err| Error::Compress {
                compression: compression.name(),
                message: err.to_string(),
            })
        }
        Compression::Lz4Legacy => compress_lz4_legacy(bytes),
    }
}

pub fn read_archive(path: &Path) -> Result<(Compression, Vec<u8>)> {
    let bytes = std::fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let compression = detect_compression(&bytes).ok_or(Error::UnknownFormat)?;
    let archive = decompress(&bytes, compression)?;
    if !archive.starts_with(CPIO_MAGIC_NEWC) && !archive.starts_with(CPIO_MAGIC_CRC) {
        return Err(Error::UnknownFormat);
    }
    Ok((compression, archive))
}

pub fn detect_file_compression(path: &Path) -> Result<Compression> {
    let mut file = std::fs::File::open(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut prefix = [0u8; 8];
    let size = file.read(&mut prefix).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    detect_compression(&prefix[..size]).ok_or(Error::UnknownFormat)
}

pub fn inspect(path: &Path) -> Result<Compression> {
    let (compression, archive) = read_archive(path)?;
    parse_newc(&archive)?;
    Ok(compression)
}

fn ensure_no_symlink_ancestors(root: &Path, relative: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            continue;
        };
        current.push(value);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::SymlinkEscape {
                    path: relative.to_path_buf(),
                    symlink: current,
                });
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(Error::Metadata {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

pub fn extract(path: &Path, output_dir: &Path) -> Result<Compression> {
    let (compression, archive) = read_archive(path)?;
    let entries = parse_newc(&archive)?;
    std::fs::create_dir_all(output_dir).map_err(|source| Error::CreateDir {
        path: output_dir.to_path_buf(),
        source,
    })?;

    let mut hardlink_sources = HashMap::<(u32, u32, u32), PathBuf>::new();
    for entry in &entries {
        if entry.mode & S_IFMT == S_IFREG && entry.nlink > 1 {
            let key = (entry.dev_major, entry.dev_minor, entry.inode);
            let source = hardlink_sources
                .entry(key)
                .or_insert_with(|| entry.path.clone());
            if !entry.data.is_empty() {
                *source = entry.path.clone();
            }
        }
    }

    let mut directory_modes = Vec::new();
    let mut deferred_hardlinks = Vec::new();
    for entry in entries {
        if entry.path.as_os_str().is_empty() {
            directory_modes.push((output_dir.to_path_buf(), entry.mode));
            continue;
        }

        ensure_no_symlink_ancestors(output_dir, entry.path.parent().unwrap_or(Path::new("")))?;
        let output = output_dir.join(&entry.path);
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        match entry.mode & S_IFMT {
            S_IFREG => {
                let hardlink_source = (entry.nlink > 1)
                    .then(|| hardlink_sources.get(&(entry.dev_major, entry.dev_minor, entry.inode)))
                    .flatten();
                if let Some(source) =
                    hardlink_source.filter(|source| source.as_path() != entry.path.as_path())
                {
                    deferred_hardlinks.push((output, output_dir.join(source)));
                    continue;
                }
                std::fs::write(&output, &entry.data).map_err(|source| Error::Write {
                    path: output.clone(),
                    source,
                })?;
                std::fs::set_permissions(
                    &output,
                    std::fs::Permissions::from_mode(entry.mode & 0o7777),
                )
                .map_err(|source| Error::Permissions {
                    path: output,
                    source,
                })?;
            }
            S_IFDIR => {
                if !entry.data.is_empty() {
                    return Err(Error::Malformed {
                        message: format!("directory {} contains data", entry.path.display()),
                    });
                }
                std::fs::create_dir_all(&output).map_err(|source| Error::CreateDir {
                    path: output.clone(),
                    source,
                })?;
                directory_modes.push((output, entry.mode));
            }
            S_IFLNK => {
                if entry.data.contains(&0) {
                    return Err(Error::Malformed {
                        message: format!("symlink {} contains a NUL", entry.path.display()),
                    });
                }
                let target = OsString::from_vec(entry.data.to_vec());
                symlink(&target, &output).map_err(|source| Error::Symlink {
                    path: output,
                    source,
                })?;
            }
            S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK => {
                crate::output::warning(format!(
                    "skipping special initramfs entry {}; devtmpfs or init scripts must recreate it",
                    entry.path.display()
                ));
            }
            _ => {
                return Err(Error::UnsupportedEntry {
                    path: entry.path,
                    mode: entry.mode,
                });
            }
        }

        let _ = (entry.uid, entry.gid, entry.mtime);
    }

    for (path, target) in deferred_hardlinks {
        std::fs::hard_link(&target, &path).map_err(|source| Error::HardLink {
            path,
            target,
            source,
        })?;
    }

    for (directory, mode) in directory_modes.into_iter().rev() {
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode & 0o7777))
            .map_err(|source| Error::Permissions {
                path: directory,
                source,
            })?;
    }
    Ok(compression)
}

#[cfg(test)]
fn write_hex(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(format!("{value:08x}").as_bytes());
}

#[cfg(test)]
fn append_padding(output: &mut Vec<u8>, alignment: usize) {
    let target = (output.len() + alignment - 1) & !(alignment - 1);
    output.resize(target, 0);
}

#[cfg(test)]
struct CpioEntry<'a> {
    path: &'a Path,
    metadata: std::fs::Metadata,
    data: Vec<u8>,
}

#[cfg(test)]
fn cpio_entry(path: &Path) -> Result<CpioEntry<'_>> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| Error::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    let data = if metadata.file_type().is_file() {
        std::fs::read(path).map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?
    } else if metadata.file_type().is_symlink() {
        std::fs::read_link(path)
            .map_err(|source| Error::Read {
                path: path.to_path_buf(),
                source,
            })?
            .as_os_str()
            .as_bytes()
            .to_vec()
    } else if metadata.file_type().is_dir() {
        Vec::new()
    } else {
        return Err(Error::UnsupportedEntry {
            path: path.to_path_buf(),
            mode: metadata.mode() as u32,
        });
    };
    Ok(CpioEntry {
        path,
        metadata,
        data,
    })
}

#[cfg(test)]
fn append_entry(
    output: &mut Vec<u8>,
    inode: u32,
    name: &OsStr,
    entry: &CpioEntry<'_>,
) -> Result<()> {
    let file_size = u32::try_from(entry.data.len()).map_err(|_| Error::TooLarge {
        path: entry.path.to_path_buf(),
    })?;
    let name_size = u32::try_from(name.as_bytes().len() + 1).map_err(|_| Error::TooLarge {
        path: entry.path.to_path_buf(),
    })?;

    output.extend_from_slice(CPIO_MAGIC_NEWC);
    for value in [
        inode,
        entry.metadata.mode() as u32,
        entry.metadata.uid(),
        entry.metadata.gid(),
        entry.metadata.nlink() as u32,
        entry.metadata.mtime() as u32,
        file_size,
        0,
        0,
        0,
        0,
        name_size,
        0,
    ] {
        write_hex(output, value);
    }
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    append_padding(output, 4);
    output.extend_from_slice(&entry.data);
    append_padding(output, 4);
    Ok(())
}

#[cfg(test)]
fn collect_paths(root: &Path, relative: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    let directory = root.join(relative);
    let mut children = std::fs::read_dir(&directory)
        .map_err(|source| Error::Read {
            path: directory.clone(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| Error::Read {
            path: directory,
            source,
        })?;
    children.sort_by_key(|entry| entry.file_name().as_bytes().to_vec());

    for child in children {
        let child_relative = relative.join(child.file_name());
        paths.push(child_relative.clone());
        let metadata =
            std::fs::symlink_metadata(child.path()).map_err(|source| Error::Metadata {
                path: child.path(),
                source,
            })?;
        if metadata.file_type().is_dir() {
            collect_paths(root, &child_relative, paths)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn build_newc(root: &Path) -> Result<Vec<u8>> {
    let root_metadata = std::fs::metadata(root).map_err(|source| Error::Metadata {
        path: root.to_path_buf(),
        source,
    })?;
    if !root_metadata.is_dir() {
        return Err(Error::Malformed {
            message: format!("{} is not a directory", root.display()),
        });
    }

    let mut archive = Vec::new();
    let root_entry = cpio_entry(root)?;
    append_entry(
        &mut archive,
        root_entry.metadata.ino() as u32,
        OsStr::new("."),
        &root_entry,
    )?;

    let mut paths = Vec::new();
    collect_paths(root, Path::new(""), &mut paths)?;
    for relative in &paths {
        let full_path = root.join(relative);
        let entry = cpio_entry(&full_path)?;
        append_entry(
            &mut archive,
            entry.metadata.ino() as u32,
            relative.as_os_str(),
            &entry,
        )?;
    }

    let trailer_metadata = root_entry.metadata;
    let trailer = CpioEntry {
        path: root,
        metadata: trailer_metadata,
        data: Vec::new(),
    };
    append_entry(
        &mut archive,
        u32::try_from(paths.len() + 2).unwrap_or(u32::MAX),
        OsStr::new("TRAILER!!!"),
        &trailer,
    )?;
    append_padding(&mut archive, 512);
    Ok(archive)
}

#[cfg(test)]
pub fn pack(root: &Path, output: &Path, compression: Compression) -> Result<()> {
    let archive = build_newc(root)?;
    let bytes = compress(&archive, compression)?;
    std::fs::write(output, bytes).map_err(|source| Error::Write {
        path: output.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> tempfile::TempDir {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("etc/init.d")).expect("create dirs");
        std::fs::write(root.path().join("etc/init.d/rcS"), b"#!/bin/sh\n").expect("write rcS");
        std::fs::set_permissions(
            root.path().join("etc/init.d/rcS"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("chmod rcS");
        symlink("/proc/net/pnp", root.path().join("etc/resolv.conf")).expect("symlink");
        root
    }

    #[test]
    fn round_trips_supported_compressions() {
        for compression in [
            Compression::None,
            Compression::Gzip,
            Compression::Xz,
            Compression::Lzma,
            Compression::Bzip2,
            Compression::Zstd,
            Compression::Lz4,
            Compression::Lz4Legacy,
        ] {
            let source = fixture_root();
            let archive = tempfile::NamedTempFile::new().expect("archive");
            pack(source.path(), archive.path(), compression).expect("pack");
            assert_eq!(inspect(archive.path()).expect("inspect"), compression);

            let output = tempfile::TempDir::new().expect("output");
            extract(archive.path(), output.path()).expect("extract");
            assert_eq!(
                std::fs::read(output.path().join("etc/init.d/rcS")).expect("read rcS"),
                b"#!/bin/sh\n"
            );
            assert_eq!(
                std::fs::metadata(output.path().join("etc/init.d/rcS"))
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
            assert_eq!(
                std::fs::read_link(output.path().join("etc/resolv.conf")).expect("read link"),
                Path::new("/proc/net/pnp")
            );
        }
    }

    #[test]
    fn rejects_parent_traversal() {
        let root = fixture_root();
        let mut archive = build_newc(root.path()).expect("build archive");
        let name_offset = CPIO_HEADER_LEN;
        archive[name_offset..name_offset + 1].copy_from_slice(b".");

        let first_entry_end = align4(CPIO_HEADER_LEN + 2).expect("align");
        let second_name = first_entry_end + CPIO_HEADER_LEN;
        archive[second_name..second_name + 3].copy_from_slice(b"../");

        let err = parse_newc(&archive).expect_err("traversal should fail");
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn rejects_absolute_paths() {
        let root = fixture_root();
        let mut archive = build_newc(root.path()).expect("build archive");
        let name = b"etc\0";
        let offset = archive
            .windows(name.len())
            .position(|window| window == name)
            .expect("etc entry");
        archive[offset..offset + name.len()].copy_from_slice(b"/ab\0");

        let err = parse_newc(&archive).expect_err("absolute path should fail");
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn rejects_truncated_archives() {
        let root = fixture_root();
        let mut archive = build_newc(root.path()).expect("build archive");
        archive.truncate(archive.len() / 2);
        assert!(matches!(parse_newc(&archive), Err(Error::Malformed { .. })));
    }

    #[test]
    fn extracts_concatenated_newc_archives() {
        let first = tempfile::TempDir::new().expect("first root");
        let second = tempfile::TempDir::new().expect("second root");
        std::fs::write(first.path().join("first"), b"one").expect("write first");
        std::fs::write(second.path().join("second"), b"two").expect("write second");
        let mut archive = build_newc(first.path()).expect("build first archive");
        archive.extend(build_newc(second.path()).expect("build second archive"));
        let file = tempfile::NamedTempFile::new().expect("archive");
        std::fs::write(file.path(), archive).expect("write archive");
        let output = tempfile::TempDir::new().expect("output");

        extract(file.path(), output.path()).expect("extract concatenated archive");
        assert_eq!(
            std::fs::read(output.path().join("first")).expect("read first"),
            b"one"
        );
        assert_eq!(
            std::fs::read(output.path().join("second")).expect("read second"),
            b"two"
        );
    }

    #[test]
    fn preserves_hard_links() {
        let root = tempfile::TempDir::new().expect("root");
        std::fs::write(root.path().join("busybox"), b"binary").expect("write busybox");
        std::fs::hard_link(root.path().join("busybox"), root.path().join("sh"))
            .expect("create hard link");
        let archive = tempfile::NamedTempFile::new().expect("archive");
        pack(root.path(), archive.path(), Compression::Gzip).expect("pack");
        let output = tempfile::TempDir::new().expect("output");
        extract(archive.path(), output.path()).expect("extract");

        let busybox = std::fs::metadata(output.path().join("busybox")).expect("busybox metadata");
        let shell = std::fs::metadata(output.path().join("sh")).expect("shell metadata");
        assert_eq!(busybox.ino(), shell.ino());
        assert_eq!(busybox.nlink(), 2);
    }

    #[test]
    fn rejects_entries_beneath_symlinks() {
        let root = tempfile::TempDir::new().expect("tempdir");
        symlink("target", root.path().join("link")).expect("symlink");
        std::fs::create_dir(root.path().join("target")).expect("target");
        std::fs::write(root.path().join("target/file"), b"x").expect("file");

        let archive = tempfile::NamedTempFile::new().expect("archive");
        pack(root.path(), archive.path(), Compression::None).expect("pack");

        let (_, mut bytes) = read_archive(archive.path()).expect("read archive");
        let target = b"target/file\0";
        let replacement = b"link/filexx\0";
        let offset = bytes
            .windows(target.len())
            .position(|window| window == target)
            .expect("entry name");
        bytes[offset..offset + target.len()].copy_from_slice(replacement);

        let output = tempfile::TempDir::new().expect("output");
        let result = parse_newc(&bytes).and_then(|entries| {
            let temp = tempfile::NamedTempFile::new().expect("temp archive");
            std::fs::write(temp.path(), &bytes).expect("write archive");
            drop(entries);
            extract(temp.path(), output.path()).map(|_| ())
        });
        assert!(matches!(result, Err(Error::SymlinkEscape { .. })));
    }
}
