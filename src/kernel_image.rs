use std::io::Read;
use std::path::{Path, PathBuf};

use goblin::elf::header::EM_X86_64;
use goblin::Object;
use snafu::Snafu;

use crate::kernel_initramfs::{self, Compression};

const BOOT_FLAG_OFFSET: usize = 0x1fe;
const SETUP_MAGIC_OFFSET: usize = 0x202;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed reading kernel image {}: {}", path.display(), source))]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed writing extracted kernel {}: {}", path.display(), source))]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("{} is not an x86-64 Linux kernel image or bzImage", path.display()))]
    InvalidImage { path: PathBuf },

    #[snafu(display("could not find an embedded x86-64 vmlinux in {}", path.display()))]
    VmlinuxNotFound { path: PathBuf },
}

pub type Result<T> = std::result::Result<T, Error>;

fn is_x86_64_elf(bytes: &[u8]) -> bool {
    matches!(
        Object::parse(bytes),
        Ok(Object::Elf(elf)) if elf.header.e_machine == EM_X86_64
    )
}

fn is_x86_64_elf_header(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
        && bytes.get(4) == Some(&2)
        && bytes.get(5) == Some(&1)
        && bytes.get(18..20) == Some(&EM_X86_64.to_le_bytes())
}

pub fn is_bzimage(bytes: &[u8]) -> bool {
    bytes.get(BOOT_FLAG_OFFSET..BOOT_FLAG_OFFSET + 2) == Some(&[0x55, 0xaa])
        && bytes.get(SETUP_MAGIC_OFFSET..SETUP_MAGIC_OFFSET + 4) == Some(b"HdrS")
}

pub fn is_kernel_image(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut prefix = vec![0; SETUP_MAGIC_OFFSET + 4];
    let Ok(size) = file.read(&mut prefix) else {
        return false;
    };
    prefix.truncate(size);
    is_bzimage(&prefix) || is_x86_64_elf_header(&prefix)
}

pub fn extract_vmlinux_bytes(image: &[u8]) -> Option<Vec<u8>> {
    if is_x86_64_elf(image) {
        return Some(image.to_vec());
    }

    for (signature, compression) in Compression::signatures()
        .iter()
        .filter(|(_, compression)| *compression != Compression::None)
    {
        for (offset, window) in image.windows(signature.len()).enumerate() {
            if window != *signature {
                continue;
            }
            if let Ok(candidate) = kernel_initramfs::decompress(&image[offset..], *compression) {
                if is_x86_64_elf(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

pub fn inspect(path: &Path) -> Result<()> {
    let mut file = std::fs::File::open(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut prefix = vec![0; SETUP_MAGIC_OFFSET + 4];
    let size = file.read(&mut prefix).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    prefix.truncate(size);
    if is_bzimage(&prefix) || is_x86_64_elf_header(&prefix) {
        Ok(())
    } else {
        Err(Error::InvalidImage {
            path: path.to_path_buf(),
        })
    }
}

pub fn extract_vmlinux(path: &Path, output: &Path) -> Result<()> {
    let image = std::fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !is_bzimage(&image) && !is_x86_64_elf_header(&image) {
        return Err(Error::InvalidImage {
            path: path.to_path_buf(),
        });
    }
    let vmlinux = extract_vmlinux_bytes(&image).ok_or_else(|| Error::VmlinuxNotFound {
        path: path.to_path_buf(),
    })?;
    std::fs::write(output, vmlinux).map_err(|source| Error::Write {
        path: output.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::GzEncoder;
    use flate2::Compression as GzCompression;

    use super::*;

    #[test]
    fn recognizes_bzimage_header() {
        let mut image = vec![0; 0x300];
        image[BOOT_FLAG_OFFSET..BOOT_FLAG_OFFSET + 2].copy_from_slice(&[0x55, 0xaa]);
        image[SETUP_MAGIC_OFFSET..SETUP_MAGIC_OFFSET + 4].copy_from_slice(b"HdrS");
        assert!(is_bzimage(&image));
    }

    #[test]
    fn extracts_gzip_vmlinux_from_bzimage() {
        let elf = std::fs::read("/bin/true").expect("read x86-64 ELF fixture");
        assert!(is_x86_64_elf(&elf));

        let mut encoder = GzEncoder::new(Vec::new(), GzCompression::default());
        encoder.write_all(&elf).expect("compress elf");
        let compressed = encoder.finish().expect("finish gzip");

        let mut image = vec![0; 0x300];
        image[BOOT_FLAG_OFFSET..BOOT_FLAG_OFFSET + 2].copy_from_slice(&[0x55, 0xaa]);
        image[SETUP_MAGIC_OFFSET..SETUP_MAGIC_OFFSET + 4].copy_from_slice(b"HdrS");
        image.extend_from_slice(&compressed);

        assert_eq!(extract_vmlinux_bytes(&image), Some(elf));
    }
}
