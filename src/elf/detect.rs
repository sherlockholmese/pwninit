use std::io::Read;
use std::path::{Path, PathBuf};

use snafu::ResultExt;
use snafu::Snafu;
use std::fs::{self, File};
use std::io;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed inspecting {} for an ELF header: {}", path.display(), source))]
    Inspect { path: PathBuf, source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Is the binary at `path` an ELF?
pub fn is_elf(path: &Path) -> Result<bool> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound && path.is_symlink() => return Ok(false),
        Err(source) => {
            return Err(Error::Inspect {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    if !metadata.is_file() {
        return Ok(false);
    }
    let mut file = File::open(path).context(InspectSnafu { path })?;
    let mut magic = [0; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == *b"\x7fELF"),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(source) => Err(Error::Inspect {
            path: path.to_path_buf(),
            source,
        }),
    }
}
