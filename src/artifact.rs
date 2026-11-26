use std::fs::{self, File, Metadata, Permissions};
use std::io::{self, ErrorKind, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::NamedTempFile;

pub fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

pub fn existing(path: &Path) -> io::Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn regular_file(path: &Path) -> io::Result<Metadata> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        Ok(metadata)
    } else {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            "expected a regular file",
        ))
    }
}

/// Stage an artifact in its destination directory so publication is atomic.
pub fn stage(path: &Path) -> io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o666))
        .tempfile_in(parent(path))
}

pub fn stage_replacement(
    path: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<NamedTempFile> {
    let metadata = existing(path)?;
    if metadata
        .as_ref()
        .is_some_and(|metadata| !metadata.is_file() && !metadata.is_symlink())
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "expected an output file or symlink",
        ));
    }
    let mut temporary = stage(path)?;
    write(temporary.as_file_mut())?;
    temporary.flush()?;
    if let Some(metadata) = metadata.filter(Metadata::is_file) {
        temporary.as_file().set_permissions(Permissions::from_mode(
            metadata.permissions().mode() & 0o777,
        ))?;
    }
    Ok(temporary)
}

pub fn replace(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    stage_replacement(path, write)?
        .persist(path)
        .map_err(|err| err.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_write_preserves_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        fs::write(&path, b"original").unwrap();
        let error = replace(&path, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("write interrupted"))
        });
        assert!(error.is_err());
        assert_eq!(fs::read(path).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn replacement_does_not_write_through_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        let path = dir.path().join("artifact");
        fs::write(&original, b"original").unwrap();
        std::os::unix::fs::symlink(&original, &path).unwrap();
        replace(&path, |file| file.write_all(b"replacement")).unwrap();
        assert_eq!(fs::read(original).unwrap(), b"original");
        assert_eq!(fs::read(path).unwrap(), b"replacement");
    }
}
