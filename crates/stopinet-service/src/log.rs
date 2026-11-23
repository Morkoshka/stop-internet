//! Event log of the service: a text file in the data folder.
//!
//! It records events (start, stop, tunnel up and down, mode changes,
//! errors), never remote addresses. When the file grows over [`MAX_SIZE`],
//! it is renamed to `service.log.old`, replacing the previous one, so the
//! log never takes more than about twice that size.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use stopinet_win::LocalTime;

/// Size after which the log starts over.
const MAX_SIZE: u64 = 1024 * 1024;

/// Append-only log file. Writing never fails: a service that cannot log
/// must still protect.
#[derive(Debug)]
pub struct Log {
    path: PathBuf,
    file: Option<File>,
    max_size: u64,
}

impl Log {
    /// Opens the log, creating its folder if needed.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self::with_limit(path.into(), MAX_SIZE)
    }

    fn with_limit(path: PathBuf, max_size: u64) -> Self {
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let file = open_append(&path);
        Self {
            path,
            file,
            max_size,
        }
    }

    /// Writes one line with the local time in front.
    pub fn write(&mut self, message: impl fmt::Display) {
        self.rotate_if_full();
        if let Some(file) = &mut self.file {
            let _ = writeln!(file, "{} {message}", LocalTime::now());
        }
    }

    fn rotate_if_full(&mut self) {
        let full = self
            .file
            .as_ref()
            .and_then(|file| file.metadata().ok())
            .is_some_and(|meta| meta.len() >= self.max_size);
        if full {
            self.file = None;
            let _ = fs::rename(&self.path, self.path.with_extension("log.old"));
            self.file = open_append(&self.path);
        }
    }
}

fn open_append(path: &Path) -> Option<File> {
    OpenOptions::new().create(true).append(true).open(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_over_when_full() {
        let dir = std::env::temp_dir().join(format!("stopinet-log-test-{}", std::process::id()));
        let path = dir.join("service.log");
        let _ = fs::remove_dir_all(&dir);

        let mut log = Log::with_limit(path.clone(), 64);
        log.write("first line, long enough to fill the small test log");
        log.write("second line");
        drop(log);

        let current = fs::read_to_string(&path).unwrap();
        let old = fs::read_to_string(dir.join("service.log.old")).unwrap();
        assert!(old.contains("first line"), "{old}");
        assert!(current.contains("second line"), "{current}");
        assert!(!current.contains("first line"), "{current}");

        fs::remove_dir_all(&dir).unwrap();
    }
}
