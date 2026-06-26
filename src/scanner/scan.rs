use super::{database::HashDatabase, hash::hash_file};
use std::path::Path;

#[derive(Debug, Default)]
/// The stats from scanning a given file/directory path.
pub struct ScanSummaryStats {
    pub files_scanned: u64,
    pub threats_detected: u64,
    pub errors: u64,
}

impl ScanSummaryStats {
    /// Function to create a new instance of `ScanSummaryStats`.
    pub fn new() -> Self {
        Self::default()
    }
}

/// The result of scanning a single file.
#[derive(Debug)]
enum ScanResult {
    Clean,
    KnownHash { family: Option<String> },
}

pub fn scan_path(path: &Path, hash_database: &HashDatabase) -> ScanSummaryStats {
    let mut summary = ScanSummaryStats::new();

    if path.is_file() {
        scan_one_and_report(path, hash_database, &mut summary);
    } else if path.is_dir() {
        scan_directory(path, hash_database, &mut summary);
    } else {
        eprintln!("Skipping non-file target: {:?}", path);
        summary.errors += 1;
    }

    summary
}

/// Function to scan a single file and compare it known hashes.
fn scan_file(path: impl AsRef<Path>, hash_database: &HashDatabase) -> Result<ScanResult, String> {
    let hashes = match hash_file(path) {
        Err(_) => return Err("Unable to compare hash".to_string()),
        Ok(hashes) => hashes,
    };
    if hash_database.contains(&hashes) {
        return Ok(ScanResult::KnownHash { family: None });
    };
    Ok(ScanResult::Clean)
}

/// Function to scan a file and report the results by modifying the provided summary.
fn scan_one_and_report(path: &Path, hash_database: &HashDatabase, summary: &mut ScanSummaryStats) {
    match scan_file(path, hash_database) {
        Ok(ScanResult::Clean) => {
            summary.files_scanned += 1;
        }

        Ok(ScanResult::KnownHash { family }) => {
            summary.files_scanned += 1;
            summary.threats_detected += 1;

            match family {
                Some(family) => println!("THREAT DETECTED: known hash ({})", family),
                None => println!("THREAT DETECTED: known hash (unknown family)"),
            }

            println!("  {:?}", path.display());
        }

        Err(err) => {
            summary.errors += 1;
            eprintln!("Could not scan {:?}: {}", path.display(), err);
        }
    }
}

/// Function to scan a provided directory and update the provided summary.
fn scan_directory(directory: &Path, hash_database: &HashDatabase, summary: &mut ScanSummaryStats) {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(err) => {
            summary.errors += 1;
            eprintln!(
                "Could not read directory {:?}: {}",
                directory.display(),
                err
            );
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                summary.errors += 1;
                eprintln!(
                    "Could not read directory entry in {:?}: {}",
                    directory.display(),
                    err
                );
                return;
            }
        };

        let path = entry.path();

        if path.is_dir() {
            scan_directory(&path, hash_database, summary);
        } else if path.is_file() {
            scan_one_and_report(&path, hash_database, summary);
        } else {
            // ignore symlinks, etc. for now
            continue;
        }
    }
}
