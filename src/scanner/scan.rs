use super::{database::HashDatabase, hash::hash_file};
use std::path::Path;

#[derive(Debug, Default)]
/// The stats from scanning a given file/directory path.
pub struct ScanSummaryStats {
    pub files_scanned: u64,
    pub threats_detected: u64,
    pub errors: u64,
    pub files_skipped: u64,
    pub files_skipped_zero_size: u64,
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
    ThreatDetected { detection_type: DetectionType },
}

/// The type of detection made.
#[derive(Debug)]
enum DetectionType {
    KnownHash { family: Option<String> },
    YaraRule { rule: String },
}

pub fn scan_path(
    path: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
) -> ScanSummaryStats {
    let mut summary = ScanSummaryStats::new();

    if path.is_file() {
        scan_one_and_report(path, hash_database, yara_scanner, &mut summary);
    } else if path.is_dir() {
        scan_directory(path, hash_database, yara_scanner, &mut summary);
    } else {
        eprintln!("Skipping non-file target: {:?}", path);
        summary.errors += 1;
    }

    summary
}

/// Function to scan a single file and compare it known hashes.
fn scan_file_hashes(
    path: impl AsRef<Path>,
    hash_database: &HashDatabase,
) -> Result<ScanResult, String> {
    let hashes = match hash_file(path) {
        Err(_) => return Err("Unable to compare hash".to_string()),
        Ok(hashes) => hashes,
    };
    if hash_database.contains(&hashes) {
        return Ok(ScanResult::ThreatDetected {
            detection_type: DetectionType::KnownHash { family: None },
        });
    };
    Ok(ScanResult::Clean)
}

fn scan_file_yara(path: &Path, scanner: &mut yara_x::Scanner) -> Result<ScanResult, String> {
    let results = match scanner.scan_file(path) {
        Ok(results) => results,
        Err(err) => return Err(err.to_string()),
    };
    if let Some(matched_rule) = results.matching_rules().next() {
        return Ok(ScanResult::ThreatDetected {
            detection_type: DetectionType::YaraRule {
                rule: matched_rule.identifier().to_string(),
            },
        });
    }

    Ok(ScanResult::Clean)
}

/// Function to scan a file and report the results by modifying the provided summary.
fn scan_one_and_report(
    path: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
) {
    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(err) => {
            summary.errors += 1;
            eprintln!("Unable to read metadata for {}: {}", path.display(), err);
            return;
        }
    };

    // Guard to avoid scanning 0-length files
    if metadata.len() == 0 {
        summary.files_skipped += 1;
        summary.files_skipped_zero_size += 1;
        return;
    }

    let hash_result = match scan_file_hashes(path, hash_database) {
        Ok(result) => result,
        Err(err) => {
            summary.errors += 1;
            eprintln!("Could not scan {}: {}", path.display(), err);
            return;
        }
    };

    match hash_result {
        ScanResult::ThreatDetected { detection_type } => {
            handle_threat_detected(detection_type, path, summary);
        }

        ScanResult::Clean => {
            if metadata.len() > 32 {
                let yara_result = match scan_file_yara(path, yara_scanner) {
                    Ok(result) => result,
                    Err(err) => {
                        summary.errors += 1;
                        eprintln!("Could not scan {}: {}", path.display(), err);
                        return;
                    }
                };

                match yara_result {
                    ScanResult::Clean => {
                        summary.files_scanned += 1;
                    }
                    ScanResult::ThreatDetected { detection_type } => {
                        handle_threat_detected(detection_type, path, summary);
                    }
                }
            } else {
                summary.files_scanned += 1;
            }
        }
    }
}

fn handle_threat_detected(
    detection_type: DetectionType,
    path: &Path,
    summary: &mut ScanSummaryStats,
) {
    summary.files_scanned += 1;
    summary.threats_detected += 1;

    match detection_type {
        DetectionType::KnownHash { family } => {
            let family_name = match family {
                Some(name) => name,
                None => "unknown family".to_string(),
            };
            // println!("THREAT DETECTED: known hash ({})", family_name)
        }
        DetectionType::YaraRule { rule } => {
            // println!("THREAT DETECTED: YARA rule match ({})", rule)
        }
    }

    // println!("  {:?}", path.display());
}

/// Function to scan a provided directory and update the provided summary.
fn scan_directory(
    directory: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
) {
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
            scan_directory(&path, hash_database, yara_scanner, summary);
        } else if path.is_file() {
            scan_one_and_report(&path, hash_database, yara_scanner, summary);
        } else {
            // ignore symlinks, etc. for now
            continue;
        }
    }
}
