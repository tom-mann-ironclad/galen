use super::heuristics::{
    Confidence, Finding, FindingId, HeuristicAccumulator, MAX_FINDINGS_PER_FILE, Verdict,
};
use super::yara::{MatchedYaraRule, YaraRuleClass, score_matched_rule};
use super::{database::HashDatabase, hash::hash_file};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
/// The stats from scanning a given file/directory path.
pub struct ScanSummaryStats {
    pub files_scanned: u64,
    pub known_hash_detections: u64,
    pub yara_detections: u64,
    pub errors: u64,
    pub files_skipped: u64,
    pub files_skipped_zero_size: u64,
    pub yara_rules_triggered: HashMap<String, u64>,
    pub detections: Vec<DetectionRecord>,
}

impl ScanSummaryStats {
    /// Function to create a new instance of `ScanSummaryStats`.
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub struct DetectionRecord {
    pub path: PathBuf,
    pub score: u16,
    pub verdict: Verdict,
    pub findings: [Option<Finding>; MAX_FINDINGS_PER_FILE],
}

/// The result of scanning a single file to compare it's hash.
#[derive(Debug)]
enum HashScanResult {
    Clean,
    KnownHash { family: Option<String> },
}

/// The result of scanning a single file against YARA rules.
#[derive(Debug)]
enum YaraScanResult {
    Clean,
    YaraRules { rules: Vec<MatchedYaraRule> },
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
) -> Result<HashScanResult, String> {
    let hashes = match hash_file(path) {
        Err(_) => return Err("Unable to compare hash".to_string()),
        Ok(hashes) => hashes,
    };
    if hash_database.contains(&hashes) {
        return Ok(HashScanResult::KnownHash { family: None });
    };
    Ok(HashScanResult::Clean)
}

fn scan_file_yara(path: &Path, scanner: &mut yara_x::Scanner) -> Result<YaraScanResult, String> {
    let results = match scanner.scan_file(path) {
        Ok(results) => results,
        Err(err) => return Err(err.to_string()),
    };

    // Guard to catch clean scans without allocating.
    if results.matching_rules().len() == 0 {
        return Ok(YaraScanResult::Clean);
    }

    let mut matched_rules = Vec::new();
    
    for rule in results.matching_rules() {
        matched_rules.push(MatchedYaraRule::from_yara_rule(rule));
    }

    Ok(YaraScanResult::YaraRules {
        rules: matched_rules,
    })
}

/// Function to scan a file and report the results by modifying the provided summary.
fn scan_one_and_report(
    path: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
) {
    let mut heuristics = HeuristicAccumulator::new();
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

    // Hash the file and compare
    let hash_result = match scan_file_hashes(path, hash_database) {
        Ok(result) => result,
        Err(err) => {
            summary.errors += 1;
            eprintln!("Could not scan {}: {}", path.display(), err);
            return;
        }
    };

    match hash_result {
        HashScanResult::Clean => {}
        HashScanResult::KnownHash { family: _ } => {
            summary.known_hash_detections += 1;
            heuristics.add(Finding {
                id: FindingId::KnownHash,
                score: 100,
                confidence: Confidence::High,
            });
        }
    }

    // Run YARA rules scan
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
            YaraScanResult::Clean => {}
            YaraScanResult::YaraRules { rules } => {
                summary.yara_detections += 1;
                for rule in rules {
                    *summary.yara_rules_triggered.entry(rule.name).or_insert(0) += 1;
                    let (score, confidence) = score_matched_rule(&rule.class, &rule.strength);
                    let finding = match &rule.class {
                        YaraRuleClass::Persistence => FindingId::YaraPersistenceIndicator,
                        YaraRuleClass::PackerOrObfuscation => FindingId::YaraPackerIndicator,
                        YaraRuleClass::WebShell => FindingId::YaraRootkitIndicator,
                        _ => FindingId::SingleYaraRule
                    };
                    heuristics.add(Finding {
                        id: finding,
                        score,
                        confidence,
                    });

                }
            }
        }
    }

    // Summarise scan and report
    summary.files_scanned += 1;
    let verdict = heuristics.verdict();
    match verdict {
        Verdict::Clean => {}
        _ => {
            summary.detections.push(DetectionRecord {
                path: path.to_path_buf(),
                score: heuristics.score(),
                verdict,
                findings: heuristics.findings(),
            });
        }
    };
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
