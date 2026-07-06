use super::heuristics::{
    Confidence, Finding, FindingId, HeuristicAccumulator, MAX_FINDINGS_PER_FILE, Verdict,
};
use super::yara::{MatchedYaraRule, YaraRuleClass, score_matched_rule};
use super::{
    database::HashDatabase,
    hash::{FileHashes, hash_file_from_disk, hash_file_from_memory},
};
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE: u64 = 64 * 1024 * 1024;
const RETAINED_ENTRY_BUFFER_LIMIT: usize = 4 * 1024 * 1024;
// depth 0 = top-level archive
// depth 1 = archive inside archive
// depth 2 = archive inside archive inside archive, rejected
const MAX_ALLOWED_RECURSION: usize = 4;

#[derive(Debug, Default)]
/// The stats from scanning a given file/directory path.
pub struct ScanSummaryStats {
    pub files_scanned: u64,
    pub archives_scanned: u64,
    pub known_hash_detections: u64,
    pub yara_detections: u64,
    pub errors: u64,
    pub files_skipped: u64,
    pub files_skipped_zero_size: u64,
    pub files_skipped_encrypted: u64,
    pub files_scanned_too_large_when_uncompressed: u64,
    pub files_scanned_max_recursion: u64,
    pub skipped_unsupported_archive_entries: u64,
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

/// Enum to represent different types of archive which can be scanned.
enum ArchiveKind {
    Zip,
    Tar,
    Gzip,
    Unknown,
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

/// Function to scan a single file by comparing it known hashes.
fn scan_file_hashes_from_disk(
    path: impl AsRef<Path>,
    hash_database: &HashDatabase,
) -> Result<HashScanResult, String> {
    let hashes = match hash_file_from_disk(path) {
        Err(_) => return Err("Unable to compare hash".to_string()),
        Ok(hashes) => hashes,
    };
    compare_hashes(hashes, hash_database)
}

/// Function to scan a single file by comparing it known hashes.
fn scan_file_hashes_from_memory(
    buffer: &[u8],
    hash_database: &HashDatabase,
) -> Result<HashScanResult, String> {
    let hashes = match hash_file_from_memory(buffer) {
        Err(_) => return Err("Unable to compare hash".to_string()),
        Ok(hashes) => hashes,
    };
    compare_hashes(hashes, hash_database)
}

/// Function to compare a set of file hashes to hashes in a database.
fn compare_hashes(
    hashes: FileHashes,
    hash_database: &HashDatabase,
) -> Result<HashScanResult, String> {
    if hash_database.contains(&hashes) {
        return Ok(HashScanResult::KnownHash { family: None });
    };
    Ok(HashScanResult::Clean)
}

/// Function to scan a single file on disk by running YARA rules against it.
fn scan_file_yara_from_disk(
    path: &Path,
    scanner: &mut yara_x::Scanner,
) -> Result<YaraScanResult, String> {
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

/// Function to scan a single file in memory by running YARA rules against it.
fn scan_file_yara_from_memory(
    buffer: &[u8],
    scanner: &mut yara_x::Scanner,
) -> Result<YaraScanResult, String> {
    let results = match scanner.scan(buffer) {
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
    let hash_result = match scan_file_hashes_from_disk(path, hash_database) {
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

    // Run heavier rules scan
    if metadata.len() > 32 {
        // Check if we're attempting to scan an archive.
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(err) => {
                summary.errors += 1;
                eprintln!("Could not scan {}: {}", path.display(), err);
                return;
            }
        };

        // ZIP needs 4 bytes.
        // GZIP needs 2 bytes.
        // TAR detection usually needs 512 bytes.
        let mut buffer = [0_u8; 512];
        let bytes_read = match file.read(&mut buffer) {
            Ok(bytes) => bytes,
            Err(err) => {
                summary.errors += 1;
                eprintln!("Could not scan {}: {}", path.display(), err);
                return;
            }
        };

        let sample = &buffer[..bytes_read];

        let archive_kind = match detect_archive_kind(sample) {
            Ok(kind) => kind,
            Err(err) => {
                summary.errors += 1;
                eprintln!(
                    "Could not determine if {} is an archive: {}",
                    path.display(),
                    err
                );
                return; // Maybe we shouldn't do this and continue anyway?
            }
        };

        // Important: the probe read advanced the file cursor.
        // Archive readers must start from byte 0.
        if let Err(err) = file.seek(SeekFrom::Start(0)) {
            summary.errors += 1;
            eprintln!(
                "Could not rewind {} after archive probe: {}",
                path.display(),
                err
            );
            return;
        }

        if let Err(err) = match archive_kind {
            ArchiveKind::Unknown => Ok(()),
            ArchiveKind::Gzip => {
                scan_gzip_reader(file, path, hash_database, yara_scanner, summary, 0)
            }

            ArchiveKind::Tar => {
                scan_tar_archive(file, path, hash_database, yara_scanner, summary, 0)
            }

            ArchiveKind::Zip => {
                scan_zip_archive(file, path, hash_database, yara_scanner, summary, 0)
            }
        } {
            summary.errors += 1;
            eprintln!("Could not scan archive {}: {}", path.display(), err);
        };

        // If it's not an archive, check the YARA rules.
        let yara_result = match scan_file_yara_from_disk(path, yara_scanner) {
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
                        _ => FindingId::SingleYaraRule,
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

/// Function to detect the type of archive a file is.
fn detect_archive_kind(buffer: &[u8]) -> Result<ArchiveKind, std::io::Error> {
    if is_zip(buffer) {
        return Ok(ArchiveKind::Zip);
    }

    if is_gzip(buffer) {
        return Ok(ArchiveKind::Gzip);
    }

    if is_tar(buffer) {
        return Ok(ArchiveKind::Tar);
    }

    Ok(ArchiveKind::Unknown)
}

/// Function to check if a set of magic bytes looks like a zip file.
fn is_zip(buffer: &[u8]) -> bool {
    buffer.starts_with(b"PK\x03\x04")
        || buffer.starts_with(b"PK\x05\x06")
        || buffer.starts_with(b"PK\x07\x08")
}

/// Function to check if a set of magic bytes looks like a gzip file.
fn is_gzip(buffer: &[u8]) -> bool {
    buffer.starts_with(&[0x1f, 0x8b])
}

/// Function to check if a set of magic bytes looks like a tar file.
fn is_tar(buffer: &[u8]) -> bool {
    if buffer.len() < 512 {
        return false;
    }

    let magic = &buffer[257..263];

    magic == b"ustar\0" || magic == b"ustar "
}

/// Function to create safe(ish) virtual paths for archived files.
fn make_archive_path(archive_path: &Path, entry_path: &Path) -> PathBuf {
    let mut display = archive_path.to_string_lossy().to_string();
    display.push_str("!/");
    display.push_str(&entry_path.to_string_lossy());
    PathBuf::from(display)
}

/// Function to read a limited number of bytes from a reader into a buffer.
fn read_limited_into<R: Read>(
    reader: &mut R,
    output: &mut Vec<u8>,
    max_bytes: u64,
) -> Result<(), std::io::Error> {
    output.clear();

    let mut limited = reader.take(max_bytes + 1);
    limited.read_to_end(output)?;

    // If we read a file which is too big, clear the buffer as it's not valid.
    if output.len() as u64 > max_bytes {
        output.clear();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "archive entry exceeded memory limit",
        ));
    }

    Ok(())
}

/// Function to scan a file held in memory, and not on disk.
fn scan_bytes(
    virtual_path: &Path,
    bytes: &[u8],
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
    depth: usize,
) -> Result<(), String> {
    let mut heuristics = HeuristicAccumulator::new();

    // Skip files with a length of 0.
    if bytes.is_empty() {
        summary.files_skipped += 1;
        summary.files_skipped_zero_size += 1;
        return Ok(());
    }

    // Compare the hash of the file to known SHA256 signatures.
    let hash_result = match scan_file_hashes_from_memory(bytes, hash_database) {
        Ok(result) => result,
        Err(err) => {
            summary.errors += 1;
            eprintln!("Could not scan {}: {}", virtual_path.display(), err);
            return Err(err);
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

    // Run heavier rules scan
    if bytes.len() > 32 {
        // Check if we're attempting to scan an archive.
        let archive_kind = match detect_archive_kind(bytes) {
            Ok(kind) => kind,
            Err(err) => {
                summary.errors += 1;
                eprintln!(
                    "Could not determine if {} is an archive: {}",
                    virtual_path.display(),
                    err
                );
                return Err(err.to_string());
            }
        };

        match archive_kind {
            ArchiveKind::Unknown => {}

            ArchiveKind::Zip => {
                let cursor = Cursor::new(bytes);

                if let Err(err) = scan_zip_archive(
                    cursor,
                    virtual_path,
                    hash_database,
                    yara_scanner,
                    summary,
                    depth,
                ) {
                    summary.errors += 1;
                    eprintln!(
                        "Could not scan zip archive {}: {}",
                        virtual_path.display(),
                        err
                    );
                }
            }

            ArchiveKind::Tar => {
                let cursor = Cursor::new(bytes);

                if let Err(err) = scan_tar_archive(
                    cursor,
                    virtual_path,
                    hash_database,
                    yara_scanner,
                    summary,
                    depth,
                ) {
                    summary.errors += 1;
                    eprintln!(
                        "Could not scan tar archive {}: {}",
                        virtual_path.display(),
                        err
                    );
                }
            }

            ArchiveKind::Gzip => {
                let cursor = Cursor::new(bytes);

                if let Err(err) = scan_gzip_reader(
                    cursor,
                    virtual_path,
                    hash_database,
                    yara_scanner,
                    summary,
                    depth,
                ) {
                    summary.errors += 1;
                    eprintln!(
                        "Could not scan gzip archive {}: {}",
                        virtual_path.display(),
                        err
                    );
                }
            }
        }

        // Compare the file to YARA rules.
        let yara_result = match scan_file_yara_from_memory(bytes, yara_scanner) {
            Ok(result) => result,
            Err(err) => {
                summary.errors += 1;
                eprintln!("Could not scan {}: {}", virtual_path.display(), err);
                return Err(err);
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
                        _ => FindingId::SingleYaraRule,
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
                path: virtual_path.into(),
                score: heuristics.score(),
                verdict,
                findings: heuristics.findings(),
            });
        }
    };

    Ok(())
}

/// Function to scan a zip archive.
fn scan_zip_archive<R>(
    reader: R,
    archive_path: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
    depth: usize,
) -> Result<(), String>
where
    R: Read + std::io::Seek,
{
    if depth >= MAX_ALLOWED_RECURSION {
        summary.files_skipped += 1;
        summary.files_scanned_max_recursion += 1;
        eprintln!(
            "Skipped archive: maximum recursion reached: {}",
            archive_path.display()
        );
        return Ok(());
    }

    summary.archives_scanned += 1;

    let mut archive = zip::ZipArchive::new(reader).map_err(|err| err.to_string())?;
    let mut entry_buffer = Vec::new();

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(entry) => entry,
            Err(err) => {
                summary.errors += 1;
                eprintln!(
                    "Could not read zip entry in {}: {}",
                    archive_path.display(),
                    err
                );
                continue;
            }
        };

        if entry.is_dir() {
            continue;
        }

        if entry.encrypted() {
            summary.files_skipped += 1;
            summary.files_skipped_encrypted += 1;
            continue;
        }

        let entry_size = entry.size();

        if entry_size > MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE {
            summary.files_skipped += 1;
            summary.files_scanned_too_large_when_uncompressed += 1;
            continue;
        }

        entry_buffer.reserve(entry_size as usize);

        if let Err(err) = read_limited_into(
            &mut entry,
            &mut entry_buffer,
            MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE,
        ) {
            summary.files_skipped += 1;
            summary.files_scanned_too_large_when_uncompressed += 1;
            eprintln!(
                "Skipped zip entry: {}!/{} ({})",
                archive_path.display(),
                entry.name(),
                err
            );
            continue;
        }

        let virtual_path = make_archive_path(archive_path, Path::new(entry.name()));

        let _ = scan_bytes(
            &virtual_path,
            &entry_buffer,
            hash_database,
            yara_scanner,
            summary,
            depth + 1,
        );

        if entry_buffer.capacity() > RETAINED_ENTRY_BUFFER_LIMIT {
            entry_buffer = Vec::new();
        } else {
            entry_buffer.clear();
        }
    }

    Ok(())
}

/// Function to scan a tar archive.
fn scan_tar_archive<R>(
    reader: R,
    archive_path: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
    depth: usize,
) -> Result<(), String>
where
    R: Read,
{
    if depth >= MAX_ALLOWED_RECURSION {
        summary.files_skipped += 1;
        summary.files_scanned_max_recursion += 1;
        eprintln!(
            "Skipped archive: maximum recursion reached: {}",
            archive_path.display()
        );
        return Ok(());
    }

    summary.archives_scanned += 1;

    let mut archive = tar::Archive::new(reader);

    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(err) => {
            summary.errors += 1;
            eprintln!(
                "Could not read tar entries in {}: {}",
                archive_path.display(),
                err
            );
            return Ok(());
        }
    };

    let mut entry_buffer = Vec::new();

    for entry_result in entries {
        let mut entry = match entry_result {
            Ok(entry) => entry,
            Err(err) => {
                summary.errors += 1;
                eprintln!(
                    "Could not read tar entry in {}: {}",
                    archive_path.display(),
                    err
                );
                continue;
            }
        };

        let header = entry.header();

        if !header.entry_type().is_file() {
            summary.skipped_unsupported_archive_entries += 1;
            continue;
        }

        let entry_size = header.size().unwrap_or(0);

        if entry_size > MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE {
            summary.files_skipped += 1;
            summary.files_scanned_too_large_when_uncompressed += 1;
            continue;
        }

        let entry_path = match entry.path() {
            Ok(path) => path.into_owned(),
            Err(err) => {
                summary.errors += 1;
                eprintln!(
                    "Could not read tar entry path in {}: {}",
                    archive_path.display(),
                    err
                );
                continue;
            }
        };

        if let Err(err) = read_limited_into(
            &mut entry,
            &mut entry_buffer,
            MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE,
        ) {
            summary.files_skipped += 1;
            summary.files_scanned_too_large_when_uncompressed += 1;
            eprintln!(
                "Skipped tar entry: {}!/{} ({})",
                archive_path.display(),
                entry_path.display(),
                err
            );
            continue;
        }

        let virtual_path = make_archive_path(archive_path, &entry_path);

        let _ = scan_bytes(
            &virtual_path,
            &entry_buffer,
            hash_database,
            yara_scanner,
            summary,
            depth + 1,
        );

        if entry_buffer.capacity() > RETAINED_ENTRY_BUFFER_LIMIT {
            entry_buffer = Vec::new();
        } else {
            entry_buffer.clear();
        }
    }

    Ok(())
}

/// Function to read gzip compressed files.
fn scan_gzip_reader<R>(
    reader: R,
    archive_path: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
    depth: usize,
) -> Result<(), String>
where
    R: Read,
{
    if depth >= MAX_ALLOWED_RECURSION {
        summary.files_skipped += 1;
        summary.files_scanned_max_recursion += 1;
        eprintln!(
            "Skipped archive: maximum recursion reached: {}",
            archive_path.display()
        );
        return Ok(());
    }

    summary.archives_scanned += 1;

    let decompressed = match decompress_gzip_limited(reader, MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE) {
        Ok(bytes) => bytes,
        Err(err) if err.contains("size limit exceeded") => {
            summary.files_skipped += 1;
            summary.files_scanned_too_large_when_uncompressed += 1;
            eprintln!(
                "Skipped gzip archive: decompression limit reached: {} ({})",
                archive_path.display(),
                err
            );
            return Ok(());
        }

        Err(err) => {
            summary.errors += 1;
            eprintln!(
                "Could not decompress gzip archive: {} ({})",
                archive_path.display(),
                err
            );
            return Ok(());
        }
    };

    if decompressed.is_empty() {
        summary.files_skipped += 1;
        summary.files_skipped_zero_size += 1;
        return Ok(());
    }

    let inner_path = gzip_inner_virtual_path(archive_path);

    scan_bytes(
        &inner_path,
        &decompressed,
        hash_database,
        yara_scanner,
        summary,
        depth + 1,
    )
}

/// Helper function to decompress a gzip archive into a limited buffer.
fn decompress_gzip_limited<R: Read>(
    reader: R,
    max_decompressed_size: u64,
) -> Result<Vec<u8>, String> {
    let mut decoder = flate2::read::GzDecoder::new(reader);

    let mut limited_reader = decoder.by_ref().take(max_decompressed_size + 1);
    let mut decompressed = Vec::new();

    limited_reader
        .read_to_end(&mut decompressed)
        .map_err(|err| err.to_string())?;

    if decompressed.len() as u64 > max_decompressed_size {
        return Err("gzip decompressed size limit exceeded".to_string());
    }

    Ok(decompressed)
}

/// Helper function to get the virtual path inside of a gzip archive.
fn gzip_inner_virtual_path(path: &Path) -> std::path::PathBuf {
    let display = path.to_string_lossy();

    let inner_name = if display.ends_with(".tar.gz") {
        display.trim_end_matches(".gz").to_string()
    } else if display.ends_with(".tgz") {
        display.trim_end_matches(".tgz").to_string() + ".tar"
    } else if display.ends_with(".gz") {
        display.trim_end_matches(".gz").to_string()
    } else {
        "<decompressed>".to_string()
    };

    std::path::PathBuf::from(format!("{}!/{}", display, inner_name))
}
