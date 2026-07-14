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
use std::path::{Component, Path, PathBuf};

const MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE: u64 = 64 * 1024 * 1024;
const RETAINED_ENTRY_BUFFER_LIMIT: usize = 4 * 1024 * 1024;
const MAX_ALLOWED_RECURSION: usize = 5;
const MAX_ALLOWED_ARCHIVE_ENTRIES: usize = 10000;

#[derive(Debug, Default)]
/// Tracks safety limits that must be shared while scanning one archive tree.
struct ArchiveScanState {
    /// Cumulative member count for the current top-level archive scan.
    entries_seen: usize,
    /// Current nested archive depth for the active path being scanned.
    depth: usize,
}

impl ArchiveScanState {
    /// Start a fresh archive scan state at the caller's current depth.
    fn new(depth: usize) -> Self {
        Self {
            entries_seen: 0,
            depth,
        }
    }

    /// Descend into an archive member that may itself contain an archive.
    fn enter_child(&mut self) {
        self.depth += 1;
    }

    /// Return from a nested archive member so sibling entries keep the same depth.
    fn leave_child(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Check whether another archive may be opened at the current path depth.
    fn allow_archive(&self, summary: &mut ScanSummaryStats, archive_path: &Path) -> bool {
        if self.depth >= MAX_ALLOWED_RECURSION {
            summary.record_skip(SkipReason::MaxArchiveDepth);
            eprintln!(
                "Skipped archive: maximum recursion reached: {}",
                archive_path.display()
            );
            return false;
        }

        true
    }

    /// Record one archive member and report whether the tree entry limit still allows scanning.
    fn record_entry(&mut self, summary: &mut ScanSummaryStats, archive_path: &Path) -> bool {
        self.entries_seen += 1;

        if self.entries_seen > MAX_ALLOWED_ARCHIVE_ENTRIES {
            summary.record_skip(SkipReason::MaxArchiveEntries);
            eprintln!(
                "Skipped archive: maximum archive entries reached: {}",
                archive_path.display()
            );
            return false;
        }

        true
    }
}

#[derive(Debug, Default)]
/// The stats from scanning a given file/directory path.
pub struct ScanSummaryStats {
    pub filesystem_files_scanned: u64,
    pub archive_entries_scanned: u64,
    pub archives_scanned: u64,
    pub known_hash_detections: u64,
    pub yara_detections: u64,
    pub errors: u64,
    pub files_skipped: u64,
    pub files_skipped_by_reason: [usize; SkipReason::COUNT],
    pub yara_rules_triggered: HashMap<String, u64>,
    pub detections: Vec<DetectionRecord>,
}

impl ScanSummaryStats {
    /// Function to create a new instance of `ScanSummaryStats`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Function to record a skipped file, along with the reason for the skip.
    pub fn record_skip(&mut self, reason: SkipReason) {
        self.files_skipped += 1;
        self.files_skipped_by_reason[reason.as_index()] += 1;
    }

    /// Function to count the number of skips for a given reason.
    pub fn skip_count(&self, reason: SkipReason) -> usize {
        self.files_skipped_by_reason[reason.as_index()]
    }

    /// Function to count the total number of files scanned.
    pub fn total_files_scanned(&self) -> u64 {
        self.filesystem_files_scanned + self.archive_entries_scanned
    }
}

/// The reason a file/archive was skipped during scanning.
#[derive(Debug, Copy, Clone)]
pub enum SkipReason {
    ZeroSize,
    MaxArchiveDepth,
    MaxArchiveEntries,
    MaxDecompressedBytes,
    MaxCompressionRatio,
    MalformedArchive,
    UnsupportedArchive,
    ArchiveReadError,
    EncryptedFile,
    FileIsSymLink,
}

impl SkipReason {
    pub const COUNT: usize = 10;

    pub fn as_index(self) -> usize {
        match self {
            SkipReason::ZeroSize => 0,
            SkipReason::MaxArchiveDepth => 1,
            SkipReason::MaxArchiveEntries => 2,
            SkipReason::MaxDecompressedBytes => 3,
            SkipReason::MaxCompressionRatio => 4,
            SkipReason::MalformedArchive => 5,
            SkipReason::UnsupportedArchive => 6,
            SkipReason::ArchiveReadError => 7,
            SkipReason::EncryptedFile => 8,
            SkipReason::FileIsSymLink => 9,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SkipReason::ZeroSize => "zero-size",
            SkipReason::MaxArchiveDepth => "maximum recursion reached",
            SkipReason::MaxArchiveEntries => "maximum archive entries reached",
            SkipReason::MaxDecompressedBytes => "maximum decompressed size reached",
            SkipReason::MaxCompressionRatio => "suspicious compression ratio",
            SkipReason::MalformedArchive => "malformed archive",
            SkipReason::UnsupportedArchive => "unsupported archive",
            SkipReason::ArchiveReadError => "archive read error",
            SkipReason::EncryptedFile => "file encrypted",
            SkipReason::FileIsSymLink => "file is symlink",
        }
    }

    pub fn json_label(self) -> &'static str {
        match self {
            SkipReason::ZeroSize => "zero_size",
            SkipReason::MaxArchiveDepth => "maximum_recursion_reached",
            SkipReason::MaxArchiveEntries => "maximum_archive_entries_reached",
            SkipReason::MaxDecompressedBytes => "maximum_decompressed_size_reached",
            SkipReason::MaxCompressionRatio => "suspicious_compression_ratio",
            SkipReason::MalformedArchive => "malformed_archive",
            SkipReason::UnsupportedArchive => "unsupported_archive",
            SkipReason::ArchiveReadError => "archive_read_error",
            SkipReason::EncryptedFile => "file_encrypted",
            SkipReason::FileIsSymLink => "file_is_symlink",
        }
    }

    pub const ALL: [SkipReason; Self::COUNT] = [
        SkipReason::ZeroSize,
        SkipReason::MaxArchiveDepth,
        SkipReason::MaxArchiveEntries,
        SkipReason::MaxDecompressedBytes,
        SkipReason::MaxCompressionRatio,
        SkipReason::MalformedArchive,
        SkipReason::UnsupportedArchive,
        SkipReason::ArchiveReadError,
        SkipReason::EncryptedFile,
        SkipReason::FileIsSymLink,
    ];
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DetectionSurface {
    FileSystemFile,
    ArchiveContainer,
    ArchiveEntry,
}

impl DetectionSurface {
    pub const COUNT: usize = 3;

    pub fn label(&self) -> &'static str {
        match self {
            DetectionSurface::FileSystemFile => "filesystem file",
            DetectionSurface::ArchiveEntry => "archive entry",
            DetectionSurface::ArchiveContainer => "archive container",
        }
    }

    pub fn json_label(&self) -> &'static str {
        match self {
            DetectionSurface::FileSystemFile => "filesystem_file",
            DetectionSurface::ArchiveEntry => "archive_entry",
            DetectionSurface::ArchiveContainer => "archive_container",
        }
    }

    pub const ALL: [DetectionSurface; Self::COUNT] = [
        DetectionSurface::FileSystemFile,
        DetectionSurface::ArchiveEntry,
        DetectionSurface::ArchiveContainer,
    ];
}

#[derive(Debug)]
pub struct DetectionRecord {
    pub path: PathBuf,
    pub score: u16,
    pub verdict: Verdict,
    pub findings: [Option<Finding>; MAX_FINDINGS_PER_FILE],
    pub surface: DetectionSurface,
}

impl DetectionRecord {
    /// Function to tell if a detection recorded is from an archive.
    pub fn is_archive_path(&self) -> bool {
        self.path.to_string_lossy().contains("!/")
    }

    /// Function to tell if a detection recorded is from a file system file.
    pub fn is_filesystem_path(&self) -> bool {
        !self.is_archive_path()
    }
}

impl std::fmt::Display for DetectionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[{}] {}", self.verdict.label(), self.path.display())?;

        writeln!(f, "  score: {}", self.score)?;

        let mut findings_written = false;

        for finding in self.findings.iter().flatten() {
            if !findings_written {
                writeln!(f, "  findings:")?;
                findings_written = true;
            }

            writeln!(
                f,
                "    - {} (score {}, confidence {})",
                finding.id.label(),
                finding.score,
                finding.confidence.label()
            )?;
        }

        Ok(())
    }
}

/// The result of scanning a single file to compare it's hash.
#[derive(Debug)]
enum HashScanResult {
    Clean,
    KnownHash { _family: Option<String> },
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
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            summary.errors += 1;
            eprintln!("Unable to get metadata from {:?}: {}", path, err);
            return summary;
        }
    };
    let file_type = metadata.file_type();

    if file_type.is_file() {
        scan_one_and_report(path, hash_database, yara_scanner, &mut summary);
    } else if file_type.is_dir() {
        scan_directory(path, hash_database, yara_scanner, &mut summary);
    } else if file_type.is_symlink() {
        summary.record_skip(SkipReason::FileIsSymLink);
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
        return Ok(HashScanResult::KnownHash { _family: None });
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
    let mut surface = DetectionSurface::FileSystemFile;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            summary.errors += 1;
            eprintln!("Unable to read metadata for {}: {}", path.display(), err);
            return;
        }
    };

    // Guard to skip symlinks
    if metadata.file_type().is_symlink() {
        summary.record_skip(SkipReason::FileIsSymLink);
        return;
    }

    // Guard to avoid scanning 0-length files
    if metadata.len() == 0 {
        summary.record_skip(SkipReason::ZeroSize);
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
        HashScanResult::KnownHash { _family: _ } => {
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

        surface = match archive_kind {
            ArchiveKind::Unknown => DetectionSurface::FileSystemFile,
            _ => DetectionSurface::ArchiveContainer,
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
    summary.filesystem_files_scanned += 1;
    let verdict = heuristics.verdict();
    match verdict {
        Verdict::Clean => {}
        _ => {
            summary.detections.push(DetectionRecord {
                path: path.to_path_buf(),
                score: heuristics.score(),
                verdict,
                findings: heuristics.findings(),
                surface,
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
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) => {
                summary.errors += 1;
                eprintln!("Unable to read metadata for {}: {}", path.display(), err);
                continue;
            }
        };
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            scan_directory(&path, hash_database, yara_scanner, summary);
        } else if file_type.is_file() {
            scan_one_and_report(&path, hash_database, yara_scanner, summary);
        } else if file_type.is_symlink() {
            summary.record_skip(SkipReason::FileIsSymLink);
            eprintln!("Skipping {:?} because it is a symlink", path);
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

/// Create a virtual path for archived files.
///
/// Example:
///   outer.zip + dir/eicar.com -> outer.zip!/dir/eicar.com
fn make_archive_path(archive_path: &Path, entry_path: &Path) -> PathBuf {
    let entry_name = normalise_archive_entry_name(entry_path);

    let mut display = archive_path.to_string_lossy().to_string();
    display.push_str("!/");
    display.push_str(&entry_name.to_string_lossy());

    PathBuf::from(display)
}

/// Normalise an archive member name for virtual display paths.
///
/// This does not produce a filesystem extraction path.
/// It removes root/prefix/current-dir components and ignores parent-dir components
/// so archive entries cannot appear to escape the virtual archive namespace.
fn normalise_archive_entry_name(entry_path: &Path) -> PathBuf {
    let mut cleaned = PathBuf::new();

    for component in entry_path.components() {
        match component {
            Component::Normal(part) => cleaned.push(part),

            Component::CurDir => {}

            Component::ParentDir => {
                // Do not allow `..` to appear in virtual archive paths.
                // We are not extracting, so dropping it is safer and clearer.
            }

            Component::RootDir | Component::Prefix(_) => {
                // Avoid absolute-looking virtual paths.
            }
        }
    }

    if cleaned.as_os_str().is_empty() {
        PathBuf::from("<unnamed>")
    } else {
        cleaned
    }
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
fn scan_bytes_with_state(
    virtual_path: &Path,
    bytes: &[u8],
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
    archive_state: &mut ArchiveScanState,
) -> Result<(), String> {
    let mut heuristics = HeuristicAccumulator::new();
    let mut surface = DetectionSurface::ArchiveEntry;
    // Skip files with a length of 0.
    if bytes.is_empty() {
        summary.record_skip(SkipReason::ZeroSize);
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
        HashScanResult::KnownHash { _family: _ } => {
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

                if let Err(err) = scan_zip_archive_with_state(
                    cursor,
                    virtual_path,
                    hash_database,
                    yara_scanner,
                    summary,
                    archive_state,
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

                if let Err(err) = scan_tar_archive_with_state(
                    cursor,
                    virtual_path,
                    hash_database,
                    yara_scanner,
                    summary,
                    archive_state,
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

                if let Err(err) = scan_gzip_reader_with_state(
                    cursor,
                    virtual_path,
                    hash_database,
                    yara_scanner,
                    summary,
                    archive_state,
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

        surface = match archive_kind {
            ArchiveKind::Unknown => DetectionSurface::ArchiveEntry,
            _ => DetectionSurface::ArchiveContainer,
        };

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
    summary.archive_entries_scanned += 1;
    let verdict = heuristics.verdict();
    match verdict {
        Verdict::Clean => {}
        _ => {
            summary.detections.push(DetectionRecord {
                path: virtual_path.into(),
                score: heuristics.score(),
                verdict,
                findings: heuristics.findings(),
                surface,
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
    let mut archive_state = ArchiveScanState::new(depth);
    scan_zip_archive_with_state(
        reader,
        archive_path,
        hash_database,
        yara_scanner,
        summary,
        &mut archive_state,
    )
}

fn scan_zip_archive_with_state<R>(
    reader: R,
    archive_path: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
    archive_state: &mut ArchiveScanState,
) -> Result<(), String>
where
    R: Read + std::io::Seek,
{
    if !archive_state.allow_archive(summary, archive_path) {
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

        if !archive_state.record_entry(summary, archive_path) {
            break;
        }

        if entry.is_dir() {
            continue;
        }

        if entry.encrypted() {
            summary.record_skip(SkipReason::EncryptedFile);
            continue;
        }

        let entry_size = entry.size();

        if entry_size > MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE {
            summary.record_skip(SkipReason::MaxDecompressedBytes);
            continue;
        }

        entry_buffer.reserve(entry_size as usize);

        if let Err(err) = read_limited_into(
            &mut entry,
            &mut entry_buffer,
            MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE,
        ) {
            summary.record_skip(SkipReason::MaxDecompressedBytes);
            eprintln!(
                "Skipped zip entry: {}!/{} ({})",
                archive_path.display(),
                entry.name(),
                err
            );
            continue;
        }

        let virtual_path = make_archive_path(archive_path, Path::new(entry.name()));

        archive_state.enter_child();
        let _ = scan_bytes_with_state(
            &virtual_path,
            &entry_buffer,
            hash_database,
            yara_scanner,
            summary,
            archive_state,
        );
        archive_state.leave_child();

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
    let mut archive_state = ArchiveScanState::new(depth);
    scan_tar_archive_with_state(
        reader,
        archive_path,
        hash_database,
        yara_scanner,
        summary,
        &mut archive_state,
    )
}

fn scan_tar_archive_with_state<R>(
    reader: R,
    archive_path: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
    archive_state: &mut ArchiveScanState,
) -> Result<(), String>
where
    R: Read,
{
    if !archive_state.allow_archive(summary, archive_path) {
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

        if !archive_state.record_entry(summary, archive_path) {
            break;
        }

        let header = entry.header();

        // Don't scan directory entries or non-file entries.
        if header.entry_type().is_dir() || !header.entry_type().is_file() {
            continue;
        }

        let entry_size = header.size().unwrap_or(0);

        if entry_size > MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE {
            summary.record_skip(SkipReason::MaxDecompressedBytes);
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
            summary.record_skip(SkipReason::MaxDecompressedBytes);
            eprintln!(
                "Skipped tar entry: {}!/{} ({})",
                archive_path.display(),
                entry_path.display(),
                err
            );
            continue;
        }

        let virtual_path = make_archive_path(archive_path, &entry_path);

        archive_state.enter_child();
        let _ = scan_bytes_with_state(
            &virtual_path,
            &entry_buffer,
            hash_database,
            yara_scanner,
            summary,
            archive_state,
        );
        archive_state.leave_child();

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
    let mut archive_state = ArchiveScanState::new(depth);
    scan_gzip_reader_with_state(
        reader,
        archive_path,
        hash_database,
        yara_scanner,
        summary,
        &mut archive_state,
    )
}

fn scan_gzip_reader_with_state<R>(
    reader: R,
    archive_path: &Path,
    hash_database: &HashDatabase,
    yara_scanner: &mut yara_x::Scanner,
    summary: &mut ScanSummaryStats,
    archive_state: &mut ArchiveScanState,
) -> Result<(), String>
where
    R: Read,
{
    if !archive_state.allow_archive(summary, archive_path) {
        return Ok(());
    }

    summary.archives_scanned += 1;

    let decompressed = match decompress_gzip_limited(reader, MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE) {
        Ok(bytes) => bytes,
        Err(err) if err.contains("size limit exceeded") => {
            summary.record_skip(SkipReason::MaxDecompressedBytes);
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
        summary.record_skip(SkipReason::ZeroSize);
        return Ok(());
    }

    let inner_path = gzip_inner_virtual_path(archive_path);

    archive_state.enter_child();
    let result = scan_bytes_with_state(
        &inner_path,
        &decompressed,
        hash_database,
        yara_scanner,
        summary,
        archive_state,
    );
    archive_state.leave_child();

    result
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
fn gzip_inner_virtual_path(path: &Path) -> PathBuf {
    let inner_name = gzip_inner_entry_name(path);
    make_archive_path(path, Path::new(&inner_name))
}

/// Helper function to get the synthetic inner entry name for gzip content.
///
/// Examples:
///   eicar.tar.gz -> eicar.tar
///   archive.tgz  -> archive.tar
///   file.txt.gz  -> file.txt
fn gzip_inner_entry_name(path: &Path) -> String {
    let display = path.to_string_lossy();

    let basename = display
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("<decompressed>");

    if let Some(stem) = basename.strip_suffix(".tar.gz") {
        format!("{stem}.tar")
    } else if let Some(stem) = basename.strip_suffix(".tgz") {
        format!("{stem}.tar")
    } else if let Some(stem) = basename.strip_suffix(".gz") {
        stem.to_string()
    } else {
        "<decompressed>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::{Read, Write};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    fn compile_rules(source: &str) -> yara_x::Rules {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source).unwrap();
        compiler.build()
    }

    fn non_matching_rules() -> yara_x::Rules {
        compile_rules("rule never_matches { condition: false }")
    }

    fn gzip_bytes(payload: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn hash_database_for_payload(payload: &[u8]) -> (tempfile::NamedTempFile, HashDatabase) {
        let file = tempfile::NamedTempFile::new().unwrap();
        let connection = rusqlite::Connection::open(file.path()).unwrap();
        let sha256 = hash_file_from_memory(payload).unwrap().sha256;

        connection
            .execute("CREATE TABLE malware_hashes (sha256 BLOB NOT NULL)", [])
            .unwrap();
        connection
            .execute(
                "INSERT INTO malware_hashes (sha256) VALUES (?1)",
                rusqlite::params![&sha256[..]],
            )
            .unwrap();
        drop(connection);

        let database = crate::scanner::database::load_hash_database(file.path()).unwrap();

        (file, database)
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        writer.add_directory("ignored-dir/", options).unwrap();

        for (path, bytes) in entries {
            writer.start_file(path, options).unwrap();
            writer.write_all(bytes).unwrap();
        }

        writer.finish().unwrap().into_inner()
    }

    fn zip_bytes_with_numbered_files(count: usize) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        for i in 0..count {
            writer.start_file(format!("file-{i}.bin"), options).unwrap();
            writer.write_all(b"payload").unwrap();
        }

        writer.finish().unwrap().into_inner()
    }

    fn zip_bytes_with_padding_and_nested_zip(padding_entries: usize, nested_zip: &[u8]) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        for i in 0..padding_entries {
            writer
                .start_file(format!("padding-{i}.bin"), options)
                .unwrap();
            writer.write_all(b"padding").unwrap();
        }

        writer.start_file("nested.zip", options).unwrap();
        writer.write_all(nested_zip).unwrap();

        writer.finish().unwrap().into_inner()
    }

    fn zip_bytes_with_zero_file(path: &str, size: u64) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        writer.start_file(path, options).unwrap();
        std::io::copy(&mut std::io::repeat(0).take(size), &mut writer).unwrap();

        writer.finish().unwrap().into_inner()
    }

    fn tar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());

        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }

        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }

    fn tar_bytes_with_numbered_files(count: usize) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());

        for i in 0..count {
            let mut header = tar::Header::new_gnu();
            header.set_size(7);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("file-{i}.bin"), &b"payload"[..])
                .unwrap();
        }

        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }

    fn tar_header_declaring_size(path: &str, size: u64) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        header.as_bytes().to_vec()
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "synthetic read failure",
            ))
        }
    }

    #[test]
    fn archive_path_for_simple_zip_entry() {
        let path = make_archive_path(Path::new("./corpus/eicar.zip"), Path::new("eicar.com"));

        assert_eq!(path, PathBuf::from("./corpus/eicar.zip!/eicar.com"));
    }

    #[test]
    fn archive_path_strips_leading_dot_slash_from_tar_entry() {
        let path = make_archive_path(Path::new("./corpus/eicar.tar"), Path::new("./eicar.com"));

        assert_eq!(path, PathBuf::from("./corpus/eicar.tar!/eicar.com"));
    }

    #[test]
    fn archive_path_keeps_nested_entry_path() {
        let path = make_archive_path(
            Path::new("./corpus/outer.zip"),
            Path::new("inner/eicar.zip"),
        );

        assert_eq!(path, PathBuf::from("./corpus/outer.zip!/inner/eicar.zip"));
    }

    #[test]
    fn archive_path_strips_leading_dot_slash_from_nested_entry_path() {
        let path = make_archive_path(
            Path::new("./corpus/outer.tar"),
            Path::new("./inner/eicar.zip"),
        );

        assert_eq!(path, PathBuf::from("./corpus/outer.tar!/inner/eicar.zip"));
    }

    #[test]
    fn archive_path_can_chain_virtual_paths() {
        let path = make_archive_path(
            Path::new("./corpus/outer.zip!/inner/eicar.tar"),
            Path::new("./eicar.com"),
        );

        assert_eq!(
            path,
            PathBuf::from("./corpus/outer.zip!/inner/eicar.tar!/eicar.com")
        );
    }

    #[test]
    fn gzip_inner_virtual_path_for_tar_gz_uses_basename_only() {
        let path =
            gzip_inner_virtual_path(Path::new("./corpus/malicious/synthetic/eicar/eicar.tar.gz"));

        assert_eq!(
            path,
            PathBuf::from("./corpus/malicious/synthetic/eicar/eicar.tar.gz!/eicar.tar")
        );
    }

    #[test]
    fn gzip_inner_virtual_path_for_tgz_uses_tar_basename() {
        let path = gzip_inner_virtual_path(Path::new("./corpus/archive.tgz"));

        assert_eq!(path, PathBuf::from("./corpus/archive.tgz!/archive.tar"));
    }

    #[test]
    fn gzip_inner_virtual_path_for_plain_gz_strips_gz_from_basename() {
        let path = gzip_inner_virtual_path(Path::new("./corpus/readme.txt.gz"));

        assert_eq!(path, PathBuf::from("./corpus/readme.txt.gz!/readme.txt"));
    }

    #[test]
    fn gzip_inner_virtual_path_for_nested_virtual_tar_gz_uses_inner_basename_only() {
        let path = gzip_inner_virtual_path(Path::new("./corpus/outer.zip!/inner/eicar.tar.gz"));

        assert_eq!(
            path,
            PathBuf::from("./corpus/outer.zip!/inner/eicar.tar.gz!/eicar.tar")
        );
    }

    #[test]
    fn gzip_inner_virtual_path_for_generated_tar_gz_name() {
        let path =
            gzip_inner_virtual_path(Path::new("./corpus/archives/malicious/eicar_tar_gz.tar.gz"));

        assert_eq!(
            path,
            PathBuf::from("./corpus/archives/malicious/eicar_tar_gz.tar.gz!/eicar_tar_gz.tar")
        );
    }

    #[test]
    fn gzip_inner_virtual_path_for_zip_tar_gz_zip_case() {
        let path = gzip_inner_virtual_path(Path::new(
            "./corpus/archives/malicious/eicar_zip_inside_tar_gz.tar.gz",
        ));

        assert_eq!(
            path,
            PathBuf::from(
                "./corpus/archives/malicious/eicar_zip_inside_tar_gz.tar.gz!/eicar_zip_inside_tar_gz.tar"
            )
        );
    }

    #[test]
    fn gzip_inner_virtual_path_for_tar_gz_inside_zip_case() {
        let path = gzip_inner_virtual_path(Path::new(
            "./corpus/archives/malicious/eicar_tar_gz_inside_zip.zip!/inner/eicar.tar.gz",
        ));

        assert_eq!(
            path,
            PathBuf::from(
                "./corpus/archives/malicious/eicar_tar_gz_inside_zip.zip!/inner/eicar.tar.gz!/eicar.tar"
            )
        );
    }

    #[test]
    fn skip_summary_counts_each_reason_independently() {
        let mut summary = ScanSummaryStats::new();

        summary.record_skip(SkipReason::ZeroSize);
        summary.record_skip(SkipReason::ZeroSize);
        summary.record_skip(SkipReason::EncryptedFile);

        assert_eq!(summary.files_skipped, 3);
        assert_eq!(summary.skip_count(SkipReason::ZeroSize), 2);
        assert_eq!(summary.skip_count(SkipReason::EncryptedFile), 1);
        assert_eq!(summary.skip_count(SkipReason::MalformedArchive), 0);
    }

    #[test]
    fn skip_reason_labels_are_stable() {
        let cases = [
            (SkipReason::ZeroSize, "zero-size", "zero_size"),
            (
                SkipReason::MaxArchiveDepth,
                "maximum recursion reached",
                "maximum_recursion_reached",
            ),
            (
                SkipReason::MaxArchiveEntries,
                "maximum archive entries reached",
                "maximum_archive_entries_reached",
            ),
            (
                SkipReason::MaxDecompressedBytes,
                "maximum decompressed size reached",
                "maximum_decompressed_size_reached",
            ),
            (
                SkipReason::MaxCompressionRatio,
                "suspicious compression ratio",
                "suspicious_compression_ratio",
            ),
            (
                SkipReason::MalformedArchive,
                "malformed archive",
                "malformed_archive",
            ),
            (
                SkipReason::UnsupportedArchive,
                "unsupported archive",
                "unsupported_archive",
            ),
            (
                SkipReason::ArchiveReadError,
                "archive read error",
                "archive_read_error",
            ),
            (
                SkipReason::EncryptedFile,
                "file encrypted",
                "file_encrypted",
            ),
            (
                SkipReason::FileIsSymLink,
                "file is symlink",
                "file_is_symlink",
            ),
        ];

        assert_eq!(SkipReason::ALL.len(), SkipReason::COUNT);

        for (reason, label, json_label) in cases {
            assert_eq!(reason.label(), label);
            assert_eq!(reason.json_label(), json_label);
        }
    }

    #[test]
    fn detection_surface_labels_and_path_helpers_are_stable() {
        let cases = [
            (
                DetectionSurface::FileSystemFile,
                "filesystem file",
                "filesystem_file",
            ),
            (
                DetectionSurface::ArchiveEntry,
                "archive entry",
                "archive_entry",
            ),
            (
                DetectionSurface::ArchiveContainer,
                "archive container",
                "archive_container",
            ),
        ];

        assert_eq!(DetectionSurface::ALL.len(), DetectionSurface::COUNT);

        for (surface, label, json_label) in cases {
            assert_eq!(surface.label(), label);
            assert_eq!(surface.json_label(), json_label);
        }

        let archive_record = DetectionRecord {
            path: PathBuf::from("sample.zip!/payload.bin"),
            score: 90,
            verdict: Verdict::Malicious,
            findings: [None; MAX_FINDINGS_PER_FILE],
            surface: DetectionSurface::ArchiveEntry,
        };
        let filesystem_record = DetectionRecord {
            path: PathBuf::from("payload.bin"),
            score: 90,
            verdict: Verdict::Malicious,
            findings: [None; MAX_FINDINGS_PER_FILE],
            surface: DetectionSurface::FileSystemFile,
        };

        assert!(archive_record.is_archive_path());
        assert!(!archive_record.is_filesystem_path());
        assert!(!filesystem_record.is_archive_path());
        assert!(filesystem_record.is_filesystem_path());
    }

    #[test]
    fn detection_record_display_includes_verdict_path_score_and_findings() {
        let mut findings = [None; MAX_FINDINGS_PER_FILE];
        findings[0] = Some(Finding {
            id: FindingId::KnownHash,
            score: 100,
            confidence: Confidence::High,
        });
        let record = DetectionRecord {
            path: PathBuf::from("payload.bin"),
            score: 100,
            verdict: Verdict::Malicious,
            findings,
            surface: DetectionSurface::FileSystemFile,
        };

        let rendered = record.to_string();

        assert!(rendered.contains("[malicious] payload.bin"));
        assert!(rendered.contains("score: 100"));
        assert!(rendered.contains("findings:"));
        assert!(rendered.contains("known hash"));
        assert!(rendered.contains("confidence high"));
    }

    #[test]
    fn archive_kind_detection_recognizes_magic_bytes() {
        let mut tar_header = [0_u8; 512];
        tar_header[257..263].copy_from_slice(b"ustar\0");

        assert!(matches!(
            detect_archive_kind(b"PK\x03\x04anything").unwrap(),
            ArchiveKind::Zip
        ));
        assert!(matches!(
            detect_archive_kind(b"PK\x05\x06empty zip").unwrap(),
            ArchiveKind::Zip
        ));
        assert!(matches!(
            detect_archive_kind(b"PK\x07\x08spanned zip").unwrap(),
            ArchiveKind::Zip
        ));
        assert!(matches!(
            detect_archive_kind(&[0x1f, 0x8b, 0x08]).unwrap(),
            ArchiveKind::Gzip
        ));
        assert!(matches!(
            detect_archive_kind(&tar_header).unwrap(),
            ArchiveKind::Tar
        ));
        assert!(matches!(
            detect_archive_kind(b"plain text").unwrap(),
            ArchiveKind::Unknown
        ));
    }

    #[test]
    fn normalise_archive_entry_name_removes_escape_components() {
        assert_eq!(
            normalise_archive_entry_name(Path::new("/tmp/../payload")),
            PathBuf::from("tmp/payload")
        );
        assert_eq!(
            normalise_archive_entry_name(Path::new("../../")),
            PathBuf::from("<unnamed>")
        );
    }

    #[test]
    fn read_limited_into_errors_and_clears_output_when_limit_is_exceeded() {
        let mut input = std::io::Cursor::new(b"abcdef");
        let mut output = vec![1, 2, 3];

        let err = read_limited_into(&mut input, &mut output, 5).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(output.is_empty());
    }

    #[test]
    fn read_limited_into_propagates_reader_errors() {
        let mut input = FailingReader;
        let mut output = vec![1, 2, 3];

        let err = read_limited_into(&mut input, &mut output, 5).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(output.is_empty());
    }

    #[test]
    fn archive_scan_state_tracks_depth_and_entry_limits() {
        let mut summary = ScanSummaryStats::new();
        let archive_path = Path::new("archive.zip");
        let mut state = ArchiveScanState::new(MAX_ALLOWED_RECURSION - 1);

        assert!(state.allow_archive(&mut summary, archive_path));
        state.enter_child();
        assert!(!state.allow_archive(&mut summary, archive_path));
        state.leave_child();
        assert!(state.allow_archive(&mut summary, archive_path));
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveDepth), 1);

        state.entries_seen = MAX_ALLOWED_ARCHIVE_ENTRIES;
        assert!(!state.record_entry(&mut summary, archive_path));
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveEntries), 1);

        state.depth = 0;
        state.leave_child();
        assert_eq!(state.depth, 0);
    }

    #[test]
    fn scan_file_hashes_from_disk_reports_missing_path_error() {
        let database = HashDatabase::default();
        let target = tempfile::tempdir().unwrap().path().join("missing.bin");

        let err = scan_file_hashes_from_disk(&target, &database).unwrap_err();

        assert_eq!(err, "Unable to compare hash");
    }

    #[test]
    fn scan_file_hashes_from_disk_returns_clean_for_unknown_file() {
        let database = HashDatabase::default();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"unknown disk hash payload").unwrap();

        let result = scan_file_hashes_from_disk(file.path(), &database).unwrap();

        assert!(matches!(result, HashScanResult::Clean));
    }

    #[test]
    fn scan_file_hashes_from_memory_detects_known_hash() {
        let payload = b"known in-memory hash payload";
        let (_database_file, database) = hash_database_for_payload(payload);

        let result = scan_file_hashes_from_memory(payload, &database).unwrap();

        assert!(matches!(result, HashScanResult::KnownHash { .. }));
    }

    #[test]
    fn scan_file_hashes_from_memory_returns_clean_for_unknown_payload() {
        let database = HashDatabase::default();

        let result = scan_file_hashes_from_memory(b"unknown memory hash payload", &database)
            .expect("memory hashing should succeed");

        assert!(matches!(result, HashScanResult::Clean));
    }

    #[test]
    fn scan_file_yara_from_disk_reports_missing_path_error() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let target = tempfile::tempdir().unwrap().path().join("missing.bin");

        let err = scan_file_yara_from_disk(&target, &mut scanner).unwrap_err();

        assert!(!err.is_empty());
    }

    #[test]
    fn scan_file_yara_from_disk_returns_clean_and_matches_rules() {
        let clean_rules = non_matching_rules();
        let mut clean_scanner = yara_x::Scanner::new(&clean_rules);
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"plain payload").unwrap();

        let clean = scan_file_yara_from_disk(file.path(), &mut clean_scanner).unwrap();

        assert!(matches!(clean, YaraScanResult::Clean));

        let matching_rules = compile_rules(
            r#"
            rule Disk_Helper_Test {
                strings:
                    $marker = "disk-helper-marker"
                condition:
                    $marker
            }
            "#,
        );
        let mut matching_scanner = yara_x::Scanner::new(&matching_rules);
        std::fs::write(file.path(), b"prefix disk-helper-marker suffix").unwrap();

        let matched = scan_file_yara_from_disk(file.path(), &mut matching_scanner).unwrap();

        match matched {
            YaraScanResult::YaraRules { rules } => {
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].name, "Disk_Helper_Test");
            }
            YaraScanResult::Clean => panic!("expected YARA rule match"),
        }
    }

    #[test]
    fn scan_file_yara_from_memory_returns_clean_and_matches_rules() {
        let clean_rules = non_matching_rules();
        let mut clean_scanner = yara_x::Scanner::new(&clean_rules);

        let clean = scan_file_yara_from_memory(b"plain payload", &mut clean_scanner).unwrap();

        assert!(matches!(clean, YaraScanResult::Clean));

        let matching_rules = compile_rules(
            r#"
            rule Memory_Helper_Test {
                strings:
                    $marker = "memory-helper-marker"
                condition:
                    $marker
            }
            "#,
        );
        let mut matching_scanner = yara_x::Scanner::new(&matching_rules);

        let matched = scan_file_yara_from_memory(
            b"prefix memory-helper-marker suffix",
            &mut matching_scanner,
        )
        .unwrap();

        match matched {
            YaraScanResult::YaraRules { rules } => {
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].name, "Memory_Helper_Test");
            }
            YaraScanResult::Clean => panic!("expected YARA rule match"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn scan_path_reports_error_for_non_file_targets() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();

        let summary = scan_path(Path::new("/dev/null"), &database, &mut scanner);

        assert_eq!(summary.errors, 1);
        assert_eq!(summary.total_files_scanned(), 0);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_path_reports_error_for_missing_target() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let target = tempfile::tempdir().unwrap().path().join("missing.bin");

        let summary = scan_path(&target, &database, &mut scanner);

        assert_eq!(summary.errors, 1);
        assert_eq!(summary.total_files_scanned(), 0);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_path_skips_zero_size_file_without_counting_it_as_scanned() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let file = tempfile::NamedTempFile::new().unwrap();

        let summary = scan_path(file.path(), &database, &mut scanner);

        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.skip_count(SkipReason::ZeroSize), 1);
        assert_eq!(summary.filesystem_files_scanned, 0);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_path_recurses_directories_and_counts_small_files() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(root.path().join("one.bin"), b"one").unwrap();
        std::fs::write(nested.join("two.bin"), b"two").unwrap();
        std::fs::write(nested.join("empty.bin"), b"").unwrap();

        let summary = scan_path(root.path(), &database, &mut scanner);

        assert_eq!(summary.errors, 0);
        assert_eq!(summary.filesystem_files_scanned, 2);
        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.total_files_scanned(), 2);
        assert!(summary.detections.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn scan_path_ignores_symlinked_directory_entries() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        std::fs::write(root.path().join("inside.bin"), b"inside").unwrap();
        std::fs::write(outside.path().join("outside.bin"), b"outside").unwrap();
        symlink(outside.path(), root.path().join("linked-dir")).unwrap();

        let summary = scan_path(root.path(), &database, &mut scanner);

        assert_eq!(summary.errors, 0);
        assert_eq!(summary.filesystem_files_scanned, 1);
        assert_eq!(summary.skip_count(SkipReason::FileIsSymLink), 1);
        assert_eq!(summary.total_files_scanned(), 1);
        assert!(summary.detections.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn scan_path_ignores_symlinked_file_entries() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("outside.bin");

        std::fs::write(root.path().join("inside.bin"), b"inside").unwrap();
        std::fs::write(&outside_file, b"outside").unwrap();
        symlink(&outside_file, root.path().join("linked-file.bin")).unwrap();

        let summary = scan_path(root.path(), &database, &mut scanner);

        assert_eq!(summary.errors, 0);
        assert_eq!(summary.filesystem_files_scanned, 1);
        assert_eq!(summary.skip_count(SkipReason::FileIsSymLink), 1);
        assert_eq!(summary.total_files_scanned(), 1);
        assert!(summary.detections.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn scan_path_skips_explicit_symlink_target() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let root = tempfile::tempdir().unwrap();
        let real_file = root.path().join("real.bin");
        let linked_file = root.path().join("linked.bin");

        std::fs::write(&real_file, b"real").unwrap();
        symlink(&real_file, &linked_file).unwrap();

        let summary = scan_path(&linked_file, &database, &mut scanner);

        assert_eq!(summary.errors, 0);
        assert_eq!(summary.filesystem_files_scanned, 0);
        assert_eq!(summary.skip_count(SkipReason::FileIsSymLink), 1);
        assert_eq!(summary.total_files_scanned(), 0);
        assert!(summary.detections.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn scan_path_does_not_follow_symlink_loop() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let root = tempfile::tempdir().unwrap();

        std::fs::write(root.path().join("inside.bin"), b"inside").unwrap();
        symlink(root.path(), root.path().join("loop")).unwrap();

        let summary = scan_path(root.path(), &database, &mut scanner);

        assert_eq!(summary.errors, 0);
        assert_eq!(summary.filesystem_files_scanned, 1);
        assert_eq!(summary.skip_count(SkipReason::FileIsSymLink), 1);
        assert_eq!(summary.total_files_scanned(), 1);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_one_and_report_counts_clean_small_files_without_detection() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"clean small file").unwrap();

        scan_one_and_report(file.path(), &database, &mut scanner, &mut summary);

        assert_eq!(summary.errors, 0);
        assert_eq!(summary.filesystem_files_scanned, 1);
        assert_eq!(summary.known_hash_detections, 0);
        assert_eq!(summary.yara_detections, 0);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_one_and_report_counts_error_for_missing_path() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let target = tempfile::tempdir().unwrap().path().join("missing.bin");

        scan_one_and_report(&target, &database, &mut scanner, &mut summary);

        assert_eq!(summary.errors, 1);
        assert_eq!(summary.total_files_scanned(), 0);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_one_and_report_records_known_hash_detection() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let payload = b"known hash payload";
        let (_database_file, database) = hash_database_for_payload(payload);
        let mut summary = ScanSummaryStats::new();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), payload).unwrap();

        scan_one_and_report(file.path(), &database, &mut scanner, &mut summary);

        assert_eq!(summary.filesystem_files_scanned, 1);
        assert_eq!(summary.known_hash_detections, 1);
        assert_eq!(summary.detections.len(), 1);
        assert_eq!(summary.detections[0].score, 100);
        assert_eq!(summary.detections[0].verdict, Verdict::Malicious);
        assert_eq!(
            summary.detections[0].surface,
            DetectionSurface::FileSystemFile
        );
    }

    #[test]
    fn scan_one_and_report_records_yara_detection_for_files_over_threshold() {
        let rules = compile_rules(
            r#"
            rule EICAR_File_Test {
                strings:
                    $marker = "filesystem-yara-marker"
                condition:
                    $marker
            }
            "#,
        );
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            b"prefix filesystem-yara-marker suffix with enough bytes",
        )
        .unwrap();

        scan_one_and_report(file.path(), &database, &mut scanner, &mut summary);

        assert_eq!(summary.filesystem_files_scanned, 1);
        assert_eq!(summary.yara_detections, 1);
        assert_eq!(summary.yara_rules_triggered["EICAR_File_Test"], 1);
        assert_eq!(summary.detections.len(), 1);
        assert_eq!(
            summary.detections[0].surface,
            DetectionSurface::FileSystemFile
        );
        assert_eq!(summary.detections[0].verdict, Verdict::LikelyMalicious);
    }

    #[test]
    fn scan_one_and_report_combines_hash_and_yara_findings_for_same_file() {
        let rules = compile_rules(
            r#"
            rule EICAR_Combined_File_Test {
                strings:
                    $marker = "combined-file-marker"
                condition:
                    $marker
            }
            "#,
        );
        let mut scanner = yara_x::Scanner::new(&rules);
        let payload = b"prefix combined-file-marker suffix with enough bytes";
        let (_database_file, database) = hash_database_for_payload(payload);
        let mut summary = ScanSummaryStats::new();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), payload).unwrap();

        scan_one_and_report(file.path(), &database, &mut scanner, &mut summary);

        assert_eq!(summary.errors, 0);
        assert_eq!(summary.filesystem_files_scanned, 1);
        assert_eq!(summary.known_hash_detections, 1);
        assert_eq!(summary.yara_detections, 1);
        assert_eq!(summary.yara_rules_triggered["EICAR_Combined_File_Test"], 1);
        assert_eq!(summary.detections.len(), 1);
        assert_eq!(summary.detections[0].score, 180);
        assert_eq!(summary.detections[0].verdict, Verdict::Malicious);
        assert_eq!(
            summary.detections[0].surface,
            DetectionSurface::FileSystemFile
        );
        assert_eq!(summary.detections[0].findings.iter().flatten().count(), 2);
    }

    #[test]
    fn scan_one_and_report_counts_error_for_malformed_archive_container() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"PK\x03\x04not really a zip but long enough").unwrap();

        scan_one_and_report(file.path(), &database, &mut scanner, &mut summary);

        assert_eq!(summary.errors, 1);
        assert_eq!(summary.filesystem_files_scanned, 1);
        assert_eq!(summary.archives_scanned, 1);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_bytes_skips_empty_archive_entry() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let mut archive_state = ArchiveScanState::new(0);

        scan_bytes_with_state(
            Path::new("archive.zip!/empty"),
            b"",
            &database,
            &mut scanner,
            &mut summary,
            &mut archive_state,
        )
        .unwrap();

        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.skip_count(SkipReason::ZeroSize), 1);
        assert_eq!(summary.archive_entries_scanned, 0);
    }

    #[test]
    fn scan_bytes_records_known_hash_detection_for_archive_entry() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let payload = b"known archive entry hash";
        let (_database_file, database) = hash_database_for_payload(payload);
        let mut summary = ScanSummaryStats::new();
        let mut archive_state = ArchiveScanState::new(0);

        scan_bytes_with_state(
            Path::new("archive.zip!/known.bin"),
            payload,
            &database,
            &mut scanner,
            &mut summary,
            &mut archive_state,
        )
        .unwrap();

        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.known_hash_detections, 1);
        assert_eq!(summary.detections.len(), 1);
        assert_eq!(summary.detections[0].verdict, Verdict::Malicious);
        assert_eq!(
            summary.detections[0].surface,
            DetectionSurface::ArchiveEntry
        );
    }

    #[test]
    fn scan_bytes_counts_clean_non_archive_payload_over_yara_threshold() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let mut archive_state = ArchiveScanState::new(0);

        scan_bytes_with_state(
            Path::new("archive.zip!/clean.bin"),
            b"clean payload long enough to run archive detection and yara",
            &database,
            &mut scanner,
            &mut summary,
            &mut archive_state,
        )
        .unwrap();

        assert_eq!(summary.errors, 0);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.known_hash_detections, 0);
        assert_eq!(summary.yara_detections, 0);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_bytes_records_yara_detection_for_archive_entry() {
        let rules = compile_rules(
            r#"
            rule EICAR_Test {
                strings:
                    $marker = "galen-test-marker"
                condition:
                    $marker
            }
            "#,
        );
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let payload = b"prefix galen-test-marker suffix with enough bytes for yara";
        let mut archive_state = ArchiveScanState::new(0);

        scan_bytes_with_state(
            Path::new("archive.zip!/payload.bin"),
            payload,
            &database,
            &mut scanner,
            &mut summary,
            &mut archive_state,
        )
        .unwrap();

        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.yara_detections, 1);
        assert_eq!(summary.yara_rules_triggered["EICAR_Test"], 1);
        assert_eq!(summary.detections.len(), 1);
        assert_eq!(
            summary.detections[0].path,
            PathBuf::from("archive.zip!/payload.bin")
        );
        assert_eq!(
            summary.detections[0].surface,
            DetectionSurface::ArchiveEntry
        );
        assert_eq!(summary.detections[0].verdict, Verdict::LikelyMalicious);
    }

    #[test]
    fn scan_bytes_combines_hash_and_yara_findings_for_archive_entry() {
        let rules = compile_rules(
            r#"
            rule EICAR_Combined_Entry_Test {
                strings:
                    $marker = "combined-entry-marker"
                condition:
                    $marker
            }
            "#,
        );
        let mut scanner = yara_x::Scanner::new(&rules);
        let payload = b"prefix combined-entry-marker suffix with enough bytes";
        let (_database_file, database) = hash_database_for_payload(payload);
        let mut summary = ScanSummaryStats::new();
        let mut archive_state = ArchiveScanState::new(0);

        scan_bytes_with_state(
            Path::new("archive.zip!/combined.bin"),
            payload,
            &database,
            &mut scanner,
            &mut summary,
            &mut archive_state,
        )
        .unwrap();

        assert_eq!(summary.errors, 0);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.known_hash_detections, 1);
        assert_eq!(summary.yara_detections, 1);
        assert_eq!(summary.yara_rules_triggered["EICAR_Combined_Entry_Test"], 1);
        assert_eq!(summary.detections.len(), 1);
        assert_eq!(summary.detections[0].score, 180);
        assert_eq!(summary.detections[0].verdict, Verdict::Malicious);
        assert_eq!(
            summary.detections[0].surface,
            DetectionSurface::ArchiveEntry
        );
        assert_eq!(summary.detections[0].findings.iter().flatten().count(), 2);
    }

    #[test]
    fn scan_bytes_records_error_for_malformed_nested_zip_but_counts_container_entry() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let malformed_zip = b"PK\x03\x04not really a zip but long enough";
        let mut archive_state = ArchiveScanState::new(0);

        scan_bytes_with_state(
            Path::new("outer.zip!/bad.zip"),
            malformed_zip,
            &database,
            &mut scanner,
            &mut summary,
            &mut archive_state,
        )
        .unwrap();

        assert_eq!(summary.errors, 1);
        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_bytes_records_error_for_malformed_nested_gzip_but_counts_container_entry() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let mut malformed_gzip = vec![0x1f, 0x8b];
        malformed_gzip.extend_from_slice(b"not really gzip but long enough for archive probing");
        let mut archive_state = ArchiveScanState::new(0);

        scan_bytes_with_state(
            Path::new("outer.zip!/bad.gz"),
            &malformed_gzip,
            &database,
            &mut scanner,
            &mut summary,
            &mut archive_state,
        )
        .unwrap();

        assert_eq!(summary.errors, 1);
        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_gzip_reader_scans_decompressed_payload_as_archive_entry() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let compressed = gzip_bytes(b"small payload");

        scan_gzip_reader(
            std::io::Cursor::new(compressed),
            Path::new("payload.txt.gz"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.files_skipped, 0);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_gzip_reader_records_error_for_invalid_gzip() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();

        scan_gzip_reader(
            std::io::Cursor::new(b"not gzip".to_vec()),
            Path::new("bad.gz"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.files_skipped, 0);
    }

    #[test]
    fn scan_gzip_reader_skips_empty_decompressed_payload() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();

        scan_gzip_reader(
            std::io::Cursor::new(gzip_bytes(b"")),
            Path::new("empty.gz"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.skip_count(SkipReason::ZeroSize), 1);
        assert_eq!(summary.archive_entries_scanned, 0);
    }

    #[test]
    fn scan_gzip_reader_records_max_depth_skip_before_scanning() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();

        scan_gzip_reader(
            std::io::Cursor::new(gzip_bytes(b"payload")),
            Path::new("nested.gz"),
            &database,
            &mut scanner,
            &mut summary,
            MAX_ALLOWED_RECURSION,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 0);
        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveDepth), 1);
    }

    #[test]
    fn scan_gzip_reader_increments_depth_for_decompressed_archive() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let nested = gzip_bytes(&zip_bytes(&[("payload.bin", b"payload")]));

        scan_gzip_reader(
            std::io::Cursor::new(nested),
            Path::new("nested.zip.gz"),
            &database,
            &mut scanner,
            &mut summary,
            MAX_ALLOWED_RECURSION - 1,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveDepth), 1);
    }

    #[test]
    fn decompress_gzip_limited_rejects_payloads_over_limit() {
        let err =
            decompress_gzip_limited(std::io::Cursor::new(gzip_bytes(b"abcdef")), 5).unwrap_err();

        assert_eq!(err, "gzip decompressed size limit exceeded");
    }

    #[test]
    fn scan_zip_archive_scans_file_entries_and_skips_empty_entries() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let archive = zip_bytes(&[("dir/payload.bin", b"payload"), ("empty.bin", b"")]);

        scan_zip_archive(
            std::io::Cursor::new(archive),
            Path::new("sample.zip"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.skip_count(SkipReason::ZeroSize), 1);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_zip_archive_records_max_depth_skip_before_opening_reader() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();

        scan_zip_archive(
            std::io::Cursor::new(Vec::new()),
            Path::new("too-deep.zip"),
            &database,
            &mut scanner,
            &mut summary,
            MAX_ALLOWED_RECURSION,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 0);
        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveDepth), 1);
    }

    #[test]
    fn scan_zip_archive_applies_decompressed_size_boundary() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let archive = zip_bytes_with_zero_file("limit.bin", MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE);

        scan_zip_archive(
            std::io::Cursor::new(archive),
            Path::new("limit.zip"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.skip_count(SkipReason::MaxDecompressedBytes), 0);

        let archive =
            zip_bytes_with_zero_file("oversized.bin", MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE + 1);
        let mut summary = ScanSummaryStats::new();

        scan_zip_archive(
            std::io::Cursor::new(archive),
            Path::new("oversized.zip"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 0);
        assert_eq!(summary.skip_count(SkipReason::MaxDecompressedBytes), 1);
    }

    #[test]
    fn scan_zip_archive_limits_entries_across_one_archive_tree() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let archive = zip_bytes_with_numbered_files(MAX_ALLOWED_ARCHIVE_ENTRIES + 1);

        scan_zip_archive(
            std::io::Cursor::new(archive),
            Path::new("too-many.zip"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(
            summary.archive_entries_scanned,
            MAX_ALLOWED_ARCHIVE_ENTRIES as u64
        );
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveEntries), 1);
    }

    #[test]
    fn scan_zip_archive_entry_limit_is_not_global_across_top_level_archives() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let archive = zip_bytes_with_numbered_files(MAX_ALLOWED_ARCHIVE_ENTRIES);

        scan_zip_archive(
            std::io::Cursor::new(archive.clone()),
            Path::new("first.zip"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();
        scan_zip_archive(
            std::io::Cursor::new(archive),
            Path::new("second.zip"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 2);
        assert_eq!(
            summary.archive_entries_scanned,
            (MAX_ALLOWED_ARCHIVE_ENTRIES * 2) as u64
        );
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveEntries), 0);
    }

    #[test]
    fn scan_zip_archive_entry_limit_is_cumulative_for_nested_archives() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let nested = zip_bytes_with_numbered_files(1);
        let archive =
            zip_bytes_with_padding_and_nested_zip(MAX_ALLOWED_ARCHIVE_ENTRIES - 1, &nested);

        scan_zip_archive(
            std::io::Cursor::new(archive),
            Path::new("outer.zip"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 2);
        assert_eq!(
            summary.archive_entries_scanned,
            MAX_ALLOWED_ARCHIVE_ENTRIES as u64
        );
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveEntries), 1);
    }

    #[test]
    fn scan_zip_archive_increments_depth_for_nested_archive() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let payload: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let nested = gzip_bytes(&payload);
        let archive = zip_bytes(&[("nested.gz", &nested)]);

        scan_zip_archive(
            std::io::Cursor::new(archive),
            Path::new("outer.zip"),
            &database,
            &mut scanner,
            &mut summary,
            MAX_ALLOWED_RECURSION - 1,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveDepth), 1);
    }

    #[test]
    fn scan_zip_archive_returns_error_for_malformed_zip() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();

        let err = scan_zip_archive(
            std::io::Cursor::new(b"not a zip".to_vec()),
            Path::new("bad.zip"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap_err();

        assert!(err.contains("invalid Zip archive"));
        assert_eq!(summary.archives_scanned, 1);
    }

    #[test]
    fn scan_tar_archive_scans_file_entries_and_ignores_directories() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let archive = tar_bytes(&[("dir/payload.bin", b"payload"), ("empty.bin", b"")]);

        scan_tar_archive(
            std::io::Cursor::new(archive),
            Path::new("sample.tar"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.skip_count(SkipReason::ZeroSize), 1);
        assert!(summary.detections.is_empty());
    }

    #[test]
    fn scan_tar_archive_records_error_for_malformed_entry() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();

        scan_tar_archive(
            std::io::Cursor::new(b"not a tar archive".to_vec()),
            Path::new("bad.tar"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.archive_entries_scanned, 0);
    }

    #[test]
    fn scan_tar_archive_skips_entries_declaring_too_many_bytes() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let archive =
            tar_header_declaring_size("oversized.bin", MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE + 1);

        scan_tar_archive(
            std::io::Cursor::new(archive),
            Path::new("oversized.tar"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.skip_count(SkipReason::MaxDecompressedBytes), 1);
        assert_eq!(summary.archive_entries_scanned, 0);
    }

    #[test]
    fn scan_tar_archive_applies_decompressed_size_boundary() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let archive = tar_header_declaring_size("limit.bin", MAX_ALLOWED_UNCOMPRESSED_FILE_SIZE);

        scan_tar_archive(
            std::io::Cursor::new(archive),
            Path::new("limit.tar"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.skip_count(SkipReason::MaxDecompressedBytes), 0);
        assert_eq!(summary.errors, 1);
    }

    #[test]
    fn scan_tar_archive_limits_entries_across_one_archive_tree() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let archive = tar_bytes_with_numbered_files(MAX_ALLOWED_ARCHIVE_ENTRIES + 1);

        scan_tar_archive(
            std::io::Cursor::new(archive),
            Path::new("too-many.tar"),
            &database,
            &mut scanner,
            &mut summary,
            0,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(
            summary.archive_entries_scanned,
            MAX_ALLOWED_ARCHIVE_ENTRIES as u64
        );
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveEntries), 1);
    }

    #[test]
    fn scan_tar_archive_increments_depth_for_nested_archive() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();
        let payload: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let nested = gzip_bytes(&payload);
        let archive = tar_bytes(&[("nested.gz", &nested)]);

        scan_tar_archive(
            std::io::Cursor::new(archive),
            Path::new("outer.tar"),
            &database,
            &mut scanner,
            &mut summary,
            MAX_ALLOWED_RECURSION - 1,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 1);
        assert_eq!(summary.archive_entries_scanned, 1);
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveDepth), 1);
    }

    #[test]
    fn scan_tar_archive_records_max_depth_skip_before_reading_entries() {
        let rules = non_matching_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let database = HashDatabase::default();
        let mut summary = ScanSummaryStats::new();

        scan_tar_archive(
            std::io::Cursor::new(Vec::new()),
            Path::new("too-deep.tar"),
            &database,
            &mut scanner,
            &mut summary,
            MAX_ALLOWED_RECURSION,
        )
        .unwrap();

        assert_eq!(summary.archives_scanned, 0);
        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.skip_count(SkipReason::MaxArchiveDepth), 1);
    }
}
