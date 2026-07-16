pub mod cli;
pub mod json;
pub mod scanner;
pub mod updater;

use std::{
    io::{self, Write},
    path::Path,
    time::Duration,
};

use crate::scanner::{
    database::load_hash_database,
    heuristics::Verdict,
    scan::scan_path,
    scan::{DetectionRecord, DetectionSurface, ScanSummaryStats, SkipReason},
    yara::load_yara_rules_cache,
};
use crate::updater::{
    update_signatures::{UpdateSignaturesError, update_signatures_using_malware_bazaar},
    update_yara_rules::{UpdateYaraRulesError, update_yara_rules},
};

use crate::cli::{Command, OutputFormat, ScanArgs, UpdateArgs, parse_args};

use crate::json::{ErrorReport, ScanReport};

const EXIT_SUCCESS: i32 = 0;
const EXIT_DETECTIONS: i32 = 1;
const EXIT_OPERATIONAL_ERROR: i32 = 2;
const YARA_MAX_SCAN_SIZE: usize = 4 * 1024 * 1024;
const YARA_SCAN_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(not(tarpaulin))]
fn main() {
    let exit_code = run_cli(std::env::args(), &mut io::stdout(), &mut io::stderr());
    std::process::exit(exit_code);
}

#[cfg(tarpaulin)]
fn main() {}

/// Run the parsed CLI command and return the process exit code.
fn run_cli<I, W, E>(args: I, stdout: &mut W, stderr: &mut E) -> i32
where
    I: IntoIterator<Item = String>,
    W: Write,
    E: Write,
{
    let _ = writeln!(
        stderr,
        "{} v{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    match parse_args(args) {
        Ok(Command::Scan(args)) => run_scan_command(&args, stdout, stderr),
        Ok(Command::Update(args)) => run_update_command(&args, &RealUpdateBackend, stdout, stderr),
        Ok(Command::Help) => match write_help(stdout) {
            Ok(()) => EXIT_SUCCESS,
            Err(_) => EXIT_OPERATIONAL_ERROR,
        },
        Err(err) => {
            let _ = writeln!(stdout, "Error: {:?}", err.to_string());
            EXIT_OPERATIONAL_ERROR
        }
    }
}

/// Load scanner state, scan the requested target, and render the chosen output format.
fn run_scan_command<W, E>(args: &ScanArgs, stdout: &mut W, stderr: &mut E) -> i32
where
    W: Write,
    E: Write,
{
    let _ = writeln!(stderr, "Loading {:#?} signature database...", args.database);
    let hash_database = match load_hash_database(&args.database) {
        Ok(database) => database,
        Err(err) => {
            let message = format!("Unable to load signature database: {}", err);
            let _ = writeln!(stderr, "{}", message);
            if args.output_format == OutputFormat::Json {
                let _ = write_json_error_report("signature_database_load_failed", message, stdout);
            }
            return EXIT_OPERATIONAL_ERROR;
        }
    };
    let _ = writeln!(stderr, "{:?} signatures loaded", hash_database.len());

    let _ = writeln!(
        stderr,
        "Loading {:#?} YARA rules cache...",
        args.yara_rules_cache
    );
    let rules = match load_yara_rules_cache(&args.yara_rules_cache) {
        Ok(cache) => cache,
        Err(err) => {
            let message = format!("Unable to load YARA rules cache: {}", err);
            let _ = writeln!(stderr, "{}", message);
            if args.output_format == OutputFormat::Json {
                let _ = write_json_error_report("yara_rules_load_failed", message, stdout);
            }
            return EXIT_OPERATIONAL_ERROR;
        }
    };

    let mut yara_scanner = yara_x::Scanner::new(&rules);
    configure_yara_scanner(&mut yara_scanner);
    let _ = writeln!(stderr, "{:?} rules loaded", rules.iter().len());

    let _ = writeln!(stderr, "Starting scan...");
    let start_time = std::time::Instant::now();
    let summary = scan_path(&args.target, &hash_database, &mut yara_scanner);
    let scan_time = start_time.elapsed();

    match args.output_format {
        OutputFormat::Human => {
            write_human_scan_report(&summary, scan_time, stdout).unwrap_or(EXIT_OPERATIONAL_ERROR)
        }
        OutputFormat::Json => write_json_scan_report(&summary, scan_time, stdout, stderr)
            .unwrap_or(EXIT_OPERATIONAL_ERROR),
    }
}

/// Write a JSON operational error report to stdout.
fn write_json_error_report<W>(kind: &'static str, message: String, stdout: &mut W) -> io::Result<()>
where
    W: Write,
{
    let report = ErrorReport::new(kind, message);

    writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(&report).map_err(io::Error::other)?
    )
}

/// Apply the scanner limits used by the command-line scan path.
fn configure_yara_scanner(scanner: &mut yara_x::Scanner) {
    scanner
        .fast_scan(true)
        .max_matches_per_pattern(8)
        .max_scan_size(YARA_MAX_SCAN_SIZE)
        .use_mmap(false)
        .set_timeout(YARA_SCAN_TIMEOUT);
}

/// Write the human scan report to stdout and return the intended exit code.
fn write_human_scan_report<W>(
    summary: &ScanSummaryStats,
    scan_time: Duration,
    output: &mut W,
) -> io::Result<i32>
where
    W: Write,
{
    writeln!(output)?;
    if !summary.yara_rules_triggered.is_empty() {
        writeln!(
            output,
            "{} {} triggered:",
            summary.yara_rules_triggered.len(),
            pluralise(
                summary.yara_rules_triggered.len() as u64,
                "YARA rule",
                "YARA rules"
            )
        )?;

        let mut rules: Vec<_> = summary.yara_rules_triggered.iter().collect();
        rules.sort_by_key(|(rule, _count)| rule.as_str());

        for (rule, count) in rules {
            writeln!(
                output,
                "  {}: {} {}",
                rule,
                count,
                pluralise(*count as u64, "file", "files")
            )?;
        }
    }

    writeln!(output)?;
    writeln!(output, "Detections:")?;
    let visible_detection_records = visible_human_detections(summary);

    for record in &visible_detection_records {
        write!(output, "{record}")?;
    }

    if summary.errors > 0 {
        writeln!(output, "Errors: {}", summary.errors)?;
        return Ok(EXIT_OPERATIONAL_ERROR);
    }

    writeln!(output, "----------- SCAN SUMMARY -----------")?;
    writeln!(
        output,
        "Scanned {} {}",
        summary.total_files_scanned(),
        pluralise(summary.total_files_scanned(), "file", "files")
    )?;
    writeln!(
        output,
        "  {}: {}",
        pluralise(
            summary.filesystem_files_scanned,
            "filesystem file",
            "filesystem files"
        ),
        summary.filesystem_files_scanned
    )?;
    writeln!(
        output,
        "  {}: {}",
        pluralise(
            summary.archive_entries_scanned,
            "archive entry",
            "archive entries"
        ),
        summary.archive_entries_scanned
    )?;
    writeln!(
        output,
        "Scanned {}: {}",
        pluralise(summary.archives_scanned, "archive", "archives"),
        summary.archives_scanned
    )?;
    if summary.files_skipped > 0 {
        writeln!(
            output,
            "Skipped {} {}",
            summary.files_skipped,
            pluralise(summary.files_skipped, "file", "files")
        )?;

        for reason in SkipReason::ALL {
            let count = summary.skip_count(reason);
            if count > 0 {
                writeln!(output, "  {}: {}", reason.label(), count)?;
            }
        }
    }

    let filesystem_path_detections = visible_detection_records
        .iter()
        .filter(|record| record.is_filesystem_path())
        .count();

    let archive_path_detections = visible_detection_records
        .iter()
        .filter(|record| record.is_archive_path())
        .count();

    writeln!(
        output,
        "{}: {}",
        pluralise(
            visible_detection_records.len() as u64,
            "Detection record",
            "Detection records"
        ),
        visible_detection_records.len()
    )?;
    if !summary.detections.is_empty() {
        writeln!(
            output,
            "  {}: {}",
            pluralise(
                filesystem_path_detections as u64,
                DetectionSurface::FileSystemFile.label(),
                "filesystem files"
            ),
            filesystem_path_detections
        )?;
        writeln!(
            output,
            "  {}: {}",
            pluralise(
                archive_path_detections as u64,
                DetectionSurface::ArchiveEntry.label(),
                "archive entries"
            ),
            archive_path_detections
        )?;
    }
    writeln!(output, "Scan time: {:?}", scan_time)?;

    if visible_detection_records.is_empty() {
        Ok(EXIT_SUCCESS)
    } else {
        Ok(EXIT_DETECTIONS)
    }
}

/// Helper function to pluralise any strings.
fn pluralise<'a>(count: u64, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

/// Select human-visible detections while suppressing child archive containers.
fn visible_human_detections(summary: &ScanSummaryStats) -> Vec<&DetectionRecord> {
    summary
        .detections
        .iter()
        .filter(|record| {
            record.verdict >= Verdict::Suspicious
                && should_display_detection(record, &summary.detections)
        })
        .collect()
}

/// Write the JSON scan report to stdout and operational errors to stderr.
fn write_json_scan_report<W, E>(
    summary: &ScanSummaryStats,
    scan_time: Duration,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32>
where
    W: Write,
    E: Write,
{
    let report = ScanReport::from_summary(summary, scan_time);

    writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(&report).map_err(io::Error::other)?
    )?;

    if summary.errors > 0 {
        writeln!(stderr, "Errors: {}", summary.errors)?;
        return Ok(EXIT_OPERATIONAL_ERROR);
    }

    if !visible_human_detections(summary).is_empty() {
        Ok(EXIT_DETECTIONS)
    } else {
        Ok(EXIT_SUCCESS)
    }
}

/// Backend boundary for update side effects so command handling can be unit tested.
trait UpdateBackend {
    /// Update malware signatures and return the number of processed rows.
    fn update_signatures(&self, args: &UpdateArgs) -> Result<usize, UpdateSignaturesError>;

    /// Update compiled YARA rules and return the number of compiled rules.
    fn update_yara_rules(&self, args: &UpdateArgs) -> Result<usize, UpdateYaraRulesError>;
}

/// Backend used in production code.
struct RealUpdateBackend;

#[cfg(not(tarpaulin))]
impl UpdateBackend for RealUpdateBackend {
    fn update_signatures(&self, args: &UpdateArgs) -> Result<usize, UpdateSignaturesError> {
        update_signatures_using_malware_bazaar(&args.auth_key, "100", &args.database)
    }

    fn update_yara_rules(&self, args: &UpdateArgs) -> Result<usize, UpdateYaraRulesError> {
        update_yara_rules(&args.yara_rules_path, &args.yara_rules_cache)
    }
}

#[cfg(tarpaulin)]
impl UpdateBackend for RealUpdateBackend {
    fn update_signatures(&self, _args: &UpdateArgs) -> Result<usize, UpdateSignaturesError> {
        Err(UpdateSignaturesError::NetworkUpdateDisabled)
    }

    fn update_yara_rules(&self, _args: &UpdateArgs) -> Result<usize, UpdateYaraRulesError> {
        Err(UpdateYaraRulesError::YaraUpdateDisabled)
    }
}

/// Run the update command while preserving stdout/stderr behavior.
fn run_update_command<W, E, B>(
    args: &UpdateArgs,
    backend: &B,
    stdout: &mut W,
    stderr: &mut E,
) -> i32
where
    W: Write,
    E: Write,
    B: UpdateBackend,
{
    let _ = writeln!(stderr, "Updating malware signatures...");
    match backend.update_signatures(args) {
        Ok(inserted) => {
            let _ = writeln!(
                stdout,
                "Processed {:?} signatures from Malware Bazaar",
                inserted
            );
        }
        Err(err) => {
            let _ = writeln!(
                stdout,
                "Error - Failed to update signatures from Malware Bazaar: {}",
                err
            );
            return EXIT_OPERATIONAL_ERROR;
        }
    };

    let _ = writeln!(stderr, "Updating YARA rules...");
    match backend.update_yara_rules(args) {
        Ok(compiled) => {
            let _ = writeln!(stdout, "Compiled {:?} rules into cache", compiled);
        }
        Err(err) => {
            let _ = writeln!(stdout, "Error - Failed to update YARA rules: {}", err);
            return EXIT_OPERATIONAL_ERROR;
        }
    };

    EXIT_SUCCESS
}

/// Return the static command-line help text.
fn help_text() -> &'static str {
    "\
Usage:
  galen scan <target> [--database <path>] [--yara-cache <path>] [--output <format>]
  galen update
  galen --help

Commands:
  scan      Scan a file or directory
  update    Update local signatures

Options:
  -d, --database <path>   Path to signature database
  -y, --yara-cache <path> Path to YARA rules directory
  -o, --output            The output format for scan results: human (default) or json  
  -h, --help              Show this help text
"
}

/// Utility function to write the help options to stdout.
fn write_help<W>(output: &mut W) -> io::Result<()>
where
    W: Write,
{
    write!(output, "{}", help_text())
}

/// Helper function to determine if a path has any child detection records.
fn has_child_detection(container: &Path, records: &[DetectionRecord]) -> bool {
    let prefix = format!("{}!/", container.to_string_lossy());

    records
        .iter()
        .any(|record| record.path.to_string_lossy().starts_with(&prefix))
}

/// Function to determine which detection records should be displayed.
pub fn should_display_detection(record: &DetectionRecord, records: &[DetectionRecord]) -> bool {
    match record.surface {
        DetectionSurface::FileSystemFile => true,
        DetectionSurface::ArchiveEntry => true,
        DetectionSurface::ArchiveContainer => !has_child_detection(&record.path, records),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::heuristics::{
        Confidence, Finding, FindingId, MAX_FINDINGS_PER_FILE, Verdict,
    };
    use std::path::PathBuf;

    /// Backend used in testing as a mock.
    struct FakeUpdateBackend {
        signatures: Result<usize, UpdateSignaturesError>,
        yara_rules: Result<usize, UpdateYaraRulesError>,
    }

    impl UpdateBackend for FakeUpdateBackend {
        fn update_signatures(&self, _args: &UpdateArgs) -> Result<usize, UpdateSignaturesError> {
            self.signatures.clone()
        }

        fn update_yara_rules(&self, _args: &UpdateArgs) -> Result<usize, UpdateYaraRulesError> {
            self.yara_rules.clone()
        }
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn update_args() -> UpdateArgs {
        UpdateArgs {
            database: PathBuf::from("signatures.sqlite"),
            auth_key: "test-key".to_string(),
            yara_rules_path: PathBuf::from("rules"),
            yara_rules_cache: PathBuf::from("rules.yaraxc"),
        }
    }

    fn empty_hash_database(path: &Path) {
        let connection = rusqlite::Connection::open(path).unwrap();
        connection
            .execute("CREATE TABLE malware_hashes (sha256 BLOB NOT NULL)", [])
            .unwrap();
    }

    fn write_yara_cache(path: &Path, source: &str) {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source).unwrap();
        let rules = compiler.build();
        let file = std::fs::File::create(path).unwrap();
        let writer = std::io::BufWriter::new(file);
        rules.serialize_into(writer).unwrap();
    }

    fn scan_args(target: PathBuf, database: PathBuf, yara_rules_cache: PathBuf) -> ScanArgs {
        ScanArgs {
            target,
            database,
            yara_rules_cache,
            output_format: OutputFormat::Human,
        }
    }

    fn finding(score: u16) -> Finding {
        Finding {
            id: FindingId::KnownHash,
            score,
            confidence: Confidence::High,
        }
    }

    fn detection(path: &str, surface: DetectionSurface, verdict: Verdict) -> DetectionRecord {
        let mut findings = [None; MAX_FINDINGS_PER_FILE];
        findings[0] = Some(finding(100));

        DetectionRecord {
            path: PathBuf::from(path),
            score: 100,
            verdict,
            findings,
            surface,
        }
    }

    fn assert_output_line(output: &str, expected: &str) {
        assert!(
            output.lines().any(|line| line == expected),
            "expected output line {expected:?}\noutput:\n{output}"
        );
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("forced write failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn help_text_contains_usage_commands_and_options() {
        let help = help_text();

        assert!(help.contains("Usage:"));
        assert!(help.contains("galen scan <target>"));
        assert!(help.contains("galen update"));
        assert!(help.contains("--database"));
        assert!(help.contains("--yara-cache"));
        assert!(help.contains("--output"));
        assert!(!help.trim().is_empty());
    }

    #[test]
    fn help_text_matches_expected_output() {
        assert_eq!(
            help_text(),
            "\
Usage:
  galen scan <target> [--database <path>] [--yara-cache <path>] [--output <format>]
  galen update
  galen --help

Commands:
  scan      Scan a file or directory
  update    Update local signatures

Options:
  -d, --database <path>   Path to signature database
  -y, --yara-cache <path> Path to YARA rules directory
  -o, --output            The output format for scan results: human (default) or json  
  -h, --help              Show this help text
"
        );
    }

    #[test]
    fn run_cli_writes_help_to_stdout_and_version_to_stderr() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_cli(args(&["galen", "--help"]), &mut stdout, &mut stderr);

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert!(String::from_utf8(stdout).unwrap().contains("Usage:"));
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains(env!("CARGO_PKG_NAME"))
        );
    }

    #[test]
    fn run_cli_help_command_writes_exact_help_and_success_exit() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_cli(args(&["galen", "help"]), &mut stdout, &mut stderr);

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert_eq!(String::from_utf8(stdout).unwrap(), help_text());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            format!(
                "{} v{}\n",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn run_cli_help_returns_operational_error_when_help_text_cannot_be_written() {
        let mut stdout = FailingWriter;
        let mut stderr = Vec::new();

        let exit_code = run_cli(args(&["galen", "--help"]), &mut stdout, &mut stderr);

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            format!(
                "{} v{}\n",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn run_cli_writes_parse_errors_to_stdout() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_cli(args(&["galen"]), &mut stdout, &mut stderr);

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert!(
            String::from_utf8(stdout)
                .unwrap()
                .contains("No arguments provided")
        );
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains(env!("CARGO_PKG_NAME"))
        );
    }

    #[test]
    fn human_scan_report_writes_report_to_stdout_and_returns_success() {
        let mut summary = ScanSummaryStats::new();
        summary.filesystem_files_scanned = 1;
        let mut output = Vec::new();

        let exit_code =
            write_human_scan_report(&summary, Duration::from_millis(25), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert!(output.contains("Detections:"));
        assert!(output.contains("Scanned 1 file"));
        assert!(output.contains("Scan time: 25ms"));
    }

    #[test]
    fn human_scan_report_returns_detection_exit_for_visible_detection() {
        let mut summary = ScanSummaryStats::new();
        summary.filesystem_files_scanned = 1;
        summary.detections = vec![detection(
            "payload.bin",
            DetectionSurface::FileSystemFile,
            Verdict::Malicious,
        )];
        let mut output = Vec::new();

        let exit_code =
            write_human_scan_report(&summary, Duration::from_millis(1), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(exit_code, EXIT_DETECTIONS);
        assert!(output.contains("[malicious] payload.bin"));
        assert!(output.contains("Detection record: 1"));
    }

    #[test]
    fn human_scan_report_counts_filesystem_and_archive_detections() {
        let mut summary = ScanSummaryStats::new();
        summary.filesystem_files_scanned = 1;
        summary.archive_entries_scanned = 1;
        summary.record_skip(SkipReason::ZeroSize);
        summary.record_skip(SkipReason::PermissionDenied);
        summary.detections = vec![
            detection(
                "payload.bin",
                DetectionSurface::FileSystemFile,
                Verdict::Malicious,
            ),
            detection(
                "archive.zip!/payload.bin",
                DetectionSurface::ArchiveEntry,
                Verdict::Malicious,
            ),
        ];
        let mut output = Vec::new();

        let exit_code =
            write_human_scan_report(&summary, Duration::from_millis(1), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(exit_code, EXIT_DETECTIONS);
        assert!(output.contains("Skipped 2 files"));
        assert!(output.contains("zero-size: 1"));
        assert!(output.contains("permission denied: 1"));
        assert!(output.contains("Detection records: 2"));
        assert!(output.contains("filesystem file: 1"));
        assert!(output.contains("archive entry: 1"));
    }

    #[test]
    fn human_scan_report_uses_singular_count_labels() {
        let mut summary = ScanSummaryStats::new();
        summary.filesystem_files_scanned = 1;
        summary.archives_scanned = 1;
        summary.record_skip(SkipReason::ZeroSize);
        summary
            .yara_rules_triggered
            .insert("one_rule".to_string(), 1);
        summary.detections = vec![detection(
            "payload.bin",
            DetectionSurface::FileSystemFile,
            Verdict::Malicious,
        )];
        let mut output = Vec::new();

        let exit_code =
            write_human_scan_report(&summary, Duration::from_millis(1), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(exit_code, EXIT_DETECTIONS);
        assert_output_line(&output, "1 YARA rule triggered:");
        assert_output_line(&output, "  one_rule: 1 file");
        assert_output_line(&output, "Scanned 1 file");
        assert_output_line(&output, "  filesystem file: 1");
        assert_output_line(&output, "Scanned archive: 1");
        assert_output_line(&output, "Skipped 1 file");
        assert_output_line(&output, "Detection record: 1");
    }

    #[test]
    fn human_scan_report_uses_plural_count_labels() {
        let mut summary = ScanSummaryStats::new();
        summary.filesystem_files_scanned = 2;
        summary.archive_entries_scanned = 2;
        summary.archives_scanned = 2;
        summary.record_skip(SkipReason::ZeroSize);
        summary.record_skip(SkipReason::PermissionDenied);
        summary.yara_rules_triggered.insert("a_rule".to_string(), 2);
        summary.yara_rules_triggered.insert("b_rule".to_string(), 2);
        summary.detections = vec![
            detection(
                "one.bin",
                DetectionSurface::FileSystemFile,
                Verdict::Malicious,
            ),
            detection(
                "two.bin",
                DetectionSurface::FileSystemFile,
                Verdict::Malicious,
            ),
            detection(
                "archive.zip!/one.bin",
                DetectionSurface::ArchiveEntry,
                Verdict::Malicious,
            ),
            detection(
                "archive.zip!/two.bin",
                DetectionSurface::ArchiveEntry,
                Verdict::Malicious,
            ),
        ];
        let mut output = Vec::new();

        let exit_code =
            write_human_scan_report(&summary, Duration::from_millis(1), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(exit_code, EXIT_DETECTIONS);
        assert_output_line(&output, "2 YARA rules triggered:");
        assert_output_line(&output, "  a_rule: 2 files");
        assert_output_line(&output, "  b_rule: 2 files");
        assert_output_line(&output, "Scanned 4 files");
        assert_output_line(&output, "  filesystem files: 2");
        assert_output_line(&output, "  archive entries: 2");
        assert_output_line(&output, "Scanned archives: 2");
        assert_output_line(&output, "Skipped 2 files");
        assert_output_line(&output, "Detection records: 4");
    }

    #[test]
    fn human_scan_report_lists_triggered_yara_rules_in_order() {
        let mut summary = ScanSummaryStats::new();
        summary.filesystem_files_scanned = 2;
        summary.yara_rules_triggered.insert("z_rule".to_string(), 1);
        summary.yara_rules_triggered.insert("a_rule".to_string(), 2);
        let mut output = Vec::new();

        let exit_code =
            write_human_scan_report(&summary, Duration::from_millis(1), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert!(output.contains("2 YARA rules triggered"));
        assert!(output.find("a_rule").unwrap() < output.find("z_rule").unwrap());
    }

    #[test]
    fn human_scan_report_excludes_suppressed_archive_container_counts() {
        let mut summary = ScanSummaryStats::new();
        summary.detections = vec![
            detection(
                "archive.zip",
                DetectionSurface::ArchiveContainer,
                Verdict::Malicious,
            ),
            detection(
                "archive.zip!/payload.bin",
                DetectionSurface::ArchiveEntry,
                Verdict::Malicious,
            ),
        ];
        let mut output = Vec::new();

        let exit_code =
            write_human_scan_report(&summary, Duration::from_millis(1), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(exit_code, EXIT_DETECTIONS);
        assert!(!output.contains("[malicious] archive.zip\n"));
        assert!(output.contains("[malicious] archive.zip!/payload.bin"));
        assert!(output.contains("Detection record: 1"));
        assert!(output.contains("archive entry: 1"));
    }

    #[test]
    fn human_scan_report_returns_operational_error_before_summary() {
        let mut summary = ScanSummaryStats::new();
        summary.errors = 1;
        let mut output = Vec::new();

        let exit_code =
            write_human_scan_report(&summary, Duration::from_millis(1), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert!(output.contains("Errors: 1"));
        assert!(!output.contains("SCAN SUMMARY"));
    }

    #[test]
    fn json_scan_report_keeps_json_on_stdout_and_errors_on_stderr() {
        let mut summary = ScanSummaryStats::new();
        summary.errors = 2;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            write_json_scan_report(&summary, Duration::from_millis(5), &mut stdout, &mut stderr)
                .unwrap();
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert!(stdout.contains("\"schema_version\": 1"));
        assert!(stdout.contains("\"scan_time_ms\": 5.0"));
        assert_eq!(stderr, "Errors: 2\n");
    }

    #[test]
    fn json_scan_report_returns_detection_exit_for_visible_detection() {
        let mut summary = ScanSummaryStats::new();
        summary.detections = vec![detection(
            "payload.bin",
            DetectionSurface::FileSystemFile,
            Verdict::Malicious,
        )];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            write_json_scan_report(&summary, Duration::from_millis(1), &mut stdout, &mut stderr)
                .unwrap();

        assert_eq!(exit_code, EXIT_DETECTIONS);
        assert!(String::from_utf8(stderr).unwrap().is_empty());
    }

    #[test]
    fn json_scan_report_returns_success_for_informational_only_detection() {
        let mut summary = ScanSummaryStats::new();
        summary.detections = vec![detection(
            "info.bin",
            DetectionSurface::FileSystemFile,
            Verdict::Informational,
        )];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            write_json_scan_report(&summary, Duration::from_millis(1), &mut stdout, &mut stderr)
                .unwrap();

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert!(String::from_utf8(stderr).unwrap().is_empty());
    }

    #[test]
    fn json_scan_report_returns_success_for_suppressed_container_without_visible_child() {
        let mut summary = ScanSummaryStats::new();
        summary.detections = vec![
            detection(
                "archive.zip",
                DetectionSurface::ArchiveContainer,
                Verdict::Malicious,
            ),
            detection(
                "archive.zip!/info.bin",
                DetectionSurface::ArchiveEntry,
                Verdict::Informational,
            ),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            write_json_scan_report(&summary, Duration::from_millis(1), &mut stdout, &mut stderr)
                .unwrap();

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert!(visible_human_detections(&summary).is_empty());
        assert!(String::from_utf8(stderr).unwrap().is_empty());
    }

    #[test]
    fn json_scan_report_returns_success_for_clean_summary() {
        let summary = ScanSummaryStats::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            write_json_scan_report(&summary, Duration::from_millis(1), &mut stdout, &mut stderr)
                .unwrap();

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert!(
            String::from_utf8(stdout)
                .unwrap()
                .contains("\"scanned_files\": 0")
        );
        assert!(String::from_utf8(stderr).unwrap().is_empty());
    }

    #[test]
    fn human_and_json_scan_reports_use_aligned_exit_codes() {
        let cases = [
            ("clean", ScanSummaryStats::new()),
            {
                let mut summary = ScanSummaryStats::new();
                summary.detections = vec![detection(
                    "info.bin",
                    DetectionSurface::FileSystemFile,
                    Verdict::Informational,
                )];
                ("informational", summary)
            },
            {
                let mut summary = ScanSummaryStats::new();
                summary.detections = vec![detection(
                    "payload.bin",
                    DetectionSurface::FileSystemFile,
                    Verdict::Malicious,
                )];
                ("visible_detection", summary)
            },
            {
                let mut summary = ScanSummaryStats::new();
                summary.detections = vec![
                    detection(
                        "archive.zip",
                        DetectionSurface::ArchiveContainer,
                        Verdict::Malicious,
                    ),
                    detection(
                        "archive.zip!/info.bin",
                        DetectionSurface::ArchiveEntry,
                        Verdict::Informational,
                    ),
                ];
                ("suppressed_container", summary)
            },
            {
                let mut summary = ScanSummaryStats::new();
                summary.errors = 1;
                ("operational_error", summary)
            },
        ];

        for (name, summary) in cases {
            let mut human_stdout = Vec::new();
            let mut json_stdout = Vec::new();
            let mut json_stderr = Vec::new();

            let human_exit =
                write_human_scan_report(&summary, Duration::from_millis(1), &mut human_stdout)
                    .unwrap();
            let json_exit = write_json_scan_report(
                &summary,
                Duration::from_millis(1),
                &mut json_stdout,
                &mut json_stderr,
            )
            .unwrap();

            assert_eq!(human_exit, json_exit, "{name}");
        }
    }

    #[test]
    fn visible_human_detections_excludes_low_verdict_records() {
        let mut summary = ScanSummaryStats::new();
        summary.detections = vec![
            detection(
                "info.bin",
                DetectionSurface::FileSystemFile,
                Verdict::Informational,
            ),
            detection(
                "suspicious.bin",
                DetectionSurface::FileSystemFile,
                Verdict::Suspicious,
            ),
        ];

        let visible = visible_human_detections(&summary);

        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].path, PathBuf::from("suspicious.bin"));
    }

    #[test]
    fn run_scan_command_scans_clean_target_in_human_mode() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("signatures.sqlite");
        let yara_cache = root.path().join("rules.yaraxc");
        let target = root.path().join("payload.bin");
        empty_hash_database(&database);
        write_yara_cache(&yara_cache, "rule never_matches { condition: false }");
        std::fs::write(&target, b"clean payload").unwrap();
        let args = scan_args(target, database, yara_cache);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_scan_command(&args, &mut stdout, &mut stderr);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert!(stdout.contains("Scanned 1 file"));
        assert!(stdout.contains("Detection records: 0"));
        assert!(stderr.contains("Loading"));
        assert!(stderr.contains("Starting scan"));
    }

    #[test]
    fn run_scan_command_scans_clean_target_in_json_mode() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("signatures.sqlite");
        let yara_cache = root.path().join("rules.yaraxc");
        let target = root.path().join("payload.bin");
        empty_hash_database(&database);
        write_yara_cache(&yara_cache, "rule never_matches { condition: false }");
        std::fs::write(&target, b"clean payload").unwrap();
        let mut args = scan_args(target, database, yara_cache);
        args.output_format = OutputFormat::Json;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_scan_command(&args, &mut stdout, &mut stderr);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert!(stdout.contains("\"schema_version\": 1"));
        assert!(stdout.contains("\"status\": \"ok\""));
        assert!(stdout.contains("\"scanned_files\": 1"));
        assert!(!stdout.contains("Starting scan"));
        assert!(stderr.contains("Starting scan"));
    }

    #[test]
    fn run_scan_command_reports_database_load_errors() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("payload.bin");
        let args = scan_args(
            target,
            root.path().join("missing.sqlite"),
            root.path().join("missing.yaraxc"),
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_scan_command(&args, &mut stdout, &mut stderr);
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert!(stderr.contains("Unable to load signature database"));
    }

    #[test]
    fn run_scan_command_reports_database_load_errors_as_json() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("payload.bin");
        let mut args = scan_args(
            target,
            root.path().join("missing.sqlite"),
            root.path().join("missing.yaraxc"),
        );
        args.output_format = OutputFormat::Json;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_scan_command(&args, &mut stdout, &mut stderr);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert!(stdout.contains("\"schema_version\": 1"));
        assert!(stdout.contains("\"status\": \"error\""));
        assert!(stdout.contains("\"kind\": \"signature_database_load_failed\""));
        assert!(stdout.contains("\"message\": \"Unable to load signature database:"));
        assert!(stderr.contains("Unable to load signature database"));
    }

    #[test]
    fn run_scan_command_reports_yara_cache_load_errors() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("signatures.sqlite");
        let target = root.path().join("payload.bin");
        empty_hash_database(&database);
        let args = scan_args(target, database, root.path().join("missing.yaraxc"));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_scan_command(&args, &mut stdout, &mut stderr);
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert!(stderr.contains("Unable to load YARA rules cache"));
    }

    #[test]
    fn run_scan_command_reports_yara_cache_load_errors_as_json() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("signatures.sqlite");
        let target = root.path().join("payload.bin");
        empty_hash_database(&database);
        let mut args = scan_args(target, database, root.path().join("missing.yaraxc"));
        args.output_format = OutputFormat::Json;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_scan_command(&args, &mut stdout, &mut stderr);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert!(stdout.contains("\"schema_version\": 1"));
        assert!(stdout.contains("\"status\": \"error\""));
        assert!(stdout.contains("\"kind\": \"yara_rules_load_failed\""));
        assert!(stdout.contains("\"message\": \"Unable to load YARA rules cache:"));
        assert!(stderr.contains("Unable to load YARA rules cache"));
    }

    #[test]
    fn update_command_preserves_stdout_and_stderr_split() {
        let backend = FakeUpdateBackend {
            signatures: Ok(3),
            yara_rules: Ok(2),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_update_command(&update_args(), &backend, &mut stdout, &mut stderr);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_SUCCESS);
        assert!(stdout.contains("Processed 3 signatures from Malware Bazaar"));
        assert!(stdout.contains("Compiled 2 rules into cache"));
        assert!(stderr.contains("Updating malware signatures"));
        assert!(stderr.contains("Updating YARA rules"));
    }

    #[test]
    fn update_command_stops_when_signature_update_fails() {
        let backend = FakeUpdateBackend {
            signatures: Err(UpdateSignaturesError::RecentFetch(
                "network unavailable".to_string(),
            )),
            yara_rules: Ok(2),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_update_command(&update_args(), &backend, &mut stdout, &mut stderr);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert!(stdout.contains("Failed to update signatures"));
        assert!(!stdout.contains("Compiled 2 rules"));
        assert!(stderr.contains("Updating malware signatures"));
        assert!(!stderr.contains("Updating YARA rules"));
    }

    #[test]
    fn update_command_reports_yara_update_failure() {
        let backend = FakeUpdateBackend {
            signatures: Ok(3),
            yara_rules: Err(UpdateYaraRulesError::RuleCompile {
                path: PathBuf::from("rules/bad.yar"),
                error: "invalid rule".to_string(),
            }),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_update_command(&update_args(), &backend, &mut stdout, &mut stderr);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();

        assert_eq!(exit_code, EXIT_OPERATIONAL_ERROR);
        assert!(stdout.contains("Processed 3 signatures"));
        assert!(stdout.contains("Failed to update YARA rules"));
        assert!(stderr.contains("Updating malware signatures"));
        assert!(stderr.contains("Updating YARA rules"));
    }

    #[cfg(tarpaulin)]
    #[test]
    fn real_update_backend_reports_disabled_updates_under_coverage() {
        let backend = RealUpdateBackend;
        let args = update_args();

        assert_eq!(
            backend.update_signatures(&args).unwrap_err(),
            UpdateSignaturesError::NetworkUpdateDisabled
        );
        assert_eq!(
            backend.update_yara_rules(&args).unwrap_err(),
            UpdateYaraRulesError::YaraUpdateDisabled
        );
    }

    #[test]
    fn archive_container_display_depends_on_child_detection_presence() {
        let orphan_container = detection(
            "sample.zip",
            DetectionSurface::ArchiveContainer,
            Verdict::Malicious,
        );
        let child = detection(
            "sample.zip!/payload.bin",
            DetectionSurface::ArchiveEntry,
            Verdict::Malicious,
        );

        assert!(should_display_detection(
            &orphan_container,
            std::slice::from_ref(&orphan_container)
        ));
        let records = [
            detection(
                "sample.zip",
                DetectionSurface::ArchiveContainer,
                Verdict::Malicious,
            ),
            child,
        ];
        assert!(!should_display_detection(&records[0], &records));
    }
}
