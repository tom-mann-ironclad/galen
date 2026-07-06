pub mod cli;
pub mod json;
pub mod scanner;
pub mod updater;

use std::path::Path;

use crate::scanner::{
    database::load_hash_database,
    heuristics::Verdict,
    scan::SkipReason,
    scan::scan_path,
    scan::{DetectionRecord, DetectionSurface},
    yara::load_yara_rules_cache,
};
use crate::updater::{
    update_signatures::update_signatures_using_malware_bazaar, update_yara_rules::update_yara_rules,
};

use crate::cli::{Command, OutputFormat, parse_args};

use crate::json::ScanReport;

fn main() {
    eprintln!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    match parse_args(std::env::args()) {
        Ok(Command::Scan(args)) => {
            eprintln!("Loading {:#?} signature database...", args.database);
            let hash_database = match load_hash_database(args.database) {
                Ok(database) => database,
                Err(err) => {
                    eprintln!("Unable to load signature database: {}", err);
                    std::process::exit(2);
                }
            };
            eprintln!("{:?} signatures loaded", hash_database.len());

            eprintln!("Loading {:#?} YARA rules cache...", args.yara_rules_cache);
            let rules = match load_yara_rules_cache(args.yara_rules_cache) {
                Ok(cache) => cache,
                Err(err) => {
                    eprintln!("Unable to load YARA rules cache: {}", err);
                    std::process::exit(2);
                }
            };

            let mut yara_scanner = yara_x::Scanner::new(&rules);
            yara_scanner
                .fast_scan(true)
                .max_matches_per_pattern(8)
                .max_scan_size(4 * 1024 * 1024)
                .use_mmap(false)
                .set_timeout(std::time::Duration::from_secs(10));
            eprintln!("{:?} rules loaded", rules.iter().len());

            eprintln!("Starting scan...");
            let start_time = std::time::Instant::now();
            let summary = scan_path(&args.target, &hash_database, &mut yara_scanner);
            let end_time = std::time::Instant::now();
            let scan_time: std::time::Duration = end_time - start_time;
            if args.output_format == OutputFormat::Human {
                println!();
                if !summary.yara_rules_triggered.is_empty() {
                    println!(
                        "{} YARA rules triggered:",
                        summary.yara_rules_triggered.len()
                    );

                    let mut rules: Vec<_> = summary.yara_rules_triggered.iter().collect();
                    rules.sort_by_key(|(rule, _count)| rule.as_str());

                    for (rule, count) in rules {
                        println!("  {}: {} files", rule, count);
                    }
                }

                println!();
                println!("Detections:");
                let mut visible_detection_records = Vec::new();
                for record in &summary.detections {
                    if record.verdict >= Verdict::Suspicious
                        && should_display_detection(record, &summary.detections)
                    {
                        visible_detection_records.push(record);
                    }
                }

                for record in &visible_detection_records {
                    println!("{record}");
                }

                if summary.errors > 0 {
                    println!("Errors: {}", summary.errors);
                    std::process::exit(2);
                }

                println!("----------- SCAN SUMMARY -----------");
                println!("Scanned {} files", summary.total_files_scanned());
                println!("  filesystem files: {}", summary.filesystem_files_scanned);
                println!("  archive entries: {}", summary.archive_entries_scanned);
                println!("Scanned archives: {}", summary.archives_scanned);
                if summary.files_skipped > 0 {
                    println!("Skipped {} files", summary.files_skipped);

                    for reason in SkipReason::ALL {
                        let count = summary.skip_count(reason);
                        if count > 0 {
                            println!("  {}: {}", reason.label(), count);
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

                println!("Detection records: {}", visible_detection_records.len());
                if !summary.detections.is_empty() {
                    println!(
                        "  {}: {}",
                        DetectionSurface::FileSystemFile.label(),
                        filesystem_path_detections
                    );
                    println!(
                        "  {}: {}",
                        DetectionSurface::ArchiveEntry.label(),
                        archive_path_detections
                    );
                }
                println!("Scan time: {:?}", scan_time);
                if !visible_detection_records.is_empty() {
                    std::process::exit(1);
                }
            } else if args.output_format == OutputFormat::Json {
                let report = ScanReport::from_summary(&summary, scan_time);

                println!("{}", serde_json::to_string_pretty(&report).unwrap());

                if summary.errors > 0 {
                    eprintln!("Errors: {}", summary.errors);
                    std::process::exit(2);
                }

                if !summary.detections.is_empty() {
                    std::process::exit(1);
                }
            }

            std::process::exit(0);
        }

        Ok(Command::Update(args)) => {
            eprintln!("Updating malware signatures...");
            match update_signatures_using_malware_bazaar(&args.auth_key, "100", args.database) {
                Ok(inserted) => {
                    println!("Processed {:?} signatures from Malware Bazaar", inserted);
                }
                Err(err) => {
                    println!(
                        "Error - Failed to update signatures from Malware Bazaar: {}",
                        err
                    );
                    std::process::exit(2);
                }
            };

            eprintln!("Updating YARA rules...");
            match update_yara_rules(&args.yara_rules_path, &args.yara_rules_cache) {
                Ok(compiled) => {
                    println!("Compiled {:?} rules into cache", compiled);
                }
                Err(err) => {
                    println!("Error - Failed to update YARA rules: {}", err);
                    std::process::exit(2);
                }
            };

            std::process::exit(0);
        }

        Ok(Command::Help) => {
            print_help();
            std::process::exit(0);
        }

        Err(err) => {
            println!("Error: {:?}", err);
            std::process::exit(1);
        }
    }
}

/// Utility function to print the help options.
fn print_help() {
    println!(
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
