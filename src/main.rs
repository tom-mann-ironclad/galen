pub mod cli;
pub mod scanner;
pub mod updater;

use crate::scanner::{database::load_hash_database, yara::load_yara_rules_cache, scan::scan_path};
use crate::updater::{update_signatures::update_signatures_using_malware_bazaar, update_yara_rules::update_yara_rules};

use crate::cli::{Command, parse_args};

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
            
            let summary = scan_path(&args.target, &hash_database, &mut yara_scanner);
            println!();
            println!("Scanned {} files", summary.files_scanned);
            println!("Skipped {} files", summary.files_skipped);
            println!("  zero-size {}", summary.files_skipped_zero_size);
            println!("Threats detected: {}", summary.threats_detected);

            if summary.errors > 0 {
                println!("Errors: {}", summary.errors);
                std::process::exit(2);
            }

            if summary.threats_detected > 0 {
                std::process::exit(1);
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
                    println!("Error - Failed to update signatures from Malware Bazaar: {}", err);
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
  galen scan <target> [--database <path>] [--yara-cache <path>]
  galen update
  galen --help

Commands:
  scan      Scan a file or directory
  update    Update local signatures

Options:
  -d, --database <path>   Path to signature database
  -y, --yara-cache <path> Path to YARA rules directory
  -h, --help              Show this help text
"
    );
}
