pub mod cli;
pub mod scanner;
pub mod updater;

use crate::scanner::{database::load_hash_database, scan::scan_path};
use crate::updater::update::update_using_malware_bazaar;

use crate::cli::{Command, parse_args};

fn main() {
    eprintln!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    match parse_args(std::env::args()) {
        Ok(Command::Scan(args)) => {
            eprintln!("Loading {:#?} signature database...", args.database);
            let hash_database = load_hash_database(args.database).unwrap();
            eprintln!("{:?} signatures loaded", hash_database.len());
            let summary = scan_path(&args.target, &hash_database);
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
            match update_using_malware_bazaar(&args.auth_key, "100", args.database) {
                Ok(inserted) => {
                    println!("Processed {:?} signatures from Malware Bazaar", inserted);
                    std::process::exit(0);
                }
                Err(err) => {
                    println!("Error - Failed to update from Malware Bazaar: {}", err);
                    std::process::exit(2);
                }
            }
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
  galen scan <target> [--db <path>]
  galen update [--source <name>]
  galen --help

Commands:
  scan      Scan a file or directory
  update    Update local signatures

Options:
  -d, --db <path>        Path to signature database
  -s, --source <name>    Signature source
  -h, --help             Show this help text
"
    );
}
