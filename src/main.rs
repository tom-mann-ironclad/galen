pub mod cli;
pub mod scanner;

use crate::scanner::{
    database::load_hash_database,
    scan::{ScanResult, scan_file},
};

use crate::cli::{Command, parse_args};

fn main() {
    eprintln!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    match parse_args(std::env::args()) {
        Ok(Command::Scan(args)) => {
            eprintln!("Loading {:#?} signature database...", args.database);
            let hash_database = load_hash_database(args.database).unwrap();
            eprintln!("{:?} signatures loaded", hash_database.len());
            let result = scan_file(args.target, &hash_database).unwrap();
            match result {
                ScanResult::Clean => {
                    println!("No known threats detected.");
                    std::process::exit(0);
                }
                ScanResult::KnownHash { family } => {
                    println!(
                        "THREAT DETECTED: known hash {}",
                        family
                            .as_deref()
                            .map(|name| format!("({name})"))
                            .unwrap_or_else(|| "(unknown family)".to_string())
                    );
                    std::process::exit(1);
                }
            }
        }

        Ok(Command::Update(_args)) => {
            eprintln!("Do any update please!");
            todo!();
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
