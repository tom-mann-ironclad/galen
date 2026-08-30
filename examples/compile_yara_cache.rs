//! Compiles a directory of YARA rules into a cache, without requiring a
//! Malware Bazaar auth key.
//!
//! `galen update` compiles YARA rules as one step of a combined signature
//! and rule update, and bails out before reaching that step if the
//! Malware Bazaar signature update fails (see `run_update_command` in
//! `src/main.rs`). CI tooling that only wants a real, representative YARA
//! ruleset compiled - for example nightly benchmarking - has no signature
//! update to run and no auth key to supply, so it calls the library
//! function directly instead.

use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let (Some(rules_dir), Some(cache_path)) = (args.next(), args.next()) else {
        eprintln!("usage: compile_yara_cache <rules-dir> <cache-path>");
        return ExitCode::FAILURE;
    };

    match galen::updater::update_yara_rules::update_yara_rules(
        &PathBuf::from(rules_dir),
        &PathBuf::from(cache_path),
    ) {
        Ok(count) => {
            println!("Compiled {count} YARA rule files into cache");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("Failed to compile YARA rules: {err}");
            ExitCode::FAILURE
        }
    }
}
