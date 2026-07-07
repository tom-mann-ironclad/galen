use std::path::PathBuf;

const DEFAULT_DATABASE: &str = "./signature_database.sqlite";
const DEFAULT_YARA_DIR: &str = "./yara/";
const DEFAULT_YARA_CACHE: &str = "./yara/compiled/galen.yaraxc";

/// Commands which the user can use with the CLI.
pub enum Command {
    Scan(ScanArgs),
    Update(UpdateArgs),
    Help,
}

/// The arguments which a `Scan` command needs.
pub struct ScanArgs {
    /// The target to be scanned.
    pub target: PathBuf,
    /// The signatures database to use.
    pub database: PathBuf,
    /// The compiled YARA rules cache.
    pub yara_rules_cache: PathBuf,
    /// The output format to be used.
    pub output_format: OutputFormat,
}

/// The arguments which an `Update` command needs.
pub struct UpdateArgs {
    /// The database to be updated.
    pub database: PathBuf,
    /// The Malware Bazaar auth key.
    pub auth_key: String,
    /// The YARA rules storage location on disk.
    pub yara_rules_path: PathBuf,
    /// The compiled YARA rules cache.
    pub yara_rules_cache: PathBuf,
}

/// The output formats supported.
#[derive(PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

impl From<String> for OutputFormat {
    fn from(string: String) -> OutputFormat {
        match string.as_str() {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Human,
        }
    }
}

/// Function to parse the arguments passed to the CLI.
pub fn parse_args<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();

    // Skip program name
    let _program = args.next();

    let Some(command) = args.next() else {
        return Err("No arguments provided".to_string());
    };

    match command.as_str() {
        "scan" => parse_scan(args),
        "update" => parse_update(args),
        "--help" | "-h" | "help" => Ok(Command::Help),
        _other => Err("Unknown command".to_string()),
    }
}

/// Function to parse the arguments of a scan command.
fn parse_scan<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let mut target: Option<PathBuf> = None;
    let mut database = PathBuf::from(DEFAULT_DATABASE);
    let mut yara_rules_cache = PathBuf::from(DEFAULT_YARA_CACHE);
    let mut output_format = OutputFormat::Human;

    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--database" | "-d" => {
                let Some(value) = args.next() else {
                    return Err("No arguments provided".to_string());
                };

                database = PathBuf::from(value);
            }

            "--yara-cache" | "-y" => {
                let Some(value) = args.next() else {
                    return Err("No arguments provided".to_string());
                };
                yara_rules_cache = PathBuf::from(value);
            }

            "--output" | "-o" => {
                let Some(value) = args.next() else {
                    return Err("No arguments provided".to_string());
                };
                output_format = OutputFormat::from(value);
            }

            value if value.starts_with("-") => {
                return Err("Unknown argument provided".to_string());
            }

            value => {
                // Guard to only allow a single target
                if target.is_some() {
                    return Err("Multiple scan targets provided".to_string());
                }

                target = Some(PathBuf::from(value));
            }
        }
    }

    // Only accept scan commands which contain a target
    let Some(target) = target else {
        return Err("No scan target provided".to_string());
    };

    Ok(Command::Scan(ScanArgs {
        target,
        database,
        yara_rules_cache,
        output_format,
    }))
}

fn parse_update<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let auth_key = match std::env::var("GALEN_AUTH_KEY") {
        Ok(key) => key,
        Err(err) => return Err(err.to_string()),
    };
    let mut args = args.into_iter();

    if let Some(arg) = args.next() {
        // Guard to catch invalid parameters
        let _value = arg.as_str();
        {
            return Err("Unknown parameter provided".to_string());
        }
    }

    Ok(Command::Update(UpdateArgs {
        database: PathBuf::from(DEFAULT_DATABASE),
        auth_key,
        yara_rules_path: PathBuf::from(DEFAULT_YARA_DIR),
        yara_rules_cache: PathBuf::from(DEFAULT_YARA_CACHE),
    }))
}

#[cfg(test)]
mod env_test_support {
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub struct GalenAuthKeyGuard {
        previous: Option<String>,
        _lock: MutexGuard<'static, ()>,
    }

    impl GalenAuthKeyGuard {
        pub fn set(value: &str) -> Self {
            let lock = ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = std::env::var("GALEN_AUTH_KEY").ok();

            // SAFETY: This module is compiled only for tests via #[cfg(test)]. Mutating
            // process environment is unsafe in Rust 2024 because other threads may read it
            // concurrently. These tests serialize all GALEN_AUTH_KEY mutations with ENV_LOCK
            // and restore the previous value while still holding that lock.
            unsafe { std::env::set_var("GALEN_AUTH_KEY", value) };

            Self {
                previous,
                _lock: lock,
            }
        }

        pub fn unset() -> Self {
            let lock = ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = std::env::var("GALEN_AUTH_KEY").ok();

            // SAFETY: This module is compiled only for tests via #[cfg(test)]. Mutating
            // process environment is unsafe in Rust 2024 because other threads may read it
            // concurrently. These tests serialize all GALEN_AUTH_KEY mutations with ENV_LOCK
            // and restore the previous value while still holding that lock.
            unsafe { std::env::remove_var("GALEN_AUTH_KEY") };

            Self {
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for GalenAuthKeyGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => {
                    // SAFETY: This test-only guard still holds ENV_LOCK during Drop, so
                    // restoration is serialized with other GALEN_AUTH_KEY test mutations.
                    unsafe { std::env::set_var("GALEN_AUTH_KEY", value) };
                }
                None => {
                    // SAFETY: This test-only guard still holds ENV_LOCK during Drop, so
                    // restoration is serialized with other GALEN_AUTH_KEY test mutations.
                    unsafe { std::env::remove_var("GALEN_AUTH_KEY") };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::env_test_support::GalenAuthKeyGuard;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn parse_error(values: &[&str]) -> String {
        match parse_args(args(values)) {
            Ok(_) => panic!("expected parse error"),
            Err(err) => err,
        }
    }

    #[test]
    fn parse_scan_uses_defaults_for_optional_paths_and_human_output() {
        let command = parse_args(args(&["galen", "scan", "target.bin"])).unwrap();

        let Command::Scan(scan) = command else {
            panic!("expected scan command");
        };

        assert_eq!(scan.target, PathBuf::from("target.bin"));
        assert_eq!(scan.database, PathBuf::from(DEFAULT_DATABASE));
        assert_eq!(scan.yara_rules_cache, PathBuf::from(DEFAULT_YARA_CACHE));
        assert!(matches!(scan.output_format, OutputFormat::Human));
    }

    #[test]
    fn parse_scan_accepts_custom_paths_and_json_output() {
        let command = parse_args(args(&[
            "galen",
            "scan",
            "--database",
            "hashes.sqlite",
            "--yara-cache",
            "rules.yaraxc",
            "--output",
            "json",
            "samples",
        ]))
        .unwrap();

        let Command::Scan(scan) = command else {
            panic!("expected scan command");
        };

        assert_eq!(scan.target, PathBuf::from("samples"));
        assert_eq!(scan.database, PathBuf::from("hashes.sqlite"));
        assert_eq!(scan.yara_rules_cache, PathBuf::from("rules.yaraxc"));
        assert!(matches!(scan.output_format, OutputFormat::Json));
    }

    #[test]
    fn parse_scan_rejects_missing_and_duplicate_targets() {
        assert_eq!(parse_error(&["galen", "scan"]), "No scan target provided");
        assert_eq!(
            parse_error(&["galen", "scan", "one", "two"]),
            "Multiple scan targets provided"
        );
    }

    #[test]
    fn parse_scan_rejects_unknown_flags_and_missing_values() {
        assert_eq!(
            parse_error(&["galen", "scan", "--unknown", "target"]),
            "Unknown argument provided"
        );
        assert_eq!(
            parse_error(&["galen", "scan", "--database"]),
            "No arguments provided"
        );
    }

    #[test]
    fn output_format_defaults_to_human_for_unknown_values() {
        assert!(matches!(
            OutputFormat::from("xml".to_string()),
            OutputFormat::Human
        ));
    }

    #[test]
    fn parse_update_uses_auth_key_from_environment_and_default_paths() {
        let _guard = GalenAuthKeyGuard::set("test-auth-key");

        let command = parse_args(args(&["galen", "update"])).unwrap();

        let Command::Update(update) = command else {
            panic!("expected update command");
        };

        assert_eq!(update.auth_key, "test-auth-key");
        assert_eq!(update.database, PathBuf::from(DEFAULT_DATABASE));
        assert_eq!(update.yara_rules_path, PathBuf::from(DEFAULT_YARA_DIR));
        assert_eq!(update.yara_rules_cache, PathBuf::from(DEFAULT_YARA_CACHE));
    }

    #[test]
    fn parse_update_rejects_unexpected_arguments() {
        let _guard = GalenAuthKeyGuard::set("test-auth-key");

        assert_eq!(
            parse_error(&["galen", "update", "--database", "custom.sqlite"]),
            "Unknown parameter provided"
        );
    }

    #[test]
    fn parse_update_requires_auth_key_environment_variable() {
        let _guard = GalenAuthKeyGuard::unset();

        let err = parse_error(&["galen", "update"]);

        assert!(err.contains("environment variable not found"));
    }
}
