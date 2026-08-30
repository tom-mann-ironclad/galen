use std::{env::VarError, fmt, path::PathBuf, time::Duration};

use crate::config::{self, ConfigOverrides};
use crate::scanner::scan::ScanConfig;

const DEFAULT_DATABASE: &str = "./signature_database.sqlite";
const DEFAULT_YARA_DIR: &str = "./yara/";
const DEFAULT_YARA_CACHE: &str = "./yara/compiled/galen.yaraxc";
pub const DEFAULT_SCAN_CONFIG: ScanConfig = ScanConfig {
    max_archive_depth: 5,
    max_archive_entries: 10_000,
    max_decompressed_file_size_bytes: 67_108_864,
    max_file_size_bytes: 67_108_864,
    zip_eocd_min_size_bytes: 22,
    zip_max_comment_size_bytes: u16::MAX as usize,
    zip64_eocd_locator_size_bytes: 20,
    retained_entry_buffer_limit_bytes: 4_194_304,
    yara_scan_timeout: Duration::from_secs(10),
};

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
    /// Resource limits applied during the scan.
    pub scan_config: ScanConfig,
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

/// Errors produced while parsing command-line arguments.
#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    NoArgumentsProvided,
    UnknownCommand,
    UnknownArgumentProvided,
    MultipleScanTargetsProvided,
    NoScanTargetProvided,
    UnknownParameterProvided,
    InvalidParameterValue(String),
    AuthKeyEnvironment(VarError),
    Config(String),
}

impl From<config::ConfigError> for CliError {
    fn from(err: config::ConfigError) -> Self {
        CliError::Config(err.to_string())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::NoArgumentsProvided => write!(formatter, "No arguments provided"),
            CliError::UnknownCommand => write!(formatter, "Unknown command"),
            CliError::UnknownArgumentProvided => write!(formatter, "Unknown argument provided"),
            CliError::MultipleScanTargetsProvided => {
                write!(formatter, "Multiple scan targets provided")
            }
            CliError::NoScanTargetProvided => write!(formatter, "No scan target provided"),
            CliError::UnknownParameterProvided => write!(formatter, "Unknown parameter provided"),
            CliError::InvalidParameterValue(parameter) => {
                write!(formatter, "Invalid value for {parameter}")
            }
            CliError::AuthKeyEnvironment(err) => write!(formatter, "{err}"),
            CliError::Config(err) => write!(formatter, "{err}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<String> for OutputFormat {
    fn from(string: String) -> OutputFormat {
        match string.as_str() {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Human,
        }
    }
}

/// Function to parse the arguments passed to the CLI.
pub fn parse_args<I>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();

    // Skip program name
    let _program = args.next();

    let Some(command) = args.next() else {
        return Err(CliError::NoArgumentsProvided);
    };

    match command.as_str() {
        "scan" => parse_scan(args),
        "update" => parse_update(args),
        "--help" | "-h" | "help" => Ok(Command::Help),
        _other => Err(CliError::UnknownCommand),
    }
}

/// Function to parse the arguments of a scan command.
fn parse_scan<I>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut target: Option<PathBuf> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut overrides = ConfigOverrides::default();

    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--database" | "-d" => {
                let Some(value) = args.next() else {
                    return Err(CliError::NoArgumentsProvided);
                };

                overrides.database = Some(PathBuf::from(value));
            }

            "--yara-cache" | "-y" => {
                let Some(value) = args.next() else {
                    return Err(CliError::NoArgumentsProvided);
                };
                overrides.yara_rules_cache = Some(PathBuf::from(value));
            }

            "--output" | "-o" => {
                let Some(value) = args.next() else {
                    return Err(CliError::NoArgumentsProvided);
                };
                overrides.output_format = Some(value);
            }

            "--config" => {
                let Some(value) = args.next() else {
                    return Err(CliError::NoArgumentsProvided);
                };
                config_path = Some(PathBuf::from(value));
            }

            "--max-archive-depth" => {
                overrides.max_archive_depth = Some(parse_usize(&mut args, &arg)?);
            }
            "--max-archive-entries" => {
                overrides.max_archive_entries = Some(parse_usize(&mut args, &arg)?);
            }
            "--max-decompressed-file-size-bytes" => {
                overrides.max_decompressed_file_size_bytes = Some(parse_u64(&mut args, &arg)?);
            }
            "--max-file-size-bytes" => {
                overrides.max_file_size_bytes = Some(parse_u64(&mut args, &arg)?);
            }
            "--retained-entry-buffer-limit-bytes" => {
                overrides.retained_entry_buffer_limit_bytes = Some(parse_usize(&mut args, &arg)?);
            }
            "--yara-scan-timeout-seconds" => {
                overrides.yara_scan_timeout_seconds = Some(parse_u64(&mut args, &arg)?);
            }

            value if value.starts_with("-") => {
                return Err(CliError::UnknownArgumentProvided);
            }

            value => {
                // Guard to only allow a single target
                if target.is_some() {
                    return Err(CliError::MultipleScanTargetsProvided);
                }

                target = Some(PathBuf::from(value));
            }
        }
    }

    // Only accept scan commands which contain a target
    let Some(target) = target else {
        return Err(CliError::NoScanTargetProvided);
    };

    let config_path = config::resolve_config_path(config_path, std::env::var("GALEN_CONFIG").ok());
    let overrides =
        config::resolve_scan_overrides(overrides, &config_path, |name| std::env::var(name).ok())?;

    let database = overrides
        .database
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATABASE));
    let yara_rules_cache = overrides
        .yara_rules_cache
        .unwrap_or_else(|| PathBuf::from(DEFAULT_YARA_CACHE));
    let output_format = overrides
        .output_format
        .map(OutputFormat::from)
        .unwrap_or(OutputFormat::Human);

    let mut scan_config = DEFAULT_SCAN_CONFIG;
    if let Some(value) = overrides.max_archive_depth {
        scan_config.max_archive_depth = value;
    }
    if let Some(value) = overrides.max_archive_entries {
        scan_config.max_archive_entries = value;
    }
    if let Some(value) = overrides.max_decompressed_file_size_bytes {
        scan_config.max_decompressed_file_size_bytes = value;
    }
    if let Some(value) = overrides.max_file_size_bytes {
        scan_config.max_file_size_bytes = value;
    }
    if let Some(value) = overrides.retained_entry_buffer_limit_bytes {
        scan_config.retained_entry_buffer_limit_bytes = value;
    }
    if let Some(value) = overrides.yara_scan_timeout_seconds {
        scan_config.yara_scan_timeout = Duration::from_secs(value);
    }

    Ok(Command::Scan(ScanArgs {
        target,
        database,
        yara_rules_cache,
        output_format,
        scan_config,
    }))
}

fn parse_u64<I>(args: &mut I, parameter: &str) -> Result<u64, CliError>
where
    I: Iterator<Item = String>,
{
    let value = args.next().ok_or(CliError::NoArgumentsProvided)?;
    value
        .parse()
        .map_err(|_| CliError::InvalidParameterValue(parameter.to_string()))
}

fn parse_usize<I>(args: &mut I, parameter: &str) -> Result<usize, CliError>
where
    I: Iterator<Item = String>,
{
    let value = args.next().ok_or(CliError::NoArgumentsProvided)?;
    value
        .parse()
        .map_err(|_| CliError::InvalidParameterValue(parameter.to_string()))
}

fn parse_update<I>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut config_path: Option<PathBuf> = None;
    let mut overrides = ConfigOverrides::default();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--database" | "-d" => {
                let Some(value) = args.next() else {
                    return Err(CliError::NoArgumentsProvided);
                };

                overrides.database = Some(PathBuf::from(value));
            }
            "--yara-dir" => {
                let Some(value) = args.next() else {
                    return Err(CliError::NoArgumentsProvided);
                };

                overrides.yara_rules_path = Some(PathBuf::from(value));
            }
            "--yara-cache" | "-y" => {
                let Some(value) = args.next() else {
                    return Err(CliError::NoArgumentsProvided);
                };

                overrides.yara_rules_cache = Some(PathBuf::from(value));
            }
            "--config" => {
                let Some(value) = args.next() else {
                    return Err(CliError::NoArgumentsProvided);
                };
                config_path = Some(PathBuf::from(value));
            }
            _other => return Err(CliError::UnknownParameterProvided),
        }
    }

    let auth_key = match std::env::var("GALEN_AUTH_KEY") {
        Ok(key) => key,
        Err(err) => return Err(CliError::AuthKeyEnvironment(err)),
    };

    let config_path = config::resolve_config_path(config_path, std::env::var("GALEN_CONFIG").ok());
    let overrides =
        config::resolve_update_overrides(overrides, &config_path, |name| std::env::var(name).ok())?;

    let database = overrides
        .database
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATABASE));
    let yara_rules_path = overrides
        .yara_rules_path
        .unwrap_or_else(|| PathBuf::from(DEFAULT_YARA_DIR));
    let yara_rules_cache = overrides
        .yara_rules_cache
        .unwrap_or_else(|| PathBuf::from(DEFAULT_YARA_CACHE));

    Ok(Command::Update(UpdateArgs {
        database,
        auth_key,
        yara_rules_path,
        yara_rules_cache,
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

    /// Sets several environment variables under one ENV_LOCK acquisition.
    /// Tests that need more than one GALEN_* variable set (e.g. an auth key
    /// plus a config override) must use this rather than combining it with
    /// `GalenAuthKeyGuard` in the same test: `Mutex` isn't reentrant, so two
    /// live guards on the same thread would deadlock.
    pub struct EnvVarsGuard {
        previous: Vec<(String, Option<String>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvVarsGuard {
        /// Holds ENV_LOCK without mutating anything. Any test that calls
        /// `parse_scan`/`parse_update` reads real GALEN_* environment
        /// variables now (via config::resolve_*_overrides), so even tests
        /// that don't care about config layering need to hold ENV_LOCK for
        /// their duration - otherwise they can observe a mutation made by a
        /// concurrently running guarded test, since plain `std::env::var`
        /// reads aren't themselves serialized by anything.
        pub fn isolate() -> Self {
            Self::set(&[])
        }

        pub fn set(pairs: &[(&str, &str)]) -> Self {
            let lock = ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut previous = Vec::with_capacity(pairs.len());

            for (name, value) in pairs {
                previous.push(((*name).to_string(), std::env::var(name).ok()));
                // SAFETY: see GalenAuthKeyGuard above; serialized by ENV_LOCK for
                // this guard's lifetime.
                unsafe { std::env::set_var(name, value) };
            }

            Self {
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvVarsGuard {
        fn drop(&mut self) {
            for (name, previous) in &self.previous {
                match previous {
                    // SAFETY: see GalenAuthKeyGuard above.
                    Some(value) => unsafe { std::env::set_var(name, value) },
                    None => unsafe { std::env::remove_var(name) },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::env_test_support::{EnvVarsGuard, GalenAuthKeyGuard};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn parse_error(values: &[&str]) -> CliError {
        match parse_args(args(values)) {
            Ok(_) => panic!("expected parse error"),
            Err(err) => err,
        }
    }

    #[test]
    fn parse_scan_uses_defaults_for_optional_paths_and_human_output() {
        let _guard = EnvVarsGuard::isolate();
        let command = parse_args(args(&["galen", "scan", "target.bin"])).unwrap();

        let Command::Scan(scan) = command else {
            panic!("expected scan command");
        };

        assert_eq!(scan.target, PathBuf::from("target.bin"));
        assert_eq!(scan.database, PathBuf::from(DEFAULT_DATABASE));
        assert_eq!(scan.yara_rules_cache, PathBuf::from(DEFAULT_YARA_CACHE));
        assert!(matches!(scan.output_format, OutputFormat::Human));
        assert_eq!(scan.scan_config.max_archive_depth, 5);
        assert_eq!(scan.scan_config.max_archive_entries, 10_000);
        assert_eq!(
            scan.scan_config.max_decompressed_file_size_bytes,
            67_108_864
        );
        assert_eq!(scan.scan_config.max_file_size_bytes, 67_108_864);
        assert_eq!(scan.scan_config.zip_eocd_min_size_bytes, 22);
        assert_eq!(scan.scan_config.zip_max_comment_size_bytes, 65_535);
        assert_eq!(scan.scan_config.zip64_eocd_locator_size_bytes, 20);
        assert_eq!(
            scan.scan_config.retained_entry_buffer_limit_bytes,
            4_194_304
        );
        assert_eq!(scan.scan_config.yara_scan_timeout, Duration::from_secs(10));
    }

    #[test]
    fn parse_scan_accepts_custom_paths_and_json_output() {
        let _guard = EnvVarsGuard::isolate();
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
    fn parse_scan_accepts_custom_resource_limits() {
        let _guard = EnvVarsGuard::isolate();
        let command = parse_args(args(&[
            "galen",
            "scan",
            "--max-archive-depth",
            "3",
            "--max-archive-entries",
            "250",
            "--max-decompressed-file-size-bytes",
            "1048576",
            "--max-file-size-bytes",
            "2097152",
            "--retained-entry-buffer-limit-bytes",
            "524288",
            "--yara-scan-timeout-seconds",
            "4",
            "samples",
        ]))
        .unwrap();

        let Command::Scan(scan) = command else {
            panic!("expected scan command");
        };

        assert_eq!(scan.scan_config.max_archive_depth, 3);
        assert_eq!(scan.scan_config.max_archive_entries, 250);
        assert_eq!(scan.scan_config.max_decompressed_file_size_bytes, 1_048_576);
        assert_eq!(scan.scan_config.max_file_size_bytes, 2_097_152);
        assert_eq!(scan.scan_config.retained_entry_buffer_limit_bytes, 524_288);
        assert_eq!(scan.scan_config.yara_scan_timeout, Duration::from_secs(4));
    }

    #[test]
    fn parse_scan_rejects_invalid_resource_limits() {
        let _guard = EnvVarsGuard::isolate();
        assert_eq!(
            parse_error(&[
                "galen",
                "scan",
                "--max-file-size-bytes",
                "large",
                "target.bin",
            ]),
            CliError::InvalidParameterValue("--max-file-size-bytes".to_string())
        );
    }

    #[test]
    fn parse_scan_accepts_short_flags_and_falls_back_to_human_output() {
        let _guard = EnvVarsGuard::isolate();
        let command = parse_args(args(&[
            "galen",
            "scan",
            "-d",
            "hashes.sqlite",
            "-y",
            "rules.yaraxc",
            "-o",
            "plain",
            "samples",
        ]))
        .unwrap();

        let Command::Scan(scan) = command else {
            panic!("expected scan command");
        };

        assert_eq!(scan.target, PathBuf::from("samples"));
        assert_eq!(scan.database, PathBuf::from("hashes.sqlite"));
        assert_eq!(scan.yara_rules_cache, PathBuf::from("rules.yaraxc"));
        assert!(matches!(scan.output_format, OutputFormat::Human));
    }

    #[test]
    fn parse_top_level_help_and_unknown_commands() {
        let _guard = EnvVarsGuard::isolate();
        assert!(matches!(
            parse_args(args(&["galen", "help"])).unwrap(),
            Command::Help
        ));

        assert_eq!(parse_error(&["galen", "unknown"]), CliError::UnknownCommand);
    }

    #[test]
    fn parse_scan_rejects_missing_and_duplicate_targets() {
        let _guard = EnvVarsGuard::isolate();
        assert_eq!(
            parse_error(&["galen", "scan"]),
            CliError::NoScanTargetProvided
        );
        assert_eq!(
            parse_error(&["galen", "scan", "one", "two"]),
            CliError::MultipleScanTargetsProvided
        );
    }

    #[test]
    fn parse_scan_rejects_unknown_flags_and_missing_values() {
        let _guard = EnvVarsGuard::isolate();
        assert_eq!(
            parse_error(&["galen", "scan", "--unknown", "target"]),
            CliError::UnknownArgumentProvided
        );
        assert_eq!(
            parse_error(&["galen", "scan", "--database"]),
            CliError::NoArgumentsProvided
        );
        assert_eq!(
            parse_error(&["galen", "scan", "--yara-cache"]),
            CliError::NoArgumentsProvided
        );
        assert_eq!(
            parse_error(&["galen", "scan", "--output"]),
            CliError::NoArgumentsProvided
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
    fn parse_update_accepts_custom_paths() {
        let _guard = GalenAuthKeyGuard::set("test-auth-key");

        let command = parse_args(args(&[
            "galen",
            "update",
            "--database",
            "custom.sqlite",
            "--yara-dir",
            "custom-rules",
            "--yara-cache",
            "custom-cache.yaraxc",
        ]))
        .unwrap();

        let Command::Update(update) = command else {
            panic!("expected update command");
        };

        assert_eq!(update.auth_key, "test-auth-key");
        assert_eq!(update.database, PathBuf::from("custom.sqlite"));
        assert_eq!(update.yara_rules_path, PathBuf::from("custom-rules"));
        assert_eq!(
            update.yara_rules_cache,
            PathBuf::from("custom-cache.yaraxc")
        );
    }

    #[test]
    fn parse_update_accepts_partial_custom_paths_and_keeps_defaults() {
        let _guard = GalenAuthKeyGuard::set("test-auth-key");

        let command = parse_args(args(&[
            "galen",
            "update",
            "-d",
            "custom.sqlite",
            "-y",
            "custom-cache.yaraxc",
        ]))
        .unwrap();

        let Command::Update(update) = command else {
            panic!("expected update command");
        };

        assert_eq!(update.database, PathBuf::from("custom.sqlite"));
        assert_eq!(update.yara_rules_path, PathBuf::from(DEFAULT_YARA_DIR));
        assert_eq!(
            update.yara_rules_cache,
            PathBuf::from("custom-cache.yaraxc")
        );
    }

    #[test]
    fn parse_update_rejects_unexpected_arguments() {
        let _guard = GalenAuthKeyGuard::set("test-auth-key");

        assert_eq!(
            parse_error(&["galen", "update", "--unknown", "custom.sqlite"]),
            CliError::UnknownParameterProvided
        );
        assert_eq!(
            parse_error(&["galen", "update", "custom.sqlite"]),
            CliError::UnknownParameterProvided
        );
    }

    #[test]
    fn parse_update_rejects_missing_parameter_values() {
        let _guard = GalenAuthKeyGuard::set("test-auth-key");

        assert_eq!(
            parse_error(&["galen", "update", "--database"]),
            CliError::NoArgumentsProvided
        );
        assert_eq!(
            parse_error(&["galen", "update", "--yara-dir"]),
            CliError::NoArgumentsProvided
        );
        assert_eq!(
            parse_error(&["galen", "update", "--yara-cache"]),
            CliError::NoArgumentsProvided
        );
    }

    #[test]
    fn parse_update_rejects_unknown_parameters_before_requiring_auth_key() {
        let _guard = GalenAuthKeyGuard::unset();

        assert_eq!(
            parse_error(&["galen", "update", "--unknown"]),
            CliError::UnknownParameterProvided
        );
    }

    #[test]
    fn parse_update_requires_auth_key_environment_variable() {
        let _guard = GalenAuthKeyGuard::unset();

        let err = parse_error(&["galen", "update"]);

        assert!(matches!(err, CliError::AuthKeyEnvironment(_)));
        assert!(err.to_string().contains("environment variable not found"));
    }

    #[test]
    fn parse_scan_applies_settings_from_config_file() {
        let _guard = EnvVarsGuard::isolate();
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("galen.toml");
        std::fs::write(
            &config_path,
            "[scan]\ndatabase = \"file.sqlite\"\noutput = \"json\"\nmax_file_size_bytes = 555\n",
        )
        .unwrap();

        let command = parse_args(args(&[
            "galen",
            "scan",
            "--config",
            config_path.to_str().unwrap(),
            "target.bin",
        ]))
        .unwrap();

        let Command::Scan(scan) = command else {
            panic!("expected scan command");
        };

        assert_eq!(scan.database, PathBuf::from("file.sqlite"));
        assert!(matches!(scan.output_format, OutputFormat::Json));
        assert_eq!(scan.scan_config.max_file_size_bytes, 555);
    }

    #[test]
    fn parse_scan_environment_overrides_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("galen.toml");
        std::fs::write(
            &config_path,
            "[scan]\nmax_file_size_bytes = 111\nmax_archive_depth = 1\n",
        )
        .unwrap();
        let _guard = EnvVarsGuard::set(&[("GALEN_MAX_FILE_SIZE_BYTES", "222")]);

        let command = parse_args(args(&[
            "galen",
            "scan",
            "--config",
            config_path.to_str().unwrap(),
            "target.bin",
        ]))
        .unwrap();

        let Command::Scan(scan) = command else {
            panic!("expected scan command");
        };

        // Environment wins over the file for max_file_size_bytes...
        assert_eq!(scan.scan_config.max_file_size_bytes, 222);
        // ...but the file still supplies whatever the environment didn't set.
        assert_eq!(scan.scan_config.max_archive_depth, 1);
    }

    #[test]
    fn parse_scan_cli_flag_overrides_environment_and_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("galen.toml");
        std::fs::write(&config_path, "[scan]\nmax_file_size_bytes = 111\n").unwrap();
        let _guard = EnvVarsGuard::set(&[("GALEN_MAX_FILE_SIZE_BYTES", "222")]);

        let command = parse_args(args(&[
            "galen",
            "scan",
            "--config",
            config_path.to_str().unwrap(),
            "--max-file-size-bytes",
            "333",
            "target.bin",
        ]))
        .unwrap();

        let Command::Scan(scan) = command else {
            panic!("expected scan command");
        };

        assert_eq!(scan.scan_config.max_file_size_bytes, 333);
    }

    #[test]
    fn parse_scan_reports_missing_explicit_config_file() {
        let _guard = EnvVarsGuard::isolate();
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.toml");

        let err = parse_error(&[
            "galen",
            "scan",
            "--config",
            missing.to_str().unwrap(),
            "target.bin",
        ]);

        assert!(matches!(err, CliError::Config(_)));
    }

    #[test]
    fn parse_scan_reports_invalid_environment_values() {
        let _guard = EnvVarsGuard::set(&[("GALEN_MAX_FILE_SIZE_BYTES", "not-a-number")]);

        let err = parse_error(&["galen", "scan", "target.bin"]);

        assert!(matches!(err, CliError::Config(_)));
    }

    #[test]
    fn parse_update_applies_config_file_for_yara_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("galen.toml");
        std::fs::write(&config_path, "[update]\nyara_dir = \"file-rules\"\n").unwrap();
        let _guard = EnvVarsGuard::set(&[("GALEN_AUTH_KEY", "test-auth-key")]);

        let command = parse_args(args(&[
            "galen",
            "update",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap();

        let Command::Update(update) = command else {
            panic!("expected update command");
        };

        assert_eq!(update.yara_rules_path, PathBuf::from("file-rules"));
    }

    #[test]
    fn parse_update_environment_variable_locates_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("galen.toml");
        std::fs::write(&config_path, "[update]\nyara_dir = \"env-located-rules\"\n").unwrap();
        let _guard = EnvVarsGuard::set(&[
            ("GALEN_AUTH_KEY", "test-auth-key"),
            ("GALEN_CONFIG", config_path.to_str().unwrap()),
        ]);

        let command = parse_args(args(&["galen", "update"])).unwrap();

        let Command::Update(update) = command else {
            panic!("expected update command");
        };

        assert_eq!(update.yara_rules_path, PathBuf::from("env-located-rules"));
    }
}
