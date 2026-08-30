//! Layered configuration support: config file, environment variables, and
//! (via `cli.rs`) CLI flags, merged with precedence CLI flags > environment
//! variables > config file > built-in defaults.
//!
//! The Malware Bazaar auth key is deliberately not part of this layering:
//! it stays environment-variable-only (`GALEN_AUTH_KEY`, read directly in
//! `cli.rs`) so a secret is never expected to live in a config file that
//! might be world-readable or accidentally committed.

use serde::Deserialize;
use std::{fmt, path::PathBuf};

/// Default location for the config file when neither `--config` nor
/// `GALEN_CONFIG` names one explicitly. Relative to the working directory,
/// matching the other cwd-relative defaults (`./signature_database.sqlite`,
/// `./yara/`).
///
/// `cargo test` runs with the crate root as its working directory, so a
/// real `./galen.toml` dropped there for manual testing would silently
/// change unit test behaviour (`galen.toml` is gitignored for this
/// reason - keep local testing config files elsewhere, e.g. pointed to via
/// `--config` or `GALEN_CONFIG`).
pub const DEFAULT_CONFIG_PATH: &str = "./galen.toml";

/// Every setting that can come from a config file, environment variable, or
/// CLI flag. `None` means "not set at this layer".
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ConfigOverrides {
    pub database: Option<PathBuf>,
    pub yara_rules_path: Option<PathBuf>,
    pub yara_rules_cache: Option<PathBuf>,
    pub output_format: Option<String>,
    pub max_archive_depth: Option<usize>,
    pub max_archive_entries: Option<usize>,
    pub max_decompressed_file_size_bytes: Option<u64>,
    pub max_file_size_bytes: Option<u64>,
    pub retained_entry_buffer_limit_bytes: Option<usize>,
    pub yara_scan_timeout_seconds: Option<u64>,
}

impl ConfigOverrides {
    /// Fills in any field left `None` in `self` using the corresponding
    /// field from `lower`. `self` is the higher-precedence layer.
    pub fn or(self, lower: ConfigOverrides) -> ConfigOverrides {
        ConfigOverrides {
            database: self.database.or(lower.database),
            yara_rules_path: self.yara_rules_path.or(lower.yara_rules_path),
            yara_rules_cache: self.yara_rules_cache.or(lower.yara_rules_cache),
            output_format: self.output_format.or(lower.output_format),
            max_archive_depth: self.max_archive_depth.or(lower.max_archive_depth),
            max_archive_entries: self.max_archive_entries.or(lower.max_archive_entries),
            max_decompressed_file_size_bytes: self
                .max_decompressed_file_size_bytes
                .or(lower.max_decompressed_file_size_bytes),
            max_file_size_bytes: self.max_file_size_bytes.or(lower.max_file_size_bytes),
            retained_entry_buffer_limit_bytes: self
                .retained_entry_buffer_limit_bytes
                .or(lower.retained_entry_buffer_limit_bytes),
            yara_scan_timeout_seconds: self
                .yara_scan_timeout_seconds
                .or(lower.yara_scan_timeout_seconds),
        }
    }
}

/// Where the config file path came from. An explicitly-named path (via
/// `--config` or `GALEN_CONFIG`) is an error if it can't be read; the
/// implicit default path is optional and silently yields no overrides if
/// absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigPathSource {
    Explicit(PathBuf),
    Default(PathBuf),
}

/// Resolves which config file to load: an explicit `--config` value wins,
/// then `GALEN_CONFIG`, then the built-in default path.
pub fn resolve_config_path(
    cli_value: Option<PathBuf>,
    env_value: Option<String>,
) -> ConfigPathSource {
    if let Some(path) = cli_value {
        return ConfigPathSource::Explicit(path);
    }
    if let Some(path) = env_value {
        return ConfigPathSource::Explicit(PathBuf::from(path));
    }
    ConfigPathSource::Default(PathBuf::from(DEFAULT_CONFIG_PATH))
}

/// Errors produced while resolving config-file or environment-variable
/// overrides.
#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    Parse {
        path: PathBuf,
        error: String,
    },
    InvalidEnvironmentValue {
        variable: String,
        value: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, error } => {
                write!(formatter, "could not read {}: {}", path.display(), error)
            }
            ConfigError::Parse { path, error } => {
                write!(formatter, "could not parse {}: {}", path.display(), error)
            }
            ConfigError::InvalidEnvironmentValue { variable, value } => {
                write!(formatter, "invalid value for {variable}: {value:?}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileConfig {
    scan: FileScanSection,
    update: FileUpdateSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileScanSection {
    database: Option<PathBuf>,
    yara_cache: Option<PathBuf>,
    output: Option<String>,
    max_archive_depth: Option<usize>,
    max_archive_entries: Option<usize>,
    max_decompressed_file_size_bytes: Option<u64>,
    max_file_size_bytes: Option<u64>,
    retained_entry_buffer_limit_bytes: Option<usize>,
    yara_scan_timeout_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileUpdateSection {
    database: Option<PathBuf>,
    yara_dir: Option<PathBuf>,
    yara_cache: Option<PathBuf>,
}

impl From<FileScanSection> for ConfigOverrides {
    fn from(section: FileScanSection) -> Self {
        ConfigOverrides {
            database: section.database,
            yara_rules_path: None,
            yara_rules_cache: section.yara_cache,
            output_format: section.output,
            max_archive_depth: section.max_archive_depth,
            max_archive_entries: section.max_archive_entries,
            max_decompressed_file_size_bytes: section.max_decompressed_file_size_bytes,
            max_file_size_bytes: section.max_file_size_bytes,
            retained_entry_buffer_limit_bytes: section.retained_entry_buffer_limit_bytes,
            yara_scan_timeout_seconds: section.yara_scan_timeout_seconds,
        }
    }
}

impl From<FileUpdateSection> for ConfigOverrides {
    fn from(section: FileUpdateSection) -> Self {
        ConfigOverrides {
            database: section.database,
            yara_rules_path: section.yara_dir,
            yara_rules_cache: section.yara_cache,
            ..Default::default()
        }
    }
}

struct FileOverrides {
    scan: ConfigOverrides,
    update: ConfigOverrides,
}

fn load_file_overrides(source: &ConfigPathSource) -> Result<FileOverrides, ConfigError> {
    let (path, required) = match source {
        ConfigPathSource::Explicit(path) => (path, true),
        ConfigPathSource::Default(path) => (path, false),
    };

    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if !required && err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileOverrides {
                scan: ConfigOverrides::default(),
                update: ConfigOverrides::default(),
            });
        }
        Err(err) => {
            return Err(ConfigError::Io {
                path: path.clone(),
                error: err,
            });
        }
    };

    let parsed: FileConfig = toml::from_str(&contents).map_err(|err| ConfigError::Parse {
        path: path.clone(),
        error: err.to_string(),
    })?;

    Ok(FileOverrides {
        scan: parsed.scan.into(),
        update: parsed.update.into(),
    })
}

fn parse_env_usize(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Result<Option<usize>, ConfigError> {
    let Some(value) = lookup(name) else {
        return Ok(None);
    };
    value
        .parse::<usize>()
        .map(Some)
        .map_err(|_| ConfigError::InvalidEnvironmentValue {
            variable: name.to_string(),
            value,
        })
}

fn parse_env_u64(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Result<Option<u64>, ConfigError> {
    let Some(value) = lookup(name) else {
        return Ok(None);
    };
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| ConfigError::InvalidEnvironmentValue {
            variable: name.to_string(),
            value,
        })
}

/// Reads `GALEN_*` environment variables relevant to the `scan` command.
/// `lookup` is injected so tests don't need to mutate real process
/// environment.
pub fn scan_overrides_from_env(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<ConfigOverrides, ConfigError> {
    Ok(ConfigOverrides {
        database: lookup("GALEN_DATABASE").map(PathBuf::from),
        yara_rules_path: None,
        yara_rules_cache: lookup("GALEN_YARA_CACHE").map(PathBuf::from),
        output_format: lookup("GALEN_OUTPUT"),
        max_archive_depth: parse_env_usize(&lookup, "GALEN_MAX_ARCHIVE_DEPTH")?,
        max_archive_entries: parse_env_usize(&lookup, "GALEN_MAX_ARCHIVE_ENTRIES")?,
        max_decompressed_file_size_bytes: parse_env_u64(
            &lookup,
            "GALEN_MAX_DECOMPRESSED_FILE_SIZE_BYTES",
        )?,
        max_file_size_bytes: parse_env_u64(&lookup, "GALEN_MAX_FILE_SIZE_BYTES")?,
        retained_entry_buffer_limit_bytes: parse_env_usize(
            &lookup,
            "GALEN_RETAINED_ENTRY_BUFFER_LIMIT_BYTES",
        )?,
        yara_scan_timeout_seconds: parse_env_u64(&lookup, "GALEN_YARA_SCAN_TIMEOUT_SECONDS")?,
    })
}

/// Reads `GALEN_*` environment variables relevant to the `update` command.
pub fn update_overrides_from_env(lookup: impl Fn(&str) -> Option<String>) -> ConfigOverrides {
    ConfigOverrides {
        database: lookup("GALEN_DATABASE").map(PathBuf::from),
        yara_rules_path: lookup("GALEN_YARA_DIR").map(PathBuf::from),
        yara_rules_cache: lookup("GALEN_YARA_CACHE").map(PathBuf::from),
        ..Default::default()
    }
}

/// Merges CLI, environment, and config-file overrides for the `scan`
/// command, in that precedence order.
pub fn resolve_scan_overrides(
    cli_overrides: ConfigOverrides,
    config_path: &ConfigPathSource,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<ConfigOverrides, ConfigError> {
    let env_overrides = scan_overrides_from_env(env_lookup)?;
    let file_overrides = load_file_overrides(config_path)?.scan;
    Ok(cli_overrides.or(env_overrides).or(file_overrides))
}

/// Merges CLI, environment, and config-file overrides for the `update`
/// command, in that precedence order.
pub fn resolve_update_overrides(
    cli_overrides: ConfigOverrides,
    config_path: &ConfigPathSource,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<ConfigOverrides, ConfigError> {
    let env_overrides = update_overrides_from_env(env_lookup);
    let file_overrides = load_file_overrides(config_path)?.update;
    Ok(cli_overrides.or(env_overrides).or(file_overrides))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn write_config(dir: &std::path::Path, contents: &str) -> PathBuf {
        let path = dir.join("galen.toml");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn or_prefers_higher_precedence_fields_and_falls_back_for_the_rest() {
        let high = ConfigOverrides {
            database: Some(PathBuf::from("high.sqlite")),
            ..Default::default()
        };
        let low = ConfigOverrides {
            database: Some(PathBuf::from("low.sqlite")),
            max_file_size_bytes: Some(123),
            ..Default::default()
        };

        let merged = high.or(low);

        assert_eq!(merged.database, Some(PathBuf::from("high.sqlite")));
        assert_eq!(merged.max_file_size_bytes, Some(123));
    }

    #[test]
    fn config_error_display_messages_are_specific_per_variant() {
        let io = ConfigError::Io {
            path: PathBuf::from("missing.toml"),
            error: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        };
        assert!(io.to_string().contains("could not read"));
        assert!(io.to_string().contains("missing.toml"));

        let parse = ConfigError::Parse {
            path: PathBuf::from("bad.toml"),
            error: "unexpected key".to_string(),
        };
        assert!(parse.to_string().contains("could not parse"));
        assert!(parse.to_string().contains("bad.toml"));
        assert!(parse.to_string().contains("unexpected key"));

        let invalid_env = ConfigError::InvalidEnvironmentValue {
            variable: "GALEN_MAX_FILE_SIZE_BYTES".to_string(),
            value: "not-a-number".to_string(),
        };
        assert!(
            invalid_env
                .to_string()
                .contains("GALEN_MAX_FILE_SIZE_BYTES")
        );
        assert!(invalid_env.to_string().contains("not-a-number"));
    }

    #[test]
    fn scan_overrides_from_env_reads_all_recognised_variables() {
        let lookup = env(&[
            ("GALEN_DATABASE", "env.sqlite"),
            ("GALEN_YARA_CACHE", "env.yaraxc"),
            ("GALEN_OUTPUT", "json"),
            ("GALEN_MAX_ARCHIVE_DEPTH", "3"),
            ("GALEN_MAX_ARCHIVE_ENTRIES", "99"),
            ("GALEN_MAX_DECOMPRESSED_FILE_SIZE_BYTES", "111"),
            ("GALEN_MAX_FILE_SIZE_BYTES", "222"),
            ("GALEN_RETAINED_ENTRY_BUFFER_LIMIT_BYTES", "333"),
            ("GALEN_YARA_SCAN_TIMEOUT_SECONDS", "7"),
        ]);

        let overrides = scan_overrides_from_env(lookup).unwrap();

        assert_eq!(overrides.database, Some(PathBuf::from("env.sqlite")));
        assert_eq!(
            overrides.yara_rules_cache,
            Some(PathBuf::from("env.yaraxc"))
        );
        assert_eq!(overrides.output_format, Some("json".to_string()));
        assert_eq!(overrides.max_archive_depth, Some(3));
        assert_eq!(overrides.max_archive_entries, Some(99));
        assert_eq!(overrides.max_decompressed_file_size_bytes, Some(111));
        assert_eq!(overrides.max_file_size_bytes, Some(222));
        assert_eq!(overrides.retained_entry_buffer_limit_bytes, Some(333));
        assert_eq!(overrides.yara_scan_timeout_seconds, Some(7));
    }

    #[test]
    fn scan_overrides_from_env_rejects_invalid_numeric_values() {
        let lookup = env(&[("GALEN_MAX_FILE_SIZE_BYTES", "not-a-number")]);

        let err = scan_overrides_from_env(lookup).unwrap_err();

        assert!(matches!(
            err,
            ConfigError::InvalidEnvironmentValue { variable, .. }
                if variable == "GALEN_MAX_FILE_SIZE_BYTES"
        ));
    }

    #[test]
    fn update_overrides_from_env_reads_yara_dir() {
        let lookup = env(&[("GALEN_YARA_DIR", "env-rules")]);

        let overrides = update_overrides_from_env(lookup);

        assert_eq!(overrides.yara_rules_path, Some(PathBuf::from("env-rules")));
    }

    #[test]
    fn resolve_config_path_prefers_cli_then_env_then_default() {
        assert_eq!(
            resolve_config_path(
                Some(PathBuf::from("cli.toml")),
                Some("env.toml".to_string())
            ),
            ConfigPathSource::Explicit(PathBuf::from("cli.toml"))
        );
        assert_eq!(
            resolve_config_path(None, Some("env.toml".to_string())),
            ConfigPathSource::Explicit(PathBuf::from("env.toml"))
        );
        assert_eq!(
            resolve_config_path(None, None),
            ConfigPathSource::Default(PathBuf::from(DEFAULT_CONFIG_PATH))
        );
    }

    #[test]
    fn missing_default_config_file_yields_no_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let source = ConfigPathSource::Default(dir.path().join("missing.toml"));

        let overrides =
            resolve_scan_overrides(ConfigOverrides::default(), &source, |_| None).unwrap();

        assert_eq!(overrides, ConfigOverrides::default());
    }

    #[test]
    fn missing_explicit_config_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let source = ConfigPathSource::Explicit(dir.path().join("missing.toml"));

        let err =
            resolve_scan_overrides(ConfigOverrides::default(), &source, |_| None).unwrap_err();

        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn loads_scan_and_update_sections_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            r#"
            [scan]
            database = "file.sqlite"
            output = "json"
            max_file_size_bytes = 555

            [update]
            yara_dir = "file-rules"
            "#,
        );
        let source = ConfigPathSource::Explicit(path);

        let scan = resolve_scan_overrides(ConfigOverrides::default(), &source, |_| None).unwrap();
        assert_eq!(scan.database, Some(PathBuf::from("file.sqlite")));
        assert_eq!(scan.output_format, Some("json".to_string()));
        assert_eq!(scan.max_file_size_bytes, Some(555));

        let update =
            resolve_update_overrides(ConfigOverrides::default(), &source, |_| None).unwrap();
        assert_eq!(update.yara_rules_path, Some(PathBuf::from("file-rules")));
    }

    #[test]
    fn rejects_unknown_keys_in_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            r#"
            [scan]
            not_a_real_key = true
            "#,
        );
        let source = ConfigPathSource::Explicit(path);

        let err =
            resolve_scan_overrides(ConfigOverrides::default(), &source, |_| None).unwrap_err();

        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn precedence_is_cli_then_env_then_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            r#"
            [scan]
            database = "file.sqlite"
            max_file_size_bytes = 1
            max_archive_depth = 1
            "#,
        );
        let source = ConfigPathSource::Explicit(path);

        // CLI sets database; env sets max_file_size_bytes; file sets
        // max_archive_depth (and database/max_file_size_bytes, which
        // should be shadowed by the higher layers).
        let cli_overrides = ConfigOverrides {
            database: Some(PathBuf::from("cli.sqlite")),
            ..Default::default()
        };

        // Exercise the env layer directly (see scan_overrides_from_env
        // tests for env-var coverage) merged with CLI and file layers here
        // to check the full three-way precedence order.
        let env_overrides = ConfigOverrides {
            max_file_size_bytes: Some(2),
            ..Default::default()
        };
        let file_overrides = load_file_overrides(&source).unwrap().scan;
        let merged = cli_overrides.or(env_overrides).or(file_overrides);

        assert_eq!(merged.database, Some(PathBuf::from("cli.sqlite")));
        assert_eq!(merged.max_file_size_bytes, Some(2));
        assert_eq!(merged.max_archive_depth, Some(1));
    }
}
