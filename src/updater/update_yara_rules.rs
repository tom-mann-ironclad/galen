use std::{
    fmt,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateYaraRulesError {
    YaraUpdateDisabled,
    NoRulesFound {
        rules_dir: PathBuf,
    },
    RuleRead {
        path: PathBuf,
        error: String,
    },
    RuleCompile {
        path: PathBuf,
        error: String,
    },
    CacheDirectoryCreate {
        path: PathBuf,
        error: String,
    },
    CacheCreate {
        path: PathBuf,
        error: String,
    },
    CacheWrite {
        path: PathBuf,
        error: String,
    },
    CacheRename {
        from: PathBuf,
        to: PathBuf,
        error: String,
    },
}

impl fmt::Display for UpdateYaraRulesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateYaraRulesError::YaraUpdateDisabled => {
                write!(formatter, "YARA update disabled during coverage")
            }
            UpdateYaraRulesError::NoRulesFound { rules_dir } => {
                write!(
                    formatter,
                    "No rules found in directory: {}",
                    rules_dir.display()
                )
            }
            UpdateYaraRulesError::RuleRead { path, error } => {
                write!(
                    formatter,
                    "Unable to read rules from {}: {error}",
                    path.display()
                )
            }
            UpdateYaraRulesError::RuleCompile { path, error } => {
                write!(
                    formatter,
                    "Unable to add rules from {}: {error}",
                    path.display()
                )
            }
            UpdateYaraRulesError::CacheDirectoryCreate { path, error } => {
                write!(
                    formatter,
                    "Unable to create YARA cache directory {}: {error}",
                    path.display()
                )
            }
            UpdateYaraRulesError::CacheCreate { path, error } => {
                write!(
                    formatter,
                    "Unable to create YARA cache file {}: {error}",
                    path.display()
                )
            }
            UpdateYaraRulesError::CacheWrite { path, error } => {
                write!(
                    formatter,
                    "Unable to write YARA cache file {}: {error}",
                    path.display()
                )
            }
            UpdateYaraRulesError::CacheRename { from, to, error } => {
                write!(
                    formatter,
                    "Unable to move YARA cache from {} to {}: {error}",
                    from.display(),
                    to.display()
                )
            }
        }
    }
}

impl std::error::Error for UpdateYaraRulesError {}

/// Function to grab the latest YARA rules and compile them into a cache on disk.
pub fn update_yara_rules(
    rules_dir: &Path,
    cache_path: &Path,
) -> Result<usize, UpdateYaraRulesError> {
    compile_yara_cache(rules_dir, cache_path)
}

/// Function to compile YARA rules from disk into a cache for runtime use.
fn compile_yara_cache(rules_dir: &Path, cache_path: &Path) -> Result<usize, UpdateYaraRulesError> {
    // Grab all the YARA rules from the specified directory.
    let rules_paths = collect_yara_rule_files(rules_dir);
    let num_rules = rules_paths.len();

    if num_rules == 0 {
        return Err(UpdateYaraRulesError::NoRulesFound {
            rules_dir: rules_dir.to_path_buf(),
        });
    };

    // Compile all the rules.
    let mut compiler = yara_x::Compiler::new();

    for path in rules_paths {
        let raw_source =
            std::fs::read_to_string(&path).map_err(|err| UpdateYaraRulesError::RuleRead {
                path: path.clone(),
                error: err.to_string(),
            })?;
        let source: &str = &raw_source;
        match compiler.add_source(yara_x::SourceCode::from(source)) {
            Ok(_) => {}
            Err(err) => {
                return Err(UpdateYaraRulesError::RuleCompile {
                    path,
                    error: err.to_string(),
                });
            }
        };
    }

    let rules = compiler.build();

    // Write the compiled cache to disk.
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            UpdateYaraRulesError::CacheDirectoryCreate {
                path: parent.to_path_buf(),
                error: err.to_string(),
            }
        })?
    }

    let tmp_path = cache_path.with_extension("yaraxc.tmp");

    {
        let file =
            std::fs::File::create(&tmp_path).map_err(|err| UpdateYaraRulesError::CacheCreate {
                path: tmp_path.clone(),
                error: err.to_string(),
            })?;
        let writer = std::io::BufWriter::new(file);

        rules
            .serialize_into(writer)
            .map_err(|err| UpdateYaraRulesError::CacheWrite {
                path: tmp_path.clone(),
                error: err.to_string(),
            })?;
    }

    std::fs::rename(&tmp_path, cache_path).map_err(|err| UpdateYaraRulesError::CacheRename {
        from: tmp_path,
        to: cache_path.to_path_buf(),
        error: err.to_string(),
    })?;

    Ok(num_rules)
}

/// Function to grab all of the file paths for YARA rules in the specifed directory.
fn collect_yara_rule_files(rules_dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect_yara_rule_files_recursive(rules_dir, &mut paths);
    paths.sort();
    paths
}

/// Function to recurively search a directory and add YARA rule file paths to the `known_paths`
/// `Vec`.
fn collect_yara_rule_files_recursive(rules_dir: &Path, known_paths: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(rules_dir) {
        Ok(entries) => entries,
        Err(_err) => return,
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_err) => return,
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_err) => return,
        };

        if file_type.is_dir() {
            collect_yara_rule_files_recursive(&path, known_paths);
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        if is_yara_rule_file(&path) {
            known_paths.push(path);
        }
    }
}

/// Function to check if a YARA file has the right extension.
fn is_yara_rule_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yar") | Some("yara")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_valid_rule(path: &Path, rule_name: &str) {
        let source = format!("rule {rule_name} {{ condition: true }}");
        std::fs::File::create(path)
            .unwrap()
            .write_all(source.as_bytes())
            .unwrap();
    }

    #[test]
    fn is_yara_rule_file_accepts_only_supported_extensions() {
        assert!(is_yara_rule_file(Path::new("rule.yar")));
        assert!(is_yara_rule_file(Path::new("rule.yara")));
        assert!(!is_yara_rule_file(Path::new("rule.txt")));
        assert!(!is_yara_rule_file(Path::new("rule")));
    }

    #[test]
    fn collect_yara_rule_files_recurses_and_sorts_results() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();

        std::fs::File::create(root.path().join("b.yar"))
            .unwrap()
            .write_all(b"rule b { condition: true }")
            .unwrap();
        std::fs::File::create(nested.join("a.yara"))
            .unwrap()
            .write_all(b"rule a { condition: true }")
            .unwrap();
        std::fs::File::create(root.path().join("ignored.txt")).unwrap();

        let paths = collect_yara_rule_files(root.path());

        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], root.path().join("b.yar"));
        assert_eq!(paths[1], nested.join("a.yara"));
    }

    #[test]
    fn update_yara_rules_compiles_supported_rule_files() {
        let root = tempfile::tempdir().unwrap();
        let cache_path = root.path().join("cache").join("rules.yaraxc");
        let rules_dir = root.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();
        write_valid_rule(&rules_dir.join("one.yar"), "one");
        write_valid_rule(&rules_dir.join("two.yara"), "two");
        std::fs::File::create(rules_dir.join("ignored.txt"))
            .unwrap()
            .write_all(b"rule ignored { condition: true }")
            .unwrap();

        let compiled = update_yara_rules(&rules_dir, &cache_path).unwrap();

        assert_eq!(compiled, 2);
        assert!(cache_path.is_file());
        assert!(!cache_path.with_extension("yaraxc.tmp").exists());
    }

    #[test]
    fn update_yara_rules_rejects_empty_rule_directories() {
        let root = tempfile::tempdir().unwrap();
        let rules_dir = root.path().join("rules");
        let cache_path = root.path().join("rules.yaraxc");
        std::fs::create_dir(&rules_dir).unwrap();

        let err = update_yara_rules(&rules_dir, &cache_path).unwrap_err();

        assert!(matches!(err, UpdateYaraRulesError::NoRulesFound { .. }));
        assert!(err.to_string().contains("No rules found in directory"));
        assert!(!cache_path.exists());
    }

    #[test]
    fn update_yara_rules_reports_invalid_rule_sources() {
        let root = tempfile::tempdir().unwrap();
        let rules_dir = root.path().join("rules");
        let cache_path = root.path().join("rules.yaraxc");
        std::fs::create_dir(&rules_dir).unwrap();
        std::fs::File::create(rules_dir.join("bad.yar"))
            .unwrap()
            .write_all(b"rule broken { condition: }")
            .unwrap();

        let err = update_yara_rules(&rules_dir, &cache_path).unwrap_err();

        assert!(matches!(err, UpdateYaraRulesError::RuleCompile { .. }));
        assert!(err.to_string().contains("Unable to add rules"));
        assert!(!cache_path.exists());
    }

    #[test]
    fn update_yara_rules_reports_rule_read_errors() {
        let root = tempfile::tempdir().unwrap();
        let rules_dir = root.path().join("rules");
        let cache_path = root.path().join("rules.yaraxc");
        std::fs::create_dir(&rules_dir).unwrap();
        std::fs::write(rules_dir.join("invalid-utf8.yar"), [0xff]).unwrap();

        let err = update_yara_rules(&rules_dir, &cache_path).unwrap_err();

        assert!(matches!(err, UpdateYaraRulesError::RuleRead { .. }));
        assert!(err.to_string().contains("Unable to read rules"));
        assert!(!cache_path.exists());
    }

    #[test]
    fn update_yara_rules_reports_cache_directory_create_errors() {
        let root = tempfile::tempdir().unwrap();
        let rules_dir = root.path().join("rules");
        let blocking_file = root.path().join("not-a-directory");
        let cache_path = blocking_file.join("rules.yaraxc");
        std::fs::create_dir(&rules_dir).unwrap();
        write_valid_rule(&rules_dir.join("valid.yar"), "valid");
        std::fs::write(&blocking_file, b"file blocks cache directory").unwrap();

        let err = update_yara_rules(&rules_dir, &cache_path).unwrap_err();

        assert!(matches!(
            err,
            UpdateYaraRulesError::CacheDirectoryCreate { .. }
        ));
        assert!(
            err.to_string()
                .contains("Unable to create YARA cache directory")
        );
    }

    #[test]
    fn update_yara_rules_reports_cache_create_errors() {
        let root = tempfile::tempdir().unwrap();
        let rules_dir = root.path().join("rules");
        let cache_path = root.path().join("rules.yaraxc");
        let tmp_path = cache_path.with_extension("yaraxc.tmp");
        std::fs::create_dir(&rules_dir).unwrap();
        write_valid_rule(&rules_dir.join("valid.yar"), "valid");
        std::fs::create_dir(&tmp_path).unwrap();

        let err = update_yara_rules(&rules_dir, &cache_path).unwrap_err();

        assert!(matches!(err, UpdateYaraRulesError::CacheCreate { .. }));
        assert!(err.to_string().contains("Unable to create YARA cache file"));
        assert!(tmp_path.is_dir());
    }

    #[test]
    fn update_yara_rules_reports_cache_rename_errors() {
        let root = tempfile::tempdir().unwrap();
        let rules_dir = root.path().join("rules");
        let cache_path = root.path().join("rules.yaraxc");
        std::fs::create_dir(&rules_dir).unwrap();
        write_valid_rule(&rules_dir.join("valid.yar"), "valid");
        std::fs::create_dir(&cache_path).unwrap();

        let err = update_yara_rules(&rules_dir, &cache_path).unwrap_err();

        assert!(matches!(err, UpdateYaraRulesError::CacheRename { .. }));
        assert!(err.to_string().contains("Unable to move YARA cache"));
        assert!(cache_path.is_dir());
    }

    #[test]
    fn update_yara_rules_error_display_messages_are_stable() {
        let path = PathBuf::from("rules/example.yar");
        let cache = PathBuf::from("cache/rules.yaraxc");
        let tmp = PathBuf::from("cache/rules.yaraxc.tmp");
        let cases = [
            (
                UpdateYaraRulesError::YaraUpdateDisabled,
                "YARA update disabled during coverage",
            ),
            (
                UpdateYaraRulesError::NoRulesFound {
                    rules_dir: PathBuf::from("rules"),
                },
                "No rules found in directory: rules",
            ),
            (
                UpdateYaraRulesError::RuleRead {
                    path: path.clone(),
                    error: "denied".to_string(),
                },
                "Unable to read rules from rules/example.yar: denied",
            ),
            (
                UpdateYaraRulesError::RuleCompile {
                    path: path.clone(),
                    error: "invalid syntax".to_string(),
                },
                "Unable to add rules from rules/example.yar: invalid syntax",
            ),
            (
                UpdateYaraRulesError::CacheDirectoryCreate {
                    path: PathBuf::from("cache"),
                    error: "denied".to_string(),
                },
                "Unable to create YARA cache directory cache: denied",
            ),
            (
                UpdateYaraRulesError::CacheCreate {
                    path: tmp.clone(),
                    error: "denied".to_string(),
                },
                "Unable to create YARA cache file cache/rules.yaraxc.tmp: denied",
            ),
            (
                UpdateYaraRulesError::CacheWrite {
                    path: tmp.clone(),
                    error: "disk full".to_string(),
                },
                "Unable to write YARA cache file cache/rules.yaraxc.tmp: disk full",
            ),
            (
                UpdateYaraRulesError::CacheRename {
                    from: tmp,
                    to: cache,
                    error: "denied".to_string(),
                },
                "Unable to move YARA cache from cache/rules.yaraxc.tmp to cache/rules.yaraxc: denied",
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }
}
