use std::path::{Path, PathBuf};

/// Function to grab the latest YARA rules and compile them into a cache on disk.
pub fn update_yara_rules(rules_dir: &Path, cache_path: &Path) -> Result<usize, String> {
    // Grab latest YARA rules
    // TODO!
    
    match compile_yara_cache(rules_dir, cache_path) {
        Ok(compiled) => Ok(compiled),
        Err(err) => Err(err.to_string()),
    }
}

/// Function to compile YARA rules from disk into a cache for runtime use.
fn compile_yara_cache(rules_dir: &Path, cache_path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    // Grab all the YARA rules from the specified directory.
    let rules_paths = collect_yara_rule_files(rules_dir);
    let num_rules = rules_paths.len();

    if num_rules == 0 {
        return Err(format!("No rules found in directory: {}", rules_dir.display()).into()
        );
    };

    // Compile all the rules.
    let mut compiler = yara_x::Compiler::new();

    for path in rules_paths {
        let raw_source = std::fs::read_to_string(&path)?;
        let source: &str = &raw_source; 
        match compiler.add_source(yara_x::SourceCode::from(source)) {
            Ok(_) => {},
            Err(err) => {
                return Err(format!("Unable to add rules from {}: {}", path.display(), err).into());
            }
        };
    }

    let rules = compiler.build();

    // Write the compiled cache to disk.
    if let Some(parent) = cache_path.parent() {
       std::fs::create_dir_all(parent)?
    }

    let tmp_path = cache_path.with_extension("yaraxc.tmp");

    {
        let file = std::fs::File::create(&tmp_path)?;
        let writer = std::io::BufWriter::new(file);

        rules.serialize_into(writer)?;
    }

    std::fs::rename(&tmp_path, cache_path)?;

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
