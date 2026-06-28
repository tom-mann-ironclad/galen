use std::{path::Path, io::BufReader, fs::File};
use yara_x::Rules;

/// Function to load a compiled YARA rules cache from disk.
pub fn load_yara_rules_cache(path: impl AsRef<Path>) -> Result<Rules, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let rules = Rules::deserialize_from(reader)?;
    Ok(rules)
}
