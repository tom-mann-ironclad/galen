use super::{database::HashDatabase, hash::hash_file};
use std::path::Path;

#[derive(Debug)]
pub enum ScanResult {
    Clean,
    KnownHash { family: Option<String> },
}

pub fn scan_file(
    path: impl AsRef<Path>,
    hash_database: &HashDatabase,
) -> Result<ScanResult, String> {
    let hashes = match hash_file(path) {
        Err(_) => return Err("Unable to compare hash".to_string()),
        Ok(hashes) => hashes,
    };
    if hash_database.contains(&hashes) {
        return Ok(ScanResult::KnownHash { family: None });
    };
    Ok(ScanResult::Clean)
}
