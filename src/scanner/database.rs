use super::hash::FileHashes;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::Path;

const SHA256_QUERY: &str = "SELECT sha256 FROM malware_hashes ORDER BY sha256";
const UPDATE_METADATA_TABLE_EXISTS_QUERY: &str =
    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'update_metadata')";
const LAST_SUCCESSFUL_UPDATE_QUERY: &str =
    "SELECT last_successful_update FROM update_metadata WHERE source = 'malware_bazaar'";

#[derive(Debug, Default)]
pub struct HashDatabase {
    sha256: Vec<[u8; 32]>,
    last_successful_update: Option<i64>,
}

impl HashDatabase {
    /// Function to check if the `HashDatabase` contains the hash of a file.
    pub fn contains(&self, file_hashes: &FileHashes) -> bool {
        self.sha256.binary_search(&file_hashes.sha256).is_ok()
    }

    /// Function to get the number of hashes in the database.
    pub fn len(&self) -> usize {
        self.sha256.len()
    }

    /// Function to get if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.sha256.is_empty()
    }

    /// Return the Unix timestamp of the last successful Malware Bazaar update, if known.
    pub fn last_successful_update(&self) -> Option<i64> {
        self.last_successful_update
    }
}

/// Function to load a hash database from an SQLite database on disk.
pub fn load_hash_database(path: impl AsRef<Path>) -> Result<HashDatabase, rusqlite::Error> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut database = HashDatabase::default();

    {
        let mut query = connection.prepare(SHA256_QUERY)?;
        let rows = query.query_map([], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(bytes)
        })?;

        for row in rows {
            let bytes = row?;
            if bytes.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                database.sha256.push(hash);
            }
        }
    }

    database.sha256.sort_unstable();
    database.sha256.dedup();

    let has_update_metadata: bool =
        connection.query_row(UPDATE_METADATA_TABLE_EXISTS_QUERY, [], |row| row.get(0))?;
    if has_update_metadata {
        database.last_successful_update = connection
            .query_row(LAST_SUCCESSFUL_UPDATE_QUERY, [], |row| row.get(0))
            .optional()?
            .flatten();
    }

    Ok(database)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn contains_uses_sorted_hashes() {
        let database = HashDatabase {
            sha256: vec![hash(1), hash(3), hash(9)],
            last_successful_update: None,
        };

        assert!(!database.is_empty());
        assert!(database.contains(&FileHashes { sha256: hash(3) }));
        assert!(!database.contains(&FileHashes { sha256: hash(4) }));
    }

    #[test]
    fn is_empty_reports_whether_hashes_are_loaded() {
        assert!(HashDatabase::default().is_empty());
        assert!(
            !HashDatabase {
                sha256: vec![hash(1)],
                ..HashDatabase::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn load_hash_database_sorts_dedupes_and_ignores_invalid_lengths() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(file.path()).unwrap();

        connection
            .execute("CREATE TABLE malware_hashes (sha256 BLOB NOT NULL)", [])
            .unwrap();
        connection
            .execute(
                "INSERT INTO malware_hashes (sha256) VALUES (?1), (?2), (?3), (?4)",
                params![&hash(9)[..], &hash(1)[..], &hash(9)[..], &[0_u8; 31][..]],
            )
            .unwrap();
        drop(connection);

        let database = load_hash_database(file.path()).unwrap();

        assert_eq!(database.len(), 2);
        assert!(database.contains(&FileHashes { sha256: hash(1) }));
        assert!(database.contains(&FileHashes { sha256: hash(9) }));
        assert_eq!(database.last_successful_update(), None);
    }

    #[test]
    fn load_hash_database_reads_last_successful_update() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(file.path()).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE malware_hashes (sha256 BLOB NOT NULL);
                CREATE TABLE update_metadata (
                    source TEXT PRIMARY KEY NOT NULL,
                    last_successful_update INTEGER
                );
                INSERT INTO update_metadata (source, last_successful_update)
                VALUES ('malware_bazaar', 1234);
                "#,
            )
            .unwrap();
        drop(connection);

        let database = load_hash_database(file.path()).unwrap();

        assert_eq!(database.last_successful_update(), Some(1234));
    }

    #[test]
    fn load_hash_database_reports_query_errors() {
        let file = tempfile::NamedTempFile::new().unwrap();
        Connection::open(file.path()).unwrap();

        let err = load_hash_database(file.path()).unwrap_err();

        assert!(err.to_string().contains("malware_hashes"));
    }

    #[test]
    fn load_hash_database_does_not_create_a_missing_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing.sqlite");

        let err = load_hash_database(&path).unwrap_err();

        assert!(!path.exists());
        assert!(err.to_string().contains("open"));
    }
}
