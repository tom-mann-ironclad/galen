use super::hash::FileHashes;
use rusqlite::Connection;
use std::path::Path;

const SHA256_QUERY: &str = "SELECT sha256 FROM malware_hashes ORDER BY sha256";

#[derive(Debug, Default)]
pub struct HashDatabase {
    sha256: Vec<[u8; 32]>,
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
}

/// Function to load a hash database from an SQLite database on disk.
pub fn load_hash_database(path: impl AsRef<Path>) -> Result<HashDatabase, rusqlite::Error> {
    let connection = Connection::open(path)?;

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
                sha256: vec![hash(1)]
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
    }
}
