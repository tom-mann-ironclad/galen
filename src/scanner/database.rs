use super::hash::FileHashes;
use rusqlite::{Connection, params};
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

pub fn insert_test_hash(path: impl AsRef<Path>) -> Result<(), rusqlite::Error> {
    let connection = Connection::open(path)?;
    let sha256: [u8; 32] = [
        100, 155, 139, 71, 30, 125, 123, 193, 117, 238, 199, 88, 167, 0, 106, 198, 147, 196, 52,
        200, 41, 124, 7, 219, 21, 40, 103, 136, 200, 55, 21, 74,
    ];
    {
        connection.execute(
            r#"
        INSERT INTO malware_hashes (
            sha256,
            family,
            source
        )
        VALUES (?1, ?2, ?3)
        "#,
            params![sha256.as_slice(), "test-family", "manual-test",],
        )?;
    }

    Ok(())
}
