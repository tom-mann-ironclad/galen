use rusqlite::{Connection, params};
use serde::Deserialize;
use std::path::Path;

const CREATE_MALWARE_HASH_TABLE: &str = r#"CREATE TABLE IF NOT EXISTS malware_hashes (
    sha256 BLOB PRIMARY KEY NOT NULL CHECK(length(sha256) = 32),
    family TEXT,
    source TEXT NOT NULL,
    first_seen INTEGER,
    file_type TEXT,
    imported_at INTEGER NOT NULL
);"#;

#[derive(Debug, Deserialize)]
struct MalwareBazaarResponse {
    query_status: String, // TODO: Make this typed?
    data: Option<Vec<MalwareBazaarSample>>,
}

#[derive(Debug, Deserialize)]
struct MalwareBazaarSample {
    sha256_hash: String,
    signature: Option<String>,
    first_seen: Option<String>,
    file_type: Option<String>,
}

/// Function to update the signatures database from Malware Bazaar.
pub fn update_using_malware_bazaar(
    auth_key: &str,
    selector: &str,
    db_path: impl AsRef<Path>,
) -> Result<usize, String> {
    let samples = match fetch_malware_bazaar_recent_hashes(auth_key, selector) {
        Ok(samples) => samples,
        Err(err) => return Err(err.to_string()),
    };

    if !samples.is_empty() {
        let _ = create_database_table(&db_path);
        match insert_malware_bazaar_hashes(db_path, &samples) {
            Ok(inserted) => return Ok(inserted),
            Err(err) => return Err(err.to_string()),
        }
    }

    Ok(0)
}

fn create_database_table(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open(path)?;

    connection.execute(CREATE_MALWARE_HASH_TABLE, [])?;
    Ok(())
}

/// Function to grab the most recent malware hashes from Malware Bazaar.
fn fetch_malware_bazaar_recent_hashes(
    auth_key: &str,
    selector: &str,
) -> Result<Vec<MalwareBazaarSample>, Box<dyn std::error::Error>> {
    let body = format!("query=get_recent&selector={}", selector);
    let mut response = ureq::post("https://mb-api.abuse.ch/api/v1/")
        .header("Auth-Key", auth_key)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(&body)?;

    let response: MalwareBazaarResponse = response.body_mut().read_json()?;

    match response.query_status.as_str() {
        "ok" => Ok(response.data.unwrap_or_default()),
        "no_results" => Ok(Vec::new()),
        other => Err(format!("Malware Bazaar query failed: {}", other).into()),
    }
}

/// Function to insert malware hashes from Malware Bazaar into the database.
fn insert_malware_bazaar_hashes(
    db_path: impl AsRef<Path>,
    samples: &[MalwareBazaarSample],
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut connection = Connection::open(db_path)?;
    let tx = connection.transaction()?;

    let mut inserted = 0;

    {
        let mut query = tx.prepare(
            r#"
            INSERT INTO malware_hashes (
                sha256,
                family,
                source,
                first_seen,
                file_type,
                imported_at
            )
            VALUES (?1, ?2, 'malware_bazaar', ?3, ?4, unixepoch())
            ON CONFLICT(sha256) DO UPDATE SET
                family = COALESCE(excluded.family, malware_hashes.family),
                first_seen = COALESCE(malware_hashes.first_seen, excluded.first_seen),
                file_type = COALESCE(excluded.file_type, malware_hashes.file_type),
                imported_at = unixepoch()
            "#,
        )?;

        for sample in samples {
            let Some(sha256_bytes) = decode_sha256_hex(&sample.sha256_hash) else {
                continue;
            };

            let first_seen = parse_malware_bazaar_timestamp(sample.first_seen.as_deref());

            let changed = query.execute(params![
                &sha256_bytes[..],
                sample.signature,
                first_seen,
                sample.file_type,
            ])?;

            inserted += changed;
        }
    }

    tx.commit()?;

    Ok(inserted)
}

/// Utility function to decode a SHA256 hash and confirm it is valid.
fn decode_sha256_hex(hash: &str) -> Option<[u8; 32]> {
    if hash.len() != 64 {
        return None;
    }

    let mut output = [0u8; 32];

    for (i, byte) in output.iter_mut().enumerate() {
        let high = decode_hex_nibble(hash.as_bytes()[&i * 2])?;
        let low = decode_hex_nibble(hash.as_bytes()[&i * 2 + 1])?;

        *byte = (high << 4) | low;
    }

    Some(output)
}

/// Function to decode a hex nibble into it's binary equivalent.
fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Function to convert a timestamp string produced by Malware Bazaar into a seconds since Unix
/// Epoch timestamp.
fn parse_malware_bazaar_timestamp(value: Option<&str>) -> Option<i64> {
    let value = value?;

    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|dt| dt.and_utc().timestamp())
}
