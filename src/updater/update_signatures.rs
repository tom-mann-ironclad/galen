use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Deserializer};
#[cfg(not(tarpaulin))]
use std::io::{BufReader, Seek, SeekFrom, copy};
use std::{fmt, fs::File, io::BufRead, path::Path};

const CREATE_METADATA_TABLE: &str = r#"
        CREATE TABLE IF NOT EXISTS update_metadata (
            source TEXT PRIMARY KEY NOT NULL,
            last_request INTEGER NOT NULL,
            last_successful_update INTEGER,
            last_mode TEXT NOT NULL,
            rows_seen INTEGER NOT NULL,
            rows_inserted INTEGER NOT NULL
    );"#;

const CREATE_MALWARE_HASH_TABLE: &str = r#"
        CREATE TABLE IF NOT EXISTS malware_hashes (
            sha256 BLOB PRIMARY KEY NOT NULL CHECK(length(sha256) = 32),
            family TEXT,
            source TEXT NOT NULL,
            first_seen INTEGER,
            file_type TEXT,
            imported_at INTEGER NOT NULL
    );"#;

// Use a conservative fair-use interval aligned with Malware Bazaar's documented one-hour window
// for recent data.
const MALWARE_BAZAAR_REQUEST_INTERVAL_SECONDS: i64 = 60 * 60;

#[derive(Debug, Clone, Deserialize)]
struct MalwareBazaarResponse {
    query_status: MalwareBazaarQueryStatus,
    data: Option<Vec<MalwareBazaarSample>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MalwareBazaarQueryStatus {
    Ok,
    NoResults,
    Other(String),
}

impl<'de> Deserialize<'de> for MalwareBazaarQueryStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let status = String::deserialize(deserializer)?;

        Ok(match status.as_str() {
            "ok" => Self::Ok,
            "no_results" => Self::NoResults,
            _other => Self::Other(status),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct MalwareBazaarSample {
    sha256_hash: String,
    family: Option<String>,
    first_seen: Option<String>,
    file_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpdateCounts {
    rows_seen: usize,
    rows_inserted: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestClaim {
    Allowed,
    RateLimited { retry_at: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateSignaturesOutcome {
    /// The request completed and this many database rows were processed.
    Updated(usize),
    /// The request was skipped until the supplied Unix timestamp.
    RateLimited { retry_at: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateSignaturesError {
    DatabaseSetup(String),
    DatabaseValidation(String),
    DatabaseCount(String),
    DatabaseMetadata(String),
    InvalidResponse(String),
    DatabaseStage(String),
    DatabaseReplace(String),
    FullFetch(String),
    RecentFetch(String),
    DatabaseInsert(String),
    NetworkUpdateDisabled,
}

impl fmt::Display for UpdateSignaturesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateSignaturesError::DatabaseSetup(err)
            | UpdateSignaturesError::DatabaseValidation(err)
            | UpdateSignaturesError::DatabaseCount(err)
            | UpdateSignaturesError::DatabaseMetadata(err)
            | UpdateSignaturesError::InvalidResponse(err)
            | UpdateSignaturesError::DatabaseStage(err)
            | UpdateSignaturesError::DatabaseReplace(err)
            | UpdateSignaturesError::FullFetch(err)
            | UpdateSignaturesError::RecentFetch(err)
            | UpdateSignaturesError::DatabaseInsert(err) => write!(formatter, "{err}"),
            UpdateSignaturesError::NetworkUpdateDisabled => {
                write!(formatter, "network update disabled during coverage")
            }
        }
    }
}

impl std::error::Error for UpdateSignaturesError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseState {
    Missing,
    Uninitialised,
    Valid,
}

/// Function to update the signatures database from Malware Bazaar.
#[cfg(not(tarpaulin))]
pub fn update_signatures_using_malware_bazaar(
    auth_key: &str,
    selector: &str,
    db_path: impl AsRef<Path>,
) -> Result<UpdateSignaturesOutcome, UpdateSignaturesError> {
    update_signatures_with_client(
        auth_key,
        selector,
        db_path.as_ref(),
        &LiveMalwareBazaarClient,
    )
}

trait MalwareBazaarClient {
    fn fetch_recent(
        &self,
        auth_key: &str,
        selector: &str,
    ) -> Result<Vec<MalwareBazaarSample>, Box<dyn std::error::Error>>;

    fn fetch_full(
        &self,
        auth_key: &str,
        db_path: &Path,
    ) -> Result<UpdateCounts, Box<dyn std::error::Error>>;
}

#[cfg(not(tarpaulin))]
struct LiveMalwareBazaarClient;

#[cfg(not(tarpaulin))]
impl MalwareBazaarClient for LiveMalwareBazaarClient {
    fn fetch_recent(
        &self,
        auth_key: &str,
        selector: &str,
    ) -> Result<Vec<MalwareBazaarSample>, Box<dyn std::error::Error>> {
        fetch_malware_bazaar_recent_hashes(auth_key, selector)
    }

    fn fetch_full(
        &self,
        auth_key: &str,
        db_path: &Path,
    ) -> Result<UpdateCounts, Box<dyn std::error::Error>> {
        fetch_malware_bazaar_full_hashes(auth_key, db_path)
    }
}

fn update_signatures_with_client(
    auth_key: &str,
    selector: &str,
    db_path: &Path,
    client: &impl MalwareBazaarClient,
) -> Result<UpdateSignaturesOutcome, UpdateSignaturesError> {
    let state = inspect_database(db_path)
        .map_err(|err| UpdateSignaturesError::DatabaseValidation(err.to_string()))?;
    let existing_entries = if state == DatabaseState::Valid {
        create_database_tables(db_path)
            .map_err(|err| UpdateSignaturesError::DatabaseSetup(err.to_string()))?;
        malware_hash_count(db_path)
            .map_err(|err| UpdateSignaturesError::DatabaseCount(err.to_string()))?
    } else {
        0
    };

    // If we have no malware signatures we need to bootstrap the database.
    if existing_entries == 0 {
        eprintln!("Empty database found, bootstrapping...");
        return bootstrap_database(auth_key, db_path, state, client);
    }

    if let RequestClaim::RateLimited { retry_at } =
        claim_malware_bazaar_request(db_path, "recent", chrono::Utc::now().timestamp())
            .map_err(|err| UpdateSignaturesError::DatabaseMetadata(err.to_string()))?
    {
        return Ok(UpdateSignaturesOutcome::RateLimited { retry_at });
    }
    let samples = match client.fetch_recent(auth_key, selector) {
        Ok(samples) => samples,
        Err(err) => return Err(UpdateSignaturesError::RecentFetch(err.to_string())),
    };

    validate_recent_samples(&samples)
        .map_err(|err| UpdateSignaturesError::InvalidResponse(err.to_string()))?;

    if !samples.is_empty() {
        eprintln!("Updating database with latest signatures...");
        match insert_malware_bazaar_hashes(db_path, &samples) {
            Ok(counts) => return Ok(UpdateSignaturesOutcome::Updated(counts.rows_inserted)),
            Err(err) => return Err(UpdateSignaturesError::DatabaseInsert(err.to_string())),
        }
    }

    record_successful_malware_bazaar_update(
        db_path,
        "recent",
        UpdateCounts {
            rows_seen: 0,
            rows_inserted: 0,
        },
    )
    .map_err(|err| UpdateSignaturesError::DatabaseMetadata(err.to_string()))?;

    Ok(UpdateSignaturesOutcome::Updated(0))
}

fn bootstrap_database(
    auth_key: &str,
    db_path: &Path,
    state: DatabaseState,
    client: &impl MalwareBazaarClient,
) -> Result<UpdateSignaturesOutcome, UpdateSignaturesError> {
    let now = chrono::Utc::now().timestamp();
    if state == DatabaseState::Valid
        && let RequestClaim::RateLimited { retry_at } =
            claim_malware_bazaar_request(db_path, "full", now)
                .map_err(|err| UpdateSignaturesError::DatabaseMetadata(err.to_string()))?
    {
        return Ok(UpdateSignaturesOutcome::RateLimited { retry_at });
    }

    let parent = db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staging = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| UpdateSignaturesError::DatabaseStage(err.to_string()))?;
    create_database_tables(staging.path())
        .map_err(|err| UpdateSignaturesError::DatabaseStage(err.to_string()))?;
    claim_malware_bazaar_request(staging.path(), "full", now)
        .map_err(|err| UpdateSignaturesError::DatabaseStage(err.to_string()))?;

    let counts = client
        .fetch_full(auth_key, staging.path())
        .map_err(|err| UpdateSignaturesError::FullFetch(err.to_string()))?;
    let staged_hashes = malware_hash_count(staging.path())
        .map_err(|err| UpdateSignaturesError::DatabaseStage(err.to_string()))?;
    if counts.rows_seen == 0 || staged_hashes == 0 {
        return Err(UpdateSignaturesError::InvalidResponse(
            "Malware Bazaar full export contained no valid hashes".to_string(),
        ));
    }
    record_successful_malware_bazaar_update(staging.path(), "full", counts)
        .map_err(|err| UpdateSignaturesError::DatabaseStage(err.to_string()))?;
    match inspect_database(staging.path()) {
        Ok(DatabaseState::Valid) => {}
        Ok(_) => {
            return Err(UpdateSignaturesError::DatabaseStage(
                "staged signature database failed validation".to_string(),
            ));
        }
        Err(err) => return Err(UpdateSignaturesError::DatabaseStage(err.to_string())),
    }

    if state != DatabaseState::Missing {
        let permissions = std::fs::metadata(db_path)
            .map_err(|err| UpdateSignaturesError::DatabaseReplace(err.to_string()))?
            .permissions();
        std::fs::set_permissions(staging.path(), permissions)
            .map_err(|err| UpdateSignaturesError::DatabaseReplace(err.to_string()))?;
    }
    staging
        .as_file()
        .sync_all()
        .map_err(|err| UpdateSignaturesError::DatabaseStage(err.to_string()))?;
    let persisted = staging
        .persist(db_path)
        .map_err(|err| UpdateSignaturesError::DatabaseReplace(err.error.to_string()))?;
    persisted
        .sync_all()
        .map_err(|err| UpdateSignaturesError::DatabaseReplace(err.to_string()))?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| UpdateSignaturesError::DatabaseReplace(err.to_string()))?;

    Ok(UpdateSignaturesOutcome::Updated(counts.rows_inserted))
}

#[cfg(tarpaulin)]
pub fn update_signatures_using_malware_bazaar(
    _auth_key: &str,
    _selector: &str,
    _db_path: impl AsRef<Path>,
) -> Result<UpdateSignaturesOutcome, UpdateSignaturesError> {
    Err(UpdateSignaturesError::NetworkUpdateDisabled)
}

fn inspect_database(path: &Path) -> Result<DatabaseState, Box<dyn std::error::Error>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DatabaseState::Missing);
        }
        Err(err) => return Err(err.into()),
    };

    if metadata.file_type().is_symlink() {
        return Err("signature database path must not be a symbolic link".into());
    }
    if !metadata.is_file() {
        return Err("signature database path must be a regular file".into());
    }

    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(format!("SQLite quick_check failed: {quick_check}").into());
    }

    let table_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if table_count == 0 {
        return Ok(DatabaseState::Uninitialised);
    }

    let malware_columns = table_columns(&connection, "malware_hashes")?;
    let expected_malware = [
        "family",
        "file_type",
        "first_seen",
        "imported_at",
        "sha256",
        "source",
    ];
    if malware_columns != expected_malware {
        return Err("signature database has an incompatible malware_hashes schema".into());
    }

    let metadata_columns = table_columns(&connection, "update_metadata")?;
    let legacy_metadata = [
        "last_mode",
        "last_successful_update",
        "rows_inserted",
        "rows_seen",
        "source",
    ];
    let current_metadata = [
        "last_mode",
        "last_request",
        "last_successful_update",
        "rows_inserted",
        "rows_seen",
        "source",
    ];
    if !metadata_columns.is_empty()
        && metadata_columns != legacy_metadata
        && metadata_columns != current_metadata
    {
        return Err("signature database has an incompatible update_metadata schema".into());
    }

    Ok(DatabaseState::Valid)
}

fn table_columns(connection: &Connection, table: &str) -> Result<Vec<String>, rusqlite::Error> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let mut names = columns.collect::<Result<Vec<_>, _>>()?;
    names.sort_unstable();
    Ok(names)
}

/// Function to ensure that all required database tables exist.
fn create_database_tables(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )?;
    connection.execute(CREATE_METADATA_TABLE, [])?;

    let has_last_request = {
        let mut statement = connection.prepare("PRAGMA table_info(update_metadata)")?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
        let mut found = false;

        for column in columns {
            if column? == "last_request" {
                found = true;
                break;
            }
        }

        found
    };

    if !has_last_request {
        let tx = connection.transaction()?;
        tx.execute(
            "ALTER TABLE update_metadata RENAME TO update_metadata_legacy",
            [],
        )?;
        tx.execute(CREATE_METADATA_TABLE, [])?;
        tx.execute(
            r#"
            INSERT INTO update_metadata (
                source,
                last_request,
                last_successful_update,
                last_mode,
                rows_seen,
                rows_inserted
            )
            SELECT
                source,
                last_successful_update,
                last_successful_update,
                last_mode,
                rows_seen,
                rows_inserted
            FROM update_metadata_legacy
            WHERE last_successful_update IS NOT NULL
            "#,
            [],
        )?;
        tx.execute("DROP TABLE update_metadata_legacy", [])?;
        tx.commit()?;
    }

    connection.execute(CREATE_MALWARE_HASH_TABLE, [])?;
    Ok(())
}

/// Open the updater database without implicitly recreating a missing file.
fn open_existing_database(path: impl AsRef<Path>) -> Result<Connection, rusqlite::Error> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
}

/// Atomically enforce the request interval and record an allowed outbound call.
fn claim_malware_bazaar_request(
    path: impl AsRef<Path>,
    mode: &str,
    now: i64,
) -> Result<RequestClaim, Box<dyn std::error::Error>> {
    let mut connection = open_existing_database(path)?;
    let tx = connection.transaction()?;
    let cutoff = now.saturating_sub(MALWARE_BAZAAR_REQUEST_INTERVAL_SECONDS);
    let changed = tx.execute(
        r#"
        INSERT INTO update_metadata (
            source,
            last_request,
            last_successful_update,
            last_mode,
            rows_seen,
            rows_inserted
        )
        VALUES ('malware_bazaar', ?2, NULL, ?1, 0, 0)
        ON CONFLICT(source) DO UPDATE SET
            last_request = excluded.last_request
        WHERE update_metadata.last_request <= ?3
        "#,
        params![mode, now, cutoff],
    )?;

    let claim = if changed == 1 {
        RequestClaim::Allowed
    } else {
        let last_request: i64 = tx.query_row(
            "SELECT last_request FROM update_metadata WHERE source = 'malware_bazaar'",
            [],
            |row| row.get(0),
        )?;
        RequestClaim::RateLimited {
            retry_at: last_request.saturating_add(MALWARE_BAZAAR_REQUEST_INTERVAL_SECONDS),
        }
    };

    tx.commit()?;
    Ok(claim)
}

/// Record the outcome of a successfully completed Malware Bazaar update.
fn record_successful_malware_bazaar_update(
    path: impl AsRef<Path>,
    mode: &str,
    counts: UpdateCounts,
) -> Result<(), Box<dyn std::error::Error>> {
    let rows_seen = i64::try_from(counts.rows_seen)?;
    let rows_inserted = i64::try_from(counts.rows_inserted)?;
    let connection = open_existing_database(path)?;
    let changed = connection.execute(
        r#"
        UPDATE update_metadata
        SET last_successful_update = unixepoch(),
            last_mode = ?1,
            rows_seen = ?2,
            rows_inserted = ?3
        WHERE source = 'malware_bazaar'
        "#,
        params![mode, rows_seen, rows_inserted],
    )?;

    if changed != 1 {
        return Err("Malware Bazaar request metadata is missing".into());
    }

    Ok(())
}

/// Function to grab the most recent malware hashes from Malware Bazaar.
#[cfg(not(tarpaulin))]
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

    match response.query_status {
        MalwareBazaarQueryStatus::Ok => Ok(response.data.unwrap_or_default()),
        MalwareBazaarQueryStatus::NoResults => Ok(Vec::new()),
        MalwareBazaarQueryStatus::Other(status) => {
            Err(format!("Malware Bazaar query failed: {}", status).into())
        }
    }
}

/// Function to grab all of the malware hashes from Malware Bazaar.
#[cfg(not(tarpaulin))]
fn fetch_malware_bazaar_full_hashes(
    auth_key: &str,
    db_path: impl AsRef<Path>,
) -> Result<UpdateCounts, Box<dyn std::error::Error>> {
    let url = format!(
        "https://mb-api.abuse.ch/v2/files/exports/{}/sha256_full.txt.zip",
        auth_key
    );
    let mut response = ureq::get(&url).call()?;
    let expected_length = response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());

    // Create a temporary file to store the large zip on disk while processing it.
    let mut tmp = tempfile::tempfile()?;
    let downloaded_length = copy(&mut response.body_mut().as_reader(), &mut tmp)?;
    if let Some(expected_length) = expected_length
        && expected_length != downloaded_length
    {
        return Err(format!(
            "Malware Bazaar full export was truncated: expected {expected_length} bytes, received {downloaded_length}"
        )
        .into());
    }

    tmp.seek(SeekFrom::Start(0))?;

    let mut archive = zip::ZipArchive::new(tmp)?;

    let mut file = archive.by_name("full_sha256.txt")?;
    let reader = BufReader::new(&mut file);

    insert_hash_lines(db_path, reader)
}

fn validate_recent_samples(
    samples: &[MalwareBazaarSample],
) -> Result<(), Box<dyn std::error::Error>> {
    for (index, sample) in samples.iter().enumerate() {
        if decode_sha256_hex(&sample.sha256_hash).is_none() {
            return Err(format!("sample {index} contains an invalid SHA-256 hash").into());
        }
        if sample.first_seen.is_some()
            && parse_malware_bazaar_timestamp(sample.first_seen.as_deref()).is_none()
        {
            return Err(format!("sample {index} contains an invalid first_seen timestamp").into());
        }
    }
    Ok(())
}

/// Function to insert malware hashes from Malware Bazaar into the database.
fn insert_malware_bazaar_hashes(
    db_path: impl AsRef<Path>,
    samples: &[MalwareBazaarSample],
) -> Result<UpdateCounts, Box<dyn std::error::Error>> {
    validate_recent_samples(samples)?;
    let mut connection = open_existing_database(db_path)?;
    let tx = connection.transaction()?;

    let mut inserted = 0;
    let mut seen = 0;

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
            let sha256_bytes = decode_sha256_hex(&sample.sha256_hash)
                .ok_or("validated Malware Bazaar hash unexpectedly became invalid")?;
            seen += 1;

            let first_seen = parse_malware_bazaar_timestamp(sample.first_seen.as_deref());

            let changed = query.execute(params![
                &sha256_bytes[..],
                sample.family,
                first_seen,
                sample.file_type,
            ])?;

            inserted += changed;
        }
    }

    let rows_seen = i64::try_from(seen)?;
    let rows_inserted = i64::try_from(inserted)?;
    let changed = tx.execute(
        r#"
        UPDATE update_metadata
        SET last_successful_update = unixepoch(),
            last_mode = 'recent',
            rows_seen = ?1,
            rows_inserted = ?2
        WHERE source = 'malware_bazaar'
        "#,
        params![rows_seen, rows_inserted],
    )?;
    if changed != 1 {
        return Err("Malware Bazaar request metadata is missing".into());
    }

    tx.commit()?;

    Ok(UpdateCounts {
        rows_seen: seen,
        rows_inserted: inserted,
    })
}

fn insert_hash_lines<R: BufRead>(
    db_path: impl AsRef<Path>,
    reader: R,
) -> Result<UpdateCounts, Box<dyn std::error::Error>> {
    let mut connection = open_existing_database(db_path)?;
    let tx = connection.transaction()?;

    let mut inserted = 0;
    let mut seen = 0;

    {
        let mut stmt = tx.prepare(
            r#"
            INSERT INTO malware_hashes (
                sha256,
                family,
                source,
                first_seen,
                file_type,
                imported_at
            )
            VALUES (?1, NULL, 'malware_bazaar', NULL, NULL, unixepoch())
            ON CONFLICT(sha256) DO NOTHING
            "#,
        )?;

        for line in reader.lines() {
            let line = line?;
            let hash = line.trim();

            if hash.is_empty() || hash.starts_with('#') {
                continue;
            }

            let hash_bytes = decode_sha256_hex(hash)
                .ok_or_else(|| format!("full export contains an invalid SHA-256 hash: {hash}"))?;

            seen += 1;
            inserted += stmt.execute(params![&hash_bytes[..]])?;
        }
    }

    tx.commit()?;

    Ok(UpdateCounts {
        rows_seen: seen,
        rows_inserted: inserted,
    })
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

/// Function to get the number of malware hashes in the database.
fn malware_hash_count(path: impl AsRef<Path>) -> Result<i64, rusqlite::Error> {
    let connection = open_existing_database(path)?;
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM malware_hashes", [], |row| row.get(0))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::cell::Cell;
    use std::io::Cursor;

    struct FakeMalwareBazaarClient {
        recent: Result<Vec<MalwareBazaarSample>, &'static str>,
        full: Result<usize, &'static str>,
        recent_calls: Cell<usize>,
        full_calls: Cell<usize>,
    }

    impl FakeMalwareBazaarClient {
        fn new(
            recent: Result<Vec<MalwareBazaarSample>, &'static str>,
            full: Result<usize, &'static str>,
        ) -> Self {
            Self {
                recent,
                full,
                recent_calls: Cell::new(0),
                full_calls: Cell::new(0),
            }
        }
    }

    impl MalwareBazaarClient for FakeMalwareBazaarClient {
        fn fetch_recent(
            &self,
            _auth_key: &str,
            _selector: &str,
        ) -> Result<Vec<MalwareBazaarSample>, Box<dyn std::error::Error>> {
            self.recent_calls.set(self.recent_calls.get() + 1);
            self.recent.clone().map_err(|err| String::from(err).into())
        }

        fn fetch_full(
            &self,
            _auth_key: &str,
            db_path: &Path,
        ) -> Result<UpdateCounts, Box<dyn std::error::Error>> {
            self.full_calls.set(self.full_calls.get() + 1);
            let count = self.full.map_err(String::from)?;
            let hashes = (0..count)
                .map(|value| format!("{value:064x}\n"))
                .collect::<String>();
            insert_hash_lines(db_path, Cursor::new(hashes))
        }
    }

    fn sample(hash: &str, family: Option<&str>, file_type: Option<&str>) -> MalwareBazaarSample {
        MalwareBazaarSample {
            sha256_hash: hash.to_string(),
            family: family.map(str::to_string),
            first_seen: Some("1970-01-01 00:00:01".to_string()),
            file_type: file_type.map(str::to_string),
        }
    }

    #[test]
    fn malware_bazaar_query_status_deserializes_known_values() {
        let ok: MalwareBazaarResponse =
            serde_json::from_str(r#"{"query_status":"ok","data":[]}"#).unwrap();
        let no_results: MalwareBazaarResponse =
            serde_json::from_str(r#"{"query_status":"no_results"}"#).unwrap();

        assert_eq!(ok.query_status, MalwareBazaarQueryStatus::Ok);
        assert_eq!(no_results.query_status, MalwareBazaarQueryStatus::NoResults);
    }

    #[test]
    fn malware_bazaar_query_status_preserves_unknown_values() {
        let response: MalwareBazaarResponse =
            serde_json::from_str(r#"{"query_status":"illegal_auth_key"}"#).unwrap();

        assert_eq!(
            response.query_status,
            MalwareBazaarQueryStatus::Other("illegal_auth_key".to_string())
        );
    }

    #[test]
    fn decode_sha256_hex_accepts_upper_and_lower_case() {
        let decoded =
            decode_sha256_hex("000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F")
                .unwrap();

        assert_eq!(decoded[0], 0x00);
        assert_eq!(decoded[10], 0x0a);
        assert_eq!(decoded[31], 0x1f);
    }

    #[test]
    fn decode_sha256_hex_combines_high_and_low_nibbles() {
        let decoded =
            decode_sha256_hex("12abf00000000000000000000000000000000000000000000000000000000000")
                .unwrap();

        assert_eq!(decoded[0], 0x12);
        assert_eq!(decoded[1], 0xab);
        assert_eq!(decoded[2], 0xf0);
    }

    #[test]
    fn decode_sha256_hex_does_not_cancel_overlapping_nibbles() {
        let decoded =
            decode_sha256_hex("ff7e810000000000000000000000000000000000000000000000000000000000")
                .unwrap();

        assert_eq!(decoded[0], 0xff);
        assert_eq!(decoded[1], 0x7e);
        assert_eq!(decoded[2], 0x81);
    }

    #[test]
    fn decode_sha256_hex_rejects_bad_length_and_bad_nibbles() {
        assert!(decode_sha256_hex("abc").is_none());
        assert!(
            decode_sha256_hex("zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .is_none()
        );
    }

    #[test]
    fn parse_malware_bazaar_timestamp_handles_valid_missing_and_invalid_values() {
        assert_eq!(
            parse_malware_bazaar_timestamp(Some("1970-01-01 00:00:01")),
            Some(1)
        );
        assert_eq!(parse_malware_bazaar_timestamp(None), None);
        assert_eq!(
            parse_malware_bazaar_timestamp(Some("not a timestamp")),
            None
        );
    }

    #[test]
    fn create_database_tables_creates_non_null_last_request_column() {
        let file = tempfile::NamedTempFile::new().unwrap();

        create_database_tables(file.path()).unwrap();

        let connection = Connection::open(file.path()).unwrap();
        let not_null: i64 = connection
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('update_metadata') WHERE name = 'last_request'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(not_null, 1);
    }

    #[test]
    fn open_existing_database_does_not_recreate_a_missing_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing.sqlite");

        let err = open_existing_database(&path).unwrap_err();

        assert!(!path.exists());
        assert!(err.to_string().contains("open"));
    }

    #[test]
    fn create_database_tables_migrates_legacy_metadata() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(file.path()).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE update_metadata (
                    source TEXT PRIMARY KEY NOT NULL,
                    last_successful_update INTEGER,
                    last_mode TEXT NOT NULL,
                    rows_seen INTEGER NOT NULL,
                    rows_inserted INTEGER NOT NULL
                );
                INSERT INTO update_metadata
                    (source, last_successful_update, last_mode, rows_seen, rows_inserted)
                VALUES ('malware_bazaar', 42, 'full', 10, 8);
                "#,
            )
            .unwrap();
        drop(connection);

        create_database_tables(file.path()).unwrap();

        let connection = Connection::open(file.path()).unwrap();
        let metadata: (i64, i64, String, i64, i64) = connection
            .query_row(
                r#"
                SELECT last_request, last_successful_update, last_mode, rows_seen, rows_inserted
                FROM update_metadata
                WHERE source = 'malware_bazaar'
                "#,
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();

        assert_eq!(metadata, (42, 42, "full".to_string(), 10, 8));
    }

    #[test]
    fn malware_bazaar_request_claim_enforces_interval_boundaries() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();

        assert_eq!(
            claim_malware_bazaar_request(file.path(), "full", 100).unwrap(),
            RequestClaim::Allowed
        );
        assert_eq!(
            claim_malware_bazaar_request(file.path(), "recent", 3_699).unwrap(),
            RequestClaim::RateLimited { retry_at: 3_700 }
        );
        assert_eq!(
            claim_malware_bazaar_request(file.path(), "recent", 3_700).unwrap(),
            RequestClaim::Allowed
        );
    }

    #[test]
    fn malware_bazaar_request_claim_is_shared_across_modes_and_callers() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();

        assert_eq!(
            claim_malware_bazaar_request(file.path(), "full", 10_000).unwrap(),
            RequestClaim::Allowed
        );
        assert_eq!(
            claim_malware_bazaar_request(file.path(), "recent", 10_000).unwrap(),
            RequestClaim::RateLimited { retry_at: 13_600 }
        );
    }

    #[test]
    fn insert_hash_lines_skips_comments_blanks_and_duplicates() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();

        let data = b"
# comment
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
";

        let inserted = insert_hash_lines(file.path(), Cursor::new(data)).unwrap();
        let connection = Connection::open(file.path()).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM malware_hashes", [], |row| row.get(0))
            .unwrap();

        assert_eq!(
            inserted,
            UpdateCounts {
                rows_seen: 3,
                rows_inserted: 2,
            }
        );
        assert_eq!(count, 2);
    }

    #[test]
    fn insert_hash_lines_rejects_invalid_rows_without_partial_inserts() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();
        let data = b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\ninvalid\n";

        assert!(insert_hash_lines(file.path(), Cursor::new(data)).is_err());
        assert_eq!(malware_hash_count(file.path()).unwrap(), 0);
    }

    #[test]
    fn insert_hash_lines_accepts_blank_and_comment_only_input_without_inserting() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();

        let inserted = insert_hash_lines(file.path(), Cursor::new(b"\n # not-a-hash\n\n")).unwrap();

        assert_eq!(
            inserted,
            UpdateCounts {
                rows_seen: 0,
                rows_inserted: 0,
            }
        );
        assert_eq!(malware_hash_count(file.path()).unwrap(), 0);
    }

    #[test]
    fn insert_malware_bazaar_hashes_counts_valid_changed_rows() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();
        claim_malware_bazaar_request(file.path(), "recent", 1).unwrap();
        let samples = [
            sample(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                Some("family-a"),
                Some("elf"),
            ),
            sample(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                Some("family-b"),
                Some("script"),
            ),
        ];

        let inserted = insert_malware_bazaar_hashes(file.path(), &samples).unwrap();
        let connection = Connection::open(file.path()).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM malware_hashes", [], |row| row.get(0))
            .unwrap();
        let family: String = connection
            .query_row(
                "SELECT family FROM malware_hashes WHERE file_type = 'elf'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let first_seen: i64 = connection
            .query_row(
                "SELECT first_seen FROM malware_hashes WHERE file_type = 'elf'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(
            inserted,
            UpdateCounts {
                rows_seen: 2,
                rows_inserted: 2,
            }
        );
        assert_eq!(count, 2);
        assert_eq!(family, "family-a");
        assert_eq!(first_seen, 1);
    }

    #[test]
    fn insert_malware_bazaar_hashes_updates_existing_rows() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();
        claim_malware_bazaar_request(file.path(), "recent", 1).unwrap();
        let hash = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

        assert_eq!(
            insert_malware_bazaar_hashes(file.path(), &[sample(hash, Some("old"), None)]).unwrap(),
            UpdateCounts {
                rows_seen: 1,
                rows_inserted: 1,
            }
        );
        assert_eq!(
            insert_malware_bazaar_hashes(file.path(), &[sample(hash, Some("new"), Some("elf"))])
                .unwrap(),
            UpdateCounts {
                rows_seen: 1,
                rows_inserted: 1,
            }
        );

        let connection = Connection::open(file.path()).unwrap();
        let (count, family, file_type): (i64, String, String) = connection
            .query_row(
                "SELECT COUNT(*), family, file_type FROM malware_hashes",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(family, "new");
        assert_eq!(file_type, "elf");
    }

    #[test]
    fn malware_hash_count_reports_current_database_size() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();

        assert_eq!(malware_hash_count(file.path()).unwrap(), 0);

        insert_hash_lines(
            file.path(),
            Cursor::new(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"),
        )
        .unwrap();

        assert_eq!(malware_hash_count(file.path()).unwrap(), 1);
    }

    #[test]
    fn update_signatures_bootstraps_empty_database_with_full_fetch() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let client = FakeMalwareBazaarClient::new(Ok(vec![]), Ok(7));

        let updated =
            update_signatures_with_client("auth", "selector", file.path(), &client).unwrap();

        assert_eq!(updated, UpdateSignaturesOutcome::Updated(7));
        assert_eq!(client.full_calls.get(), 1);
        assert_eq!(client.recent_calls.get(), 0);
    }

    #[test]
    fn update_signatures_fetches_recent_for_existing_database() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();
        insert_hash_lines(
            file.path(),
            Cursor::new(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"),
        )
        .unwrap();
        let client = FakeMalwareBazaarClient::new(
            Ok(vec![sample(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                Some("family"),
                Some("elf"),
            )]),
            Ok(99),
        );

        let updated =
            update_signatures_with_client("auth", "selector", file.path(), &client).unwrap();

        assert_eq!(updated, UpdateSignaturesOutcome::Updated(1));
        assert_eq!(malware_hash_count(file.path()).unwrap(), 2);
        assert_eq!(client.full_calls.get(), 0);
        assert_eq!(client.recent_calls.get(), 1);
    }

    #[test]
    fn update_signatures_returns_zero_when_recent_fetch_has_no_samples() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();
        insert_hash_lines(
            file.path(),
            Cursor::new(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"),
        )
        .unwrap();
        let client = FakeMalwareBazaarClient::new(Ok(vec![]), Ok(99));

        let updated =
            update_signatures_with_client("auth", "selector", file.path(), &client).unwrap();

        assert_eq!(updated, UpdateSignaturesOutcome::Updated(0));
        assert_eq!(malware_hash_count(file.path()).unwrap(), 1);
        assert_eq!(client.full_calls.get(), 0);
        assert_eq!(client.recent_calls.get(), 1);
    }

    #[test]
    fn update_signatures_records_successful_recent_update_metadata() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();
        insert_hash_lines(
            file.path(),
            Cursor::new(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"),
        )
        .unwrap();
        let client = FakeMalwareBazaarClient::new(
            Ok(vec![sample(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                Some("family"),
                Some("elf"),
            )]),
            Ok(99),
        );

        update_signatures_with_client("auth", "selector", file.path(), &client).unwrap();

        let connection = Connection::open(file.path()).unwrap();
        let metadata: (i64, i64, String, i64, i64) = connection
            .query_row(
                r#"
                SELECT last_request, last_successful_update, last_mode, rows_seen, rows_inserted
                FROM update_metadata
                WHERE source = 'malware_bazaar'
                "#,
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();

        assert!(metadata.0 > 0);
        assert!(metadata.1 >= metadata.0);
        assert_eq!(metadata.2, "recent");
        assert_eq!(metadata.3, 1);
        assert_eq!(metadata.4, 1);
    }

    #[test]
    fn update_signatures_records_failed_request_without_replacing_success_metadata() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();
        insert_hash_lines(
            file.path(),
            Cursor::new(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"),
        )
        .unwrap();
        let connection = Connection::open(file.path()).unwrap();
        connection
            .execute(
                r#"
                INSERT INTO update_metadata (
                    source, last_request, last_successful_update, last_mode, rows_seen, rows_inserted
                )
                VALUES ('malware_bazaar', 1, 1, 'full', 10, 8)
                "#,
                [],
            )
            .unwrap();
        drop(connection);
        let client = FakeMalwareBazaarClient::new(Err("recent failed"), Ok(99));

        let err =
            update_signatures_with_client("auth", "selector", file.path(), &client).unwrap_err();

        assert_eq!(
            err,
            UpdateSignaturesError::RecentFetch("recent failed".to_string())
        );
        let retry =
            update_signatures_with_client("auth", "selector", file.path(), &client).unwrap();
        assert!(matches!(
            retry,
            UpdateSignaturesOutcome::RateLimited { retry_at } if retry_at > chrono::Utc::now().timestamp()
        ));
        assert_eq!(client.recent_calls.get(), 1);

        let connection = Connection::open(file.path()).unwrap();
        let metadata: (i64, Option<i64>, String, i64, i64) = connection
            .query_row(
                r#"
                SELECT last_request, last_successful_update, last_mode, rows_seen, rows_inserted
                FROM update_metadata
                WHERE source = 'malware_bazaar'
                "#,
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();

        assert!(metadata.0 > 1);
        assert_eq!(metadata.1, Some(1));
        assert_eq!(metadata.2, "full");
        assert_eq!(metadata.3, 10);
        assert_eq!(metadata.4, 8);
    }

    #[test]
    fn update_signatures_does_not_request_when_metadata_cannot_be_written() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();
        let connection = Connection::open(file.path()).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TRIGGER reject_metadata_insert
                BEFORE INSERT ON update_metadata
                BEGIN
                    SELECT RAISE(FAIL, 'metadata unavailable');
                END;
                "#,
            )
            .unwrap();
        drop(connection);
        let client = FakeMalwareBazaarClient::new(Ok(vec![]), Ok(7));

        let err =
            update_signatures_with_client("auth", "selector", file.path(), &client).unwrap_err();

        assert!(matches!(err, UpdateSignaturesError::DatabaseMetadata(_)));
        assert_eq!(client.full_calls.get(), 0);
        assert_eq!(client.recent_calls.get(), 0);
    }

    #[test]
    fn update_signatures_propagates_fetch_errors() {
        let empty = tempfile::NamedTempFile::new().unwrap();
        let full_error_client = FakeMalwareBazaarClient::new(Ok(vec![]), Err("full failed"));

        let err =
            update_signatures_with_client("auth", "selector", empty.path(), &full_error_client)
                .unwrap_err();

        assert_eq!(
            err,
            UpdateSignaturesError::FullFetch("full failed".to_string())
        );

        let existing = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(existing.path()).unwrap();
        insert_hash_lines(
            existing.path(),
            Cursor::new(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"),
        )
        .unwrap();
        let recent_error_client = FakeMalwareBazaarClient::new(Err("recent failed"), Ok(99));

        let err = update_signatures_with_client(
            "auth",
            "selector",
            existing.path(),
            &recent_error_client,
        )
        .unwrap_err();

        assert_eq!(
            err,
            UpdateSignaturesError::RecentFetch("recent failed".to_string())
        );
    }

    #[test]
    fn failed_first_bootstrap_does_not_create_the_target_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signatures.db");
        let client = FakeMalwareBazaarClient::new(Ok(vec![]), Err("full failed"));

        let err = update_signatures_with_client("auth", "selector", &path, &client).unwrap_err();

        assert_eq!(
            err,
            UpdateSignaturesError::FullFetch("full failed".to_string())
        );
        assert!(!path.exists());
    }

    #[test]
    fn invalid_existing_database_is_preserved_without_a_network_request() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"not sqlite").unwrap();
        let client = FakeMalwareBazaarClient::new(Ok(vec![]), Ok(1));

        let err =
            update_signatures_with_client("auth", "selector", file.path(), &client).unwrap_err();

        assert!(matches!(err, UpdateSignaturesError::DatabaseValidation(_)));
        assert_eq!(std::fs::read(file.path()).unwrap(), b"not sqlite");
        assert_eq!(client.full_calls.get(), 0);
        assert_eq!(client.recent_calls.get(), 0);
    }

    #[test]
    fn invalid_recent_response_preserves_hashes_and_success_metadata() {
        let file = tempfile::NamedTempFile::new().unwrap();
        create_database_tables(file.path()).unwrap();
        insert_hash_lines(
            file.path(),
            Cursor::new(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"),
        )
        .unwrap();
        let connection = Connection::open(file.path()).unwrap();
        connection
            .execute(
                "INSERT INTO update_metadata VALUES ('malware_bazaar', 1, 1, 'full', 10, 8)",
                [],
            )
            .unwrap();
        drop(connection);
        let client = FakeMalwareBazaarClient::new(
            Ok(vec![sample("invalid", Some("bad"), Some("bad"))]),
            Ok(1),
        );

        let err =
            update_signatures_with_client("auth", "selector", file.path(), &client).unwrap_err();

        assert!(matches!(err, UpdateSignaturesError::InvalidResponse(_)));
        assert_eq!(malware_hash_count(file.path()).unwrap(), 1);
        let connection = Connection::open(file.path()).unwrap();
        let metadata: (Option<i64>, String, i64, i64) = connection
            .query_row(
                "SELECT last_successful_update, last_mode, rows_seen, rows_inserted FROM update_metadata WHERE source = 'malware_bazaar'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(metadata, (Some(1), "full".to_string(), 10, 8));
    }

    #[cfg(unix)]
    #[test]
    fn updater_rejects_database_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.db");
        std::fs::write(&target, b"preserve me").unwrap();
        let link = directory.path().join("signatures.db");
        symlink(&target, &link).unwrap();
        let client = FakeMalwareBazaarClient::new(Ok(vec![]), Ok(1));

        let err = update_signatures_with_client("auth", "selector", &link, &client).unwrap_err();

        assert!(matches!(err, UpdateSignaturesError::DatabaseValidation(_)));
        assert_eq!(std::fs::read(target).unwrap(), b"preserve me");
        assert_eq!(client.full_calls.get(), 0);
    }

    #[test]
    fn update_signatures_error_display_messages_are_stable() {
        let cases = [
            (
                UpdateSignaturesError::DatabaseSetup("setup failed".to_string()),
                "setup failed",
            ),
            (
                UpdateSignaturesError::DatabaseCount("count failed".to_string()),
                "count failed",
            ),
            (
                UpdateSignaturesError::DatabaseMetadata("metadata failed".to_string()),
                "metadata failed",
            ),
            (
                UpdateSignaturesError::FullFetch("full failed".to_string()),
                "full failed",
            ),
            (
                UpdateSignaturesError::RecentFetch("recent failed".to_string()),
                "recent failed",
            ),
            (
                UpdateSignaturesError::DatabaseInsert("insert failed".to_string()),
                "insert failed",
            ),
            (
                UpdateSignaturesError::NetworkUpdateDisabled,
                "network update disabled during coverage",
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    #[cfg(tarpaulin)]
    #[test]
    fn update_signatures_using_malware_bazaar_reports_disabled_update_under_coverage() {
        let err =
            update_signatures_using_malware_bazaar("auth", "100", Path::new("signatures.sqlite"))
                .unwrap_err();

        assert_eq!(err, UpdateSignaturesError::NetworkUpdateDisabled);
    }
}
