use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

/// The hashes of a single file from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashes {
    pub sha256: [u8; 32],
}

/// Hash a single file.
#[cfg(not(tarpaulin))]
pub fn hash_file_from_disk(path: impl AsRef<Path>) -> Result<FileHashes, std::io::Error> {
    let mut file = File::open(path)?;

    let mut sha256 = Sha256::new();

    // Reused fixed-sized buffer to avoid whole-file allocation.
    let mut buffer = [0u8; 64 * 1024];

    loop {
        // Fill our resuable buffer.
        let bytes_read = file.read(&mut buffer)?;

        // If we didn't read any new bytes then we've reached the end of the file.
        if bytes_read == 0 {
            break;
        }

        // Update our hashes with the next chunk.
        let chunk = &buffer[..bytes_read];
        sha256.update(chunk);
    }

    let sha256_digest = sha256.finalize();

    let mut sha256_out = [0u8; 32];

    sha256_out.copy_from_slice(&sha256_digest);

    Ok(FileHashes { sha256: sha256_out })
}

#[cfg(tarpaulin)]
pub fn hash_file_from_disk(path: impl AsRef<Path>) -> Result<FileHashes, std::io::Error> {
    let bytes = std::fs::read(path)?;
    hash_file_from_memory(&bytes)
}

/// Hash a single file from memory.
pub fn hash_file_from_memory(buffer: &[u8]) -> Result<FileHashes, std::io::Error> {
    let mut sha256 = Sha256::new();
    sha256.update(buffer);

    let sha256_digest = sha256.finalize();

    let mut sha256_out = [0u8; 32];

    sha256_out.copy_from_slice(&sha256_digest);

    Ok(FileHashes { sha256: sha256_out })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn hashes_empty_buffer_to_known_sha256() {
        let hashes = hash_file_from_memory(b"").unwrap();

        assert_eq!(
            hex(&hashes.sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn disk_and_memory_hashes_match() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"galen test payload").unwrap();

        let from_disk = hash_file_from_disk(file.path()).unwrap();
        let from_memory = hash_file_from_memory(b"galen test payload").unwrap();

        assert_eq!(from_disk, from_memory);
    }

    #[test]
    fn disk_hash_handles_empty_files_and_missing_paths() {
        let file = tempfile::NamedTempFile::new().unwrap();

        let hashes = hash_file_from_disk(file.path()).unwrap();

        assert_eq!(
            hex(&hashes.sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(hash_file_from_disk(file.path().with_extension("missing")).is_err());
    }
}
