use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

/// The hashes of a single file from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashes {
    pub sha256: [u8; 32],
}

/// Hash a single file.
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

/// Hash a single file from memory.
pub fn hash_file_from_memory(buffer: &[u8]) -> Result<FileHashes, std::io::Error> {
    let mut sha256 = Sha256::new();
    sha256.update(buffer);

    let sha256_digest = sha256.finalize();

    let mut sha256_out = [0u8; 32];

    sha256_out.copy_from_slice(&sha256_digest);

    Ok(FileHashes { sha256: sha256_out })
}
