use sha2::{Digest, Sha256};
use std::io::Read;

/// The hashes of a single file from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashes {
    pub sha256: [u8; 32],
}

/// Hash bytes from an already-open reader.
pub fn hash_file_from_reader(mut reader: impl Read) -> Result<FileHashes, std::io::Error> {
    let mut sha256 = Sha256::new();

    // Reused fixed-sized buffer to avoid whole-file allocation.
    let mut buffer = [0u8; 64 * 1024];

    loop {
        // Fill our resuable buffer.
        let bytes_read = reader.read(&mut buffer)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Error, ErrorKind};

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> Result<usize, Error> {
            Err(Error::new(ErrorKind::Other, "read failed"))
        }
    }

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
    fn reader_and_memory_hashes_match() {
        let from_reader = hash_file_from_reader(Cursor::new(b"galen test payload")).unwrap();
        let from_memory = hash_file_from_memory(b"galen test payload").unwrap();

        assert_eq!(from_reader, from_memory);
    }

    #[test]
    fn reader_hash_reads_all_chunks_for_large_inputs() {
        let mut payload = Vec::new();
        for i in 0..70_000 {
            payload.push((i % 251) as u8);
        }

        let from_reader = hash_file_from_reader(Cursor::new(&payload)).unwrap();
        let from_memory = hash_file_from_memory(&payload).unwrap();

        assert_eq!(from_reader, from_memory);
        assert_ne!(
            from_reader,
            hash_file_from_memory(&payload[..64 * 1024]).unwrap()
        );
    }

    #[test]
    fn reader_hash_handles_empty_input() {
        let hashes = hash_file_from_reader(Cursor::new([])).unwrap();

        assert_eq!(
            hex(&hashes.sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn reader_hash_propagates_read_errors() {
        let err = hash_file_from_reader(FailingReader).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Other);
    }
}
