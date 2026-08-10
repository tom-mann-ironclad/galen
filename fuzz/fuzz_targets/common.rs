use flate2::{Compression, write::GzEncoder};
use galen::scanner::{
    database::HashDatabase,
    scan::{FuzzArchiveKind, ScanConfig, fuzz_archive_bytes},
};
use std::{
    cell::RefCell,
    io::Write,
    sync::OnceLock,
    time::Duration,
};

const FUZZ_SCAN_CONFIG: ScanConfig = ScanConfig {
    max_archive_depth: 3,
    max_archive_entries: 128,
    max_decompressed_file_size_bytes: 256 * 1024,
    max_file_size_bytes: 1024 * 1024,
    zip_eocd_min_size_bytes: 22,
    zip_max_comment_size_bytes: u16::MAX as usize,
    zip64_eocd_locator_size_bytes: 20,
    retained_entry_buffer_limit_bytes: 64 * 1024,
    yara_scan_timeout: Duration::from_secs(1),
};

static RULES: OnceLock<yara_x::Rules> = OnceLock::new();

thread_local! {
    static SCANNER: RefCell<yara_x::Scanner<'static>> = RefCell::new({
        let rules = RULES.get_or_init(|| {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source("rule fuzz_never_matches { condition: false }")
            .expect("the fixed fuzzing rule must compile");
        compiler.build()
        });
        let mut scanner = yara_x::Scanner::new(rules);
        scanner.set_timeout(FUZZ_SCAN_CONFIG.yara_scan_timeout);
        scanner
    });
}

pub fn run(kind: FuzzArchiveKind, input: &[u8]) {
    let bytes = if input.first() == Some(&0) {
        make_valid_archive(kind, &input[1..])
    } else {
        input.to_vec()
    };
    let database = HashDatabase::default();

    SCANNER.with(|scanner| {
        let mut scanner = scanner.borrow_mut();
        let _ = fuzz_archive_bytes(
            kind,
            &bytes,
            &database,
            &mut scanner,
            FUZZ_SCAN_CONFIG,
        );
    });
}

fn make_valid_archive(kind: FuzzArchiveKind, payload: &[u8]) -> Vec<u8> {
    match kind {
        FuzzArchiveKind::Zip => make_zip(payload),
        FuzzArchiveKind::Tar => make_tar(payload),
        FuzzArchiveKind::Gzip => make_gzip(payload),
    }
}

fn make_zip(payload: &[u8]) -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);
    writer.start_file("payload.bin", options).unwrap();
    writer.write_all(payload).unwrap();
    writer.finish().unwrap().into_inner()
}

fn make_tar(payload: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(payload.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "payload.bin", payload)
        .unwrap();
    builder.into_inner().unwrap()
}

fn make_gzip(payload: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(payload).unwrap();
    encoder.finish().unwrap()
}
