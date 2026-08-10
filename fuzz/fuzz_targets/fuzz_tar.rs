#![no_main]

mod common;

use galen::scanner::scan::FuzzArchiveKind;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| common::run(FuzzArchiveKind::Tar, data));
