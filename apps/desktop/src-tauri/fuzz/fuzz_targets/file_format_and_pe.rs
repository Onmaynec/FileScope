#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| filescope_lib::fuzzing::file_format_and_pe(data));
