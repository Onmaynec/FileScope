#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| filescope_lib::fuzzing::passive_url(data));
