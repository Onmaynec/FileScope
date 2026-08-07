#![no_main]

use filescope_lib::fuzzing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzzing::file_format_and_pe(data);
});
