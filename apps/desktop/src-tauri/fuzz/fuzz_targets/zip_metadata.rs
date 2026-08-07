#![no_main]

use filescope_lib::fuzzing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzzing::zip_metadata(data);
});
