#![no_main]
//! The validators' and the route table's cookie readers agree.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&str, &[u8])| {
    tempered_adapters::fuzzing::cookies_agree(input.1, input.0);
});
