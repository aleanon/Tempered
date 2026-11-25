#![no_main]
//! The `Cookie` and `Authorization` headers, and the JWTs they carry.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&[u8], &[u8])| {
    tempered_adapters::fuzzing::request_credentials(input.0, input.1);
});
