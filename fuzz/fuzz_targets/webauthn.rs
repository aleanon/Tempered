#![no_main]
//! The browser's registration and assertion JSON.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|json: &[u8]| tempered_adapters::fuzzing::webauthn(json));
