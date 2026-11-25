#![no_main]
//! Addresses, API keys, session ids, mailed tokens and 2FA codes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| tempered_adapters::fuzzing::domain(input));
