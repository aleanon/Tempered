# Fuzzing

Targets for the parsers that read what a client sends. Run one with
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (nightly):

```sh
cargo +nightly fuzz run domain               # addresses, API keys, ids, codes
cargo +nightly fuzz run request_credentials  # Cookie / Authorization headers, JWTs
cargo +nightly fuzz run cookies_agree        # the two cookie readers agree
cargo +nightly fuzz run webauthn             # WebAuthn registration / assertion JSON
```

The entry points are `tempered_adapters::fuzzing` (feature `fuzzing`, not
public API). A crash is a finding: minimise it with `cargo fuzz tmin`, add
the input to the target's unit test, and fix it.
