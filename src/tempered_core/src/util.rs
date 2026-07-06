//! Small shared utilities.

/// Length-independent comparison to avoid leaking a secret via timing.
///
/// Compares every byte regardless of where the first mismatch occurs, so the
/// running time reveals nothing about *how much* of the input matched. Use it
/// whenever one side of the comparison is attacker-supplied and the other is
/// secret (API keys, 2FA codes, OAuth state, session-subject checks).
///
/// The length check short-circuits: length is not treated as secret here.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_strings_match() {
        assert!(constant_time_eq("abc123", "abc123"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn different_strings_do_not_match() {
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("abc", ""));
    }
}
