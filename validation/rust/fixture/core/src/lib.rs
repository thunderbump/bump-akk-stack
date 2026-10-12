#![forbid(unsafe_code)]

/// A deterministic value call for the bridge qualification.
/// ```
/// assert_eq!(eqemu_rust_proof_core::answer(41), 42);
/// ```
pub fn answer(value: u32) -> u32 {
    value.saturating_add(1)
}

#[cfg(test)]
mod tests {
    #[test]
    fn preserves_the_bound() {
        assert_eq!(super::answer(u32::MAX), u32::MAX);
    }
}
