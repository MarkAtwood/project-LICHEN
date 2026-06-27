//! Common error types shared across LICHEN crates.
//!
//! Provides structured error types for common parsing failures to enable
//! consistent error messages and proper error chaining.

use core::fmt;

/// Error indicating input data was shorter than expected.
///
/// Used by parsers across the stack when a buffer doesn't contain enough
/// bytes. The `expected` field indicates the minimum bytes required and
/// `actual` indicates how many were present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooShort {
    /// Minimum number of bytes expected.
    pub expected: usize,
    /// Actual number of bytes present.
    pub actual: usize,
}

impl TooShort {
    /// Create a new TooShort error.
    #[inline]
    pub const fn new(expected: usize, actual: usize) -> Self {
        Self { expected, actual }
    }
}

impl fmt::Display for TooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "buffer too short: expected {} bytes, got {}",
            self.expected, self.actual
        )
    }
}

impl core::error::Error for TooShort {}

/// Error indicating an output buffer is too small to hold the result.
///
/// Similar to TooShort but for output operations rather than parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall {
    /// Minimum buffer size required.
    pub required: usize,
    /// Actual buffer size provided.
    pub provided: usize,
}

impl BufferTooSmall {
    /// Create a new BufferTooSmall error.
    #[inline]
    pub const fn new(required: usize, provided: usize) -> Self {
        Self { required, provided }
    }
}

impl fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "output buffer too small: need {} bytes, have {}",
            self.required, self.provided
        )
    }
}

impl core::error::Error for BufferTooSmall {}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    #[test]
    fn too_short_display() {
        let err = TooShort::new(10, 5);
        assert_eq!(
            format!("{}", err),
            "buffer too short: expected 10 bytes, got 5"
        );
    }

    #[test]
    fn buffer_too_small_display() {
        let err = BufferTooSmall::new(100, 50);
        assert_eq!(
            format!("{}", err),
            "output buffer too small: need 100 bytes, have 50"
        );
    }
}
