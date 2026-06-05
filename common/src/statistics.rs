//! Small `no_std` statistics helpers for boot-time measurements.
//!
//! Provides [`average`] and [`std_dev`] over integer samples via the [`Number`] trait,
//! without floating-point arithmetic.
//!
use core::ops::{Add, Div, Mul, Sub};

/// Trait for integer-like numeric types compatible with `no_std`.
/// Required because `core` provides no `.sqrt()` for integers.
pub trait Number:
    Clone
    + Copy
    + Default
    + PartialOrd
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
{
    fn from_usize(val: usize) -> Self;
    fn sqrt(self) -> Self;
}

impl Number for u64 {
    fn from_usize(val: usize) -> Self {
        val as u64
    }

    /// Computes the integer square root using the Babylonian (Newton's) method.
    ///
    /// Returns the largest `n` such that `n² ≤ self`, i.e. `⌊√self⌋`.
    /// Converges quadratically — typically 5–6 iterations for `u64::MAX`.
    /// Uses no floats and no `std`, making it safe for `no_std` targets.
    fn sqrt(self) -> Self {
        if self == 0 {
            return 0;
        }
        let mut x = self;
        let mut y = (x + 1) / 2;
        while y < x {
            x = y;
            y = (self / x + x) / 2;
        }
        x
    }
}

/// Returns the arithmetic mean of `values`.
pub fn average<N: Number>(values: &[N]) -> N {
    if values.is_empty() {
        return N::default();
    }

    let sum = values.iter().copied().fold(N::default(), Add::add);

    sum / N::from_usize(values.len())
}

/// Returns the sample standard deviation of `values`.
///
/// Uses Bessel's correction (divides by `n − 1`), so at least 2 elements
/// are required — returns `None` otherwise.
pub fn std_dev<N: Number>(values: &[N]) -> Option<N> {
    if values.len() < 2 {
        return None;
    }

    let avg = average(values);

    let variance_sum = values.iter().copied().fold(N::default(), |acc, x| {
        let diff = if x >= avg { x - avg } else { avg - x };
        acc + diff * diff
    });

    // Bessel's correction
    let variance = variance_sum / N::from_usize(values.len() - 1);

    Some(variance.sqrt())
}
