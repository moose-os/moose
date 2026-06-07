//! Small `no_std` statistics helpers for boot-time measurements.
//!
//! Provides [`average`] and [`std_dev`] over integer samples via the [`Number`] trait,
//! without floating-point arithmetic.
//!
use core::{
    fmt::Debug,
    ops::{Add, Div, Mul, Rem, Sub},
};

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
    + Rem<Output = Self>
    + TryFrom<usize>
{
    const ZERO: Self;
    const ONE: Self;
    const TWO: Self;

    /// Computes the integer square root using the Babylonian (Newton's) method.
    ///
    /// Returns the largest `n` such that `n² ≤ self`, i.e. `⌊√self⌋`.
    /// Converges quadratically — typically 5–6 iterations for `u64::MAX`.
    /// Uses no floats and no `std`, making it safe for `no_std` targets.
    fn sqrt(self) -> Self {
        if self == Self::ZERO {
            return Self::ZERO;
        }
        let mut x = self;
        let mut y = (x + Self::ONE) / Self::TWO;
        while y < x {
            x = y;
            y = (self / x + x) / Self::TWO;
        }
        x
    }
}

impl Number for u64 {
    const ZERO: Self = 0;
    const ONE: Self = 1;
    const TWO: Self = 2;
}

/// Returns the arithmetic mean of `values`.
pub fn average<N: Number>(values: &[N]) -> N
where
    <N as TryFrom<usize>>::Error: Debug,
{
    if values.is_empty() {
        return N::default();
    }

    let sum = values.iter().copied().fold(N::default(), Add::add);
    let n = N::try_from(values.len()).unwrap();

    sum / n
}

/// Returns the sample standard deviation of `values`.
///
/// Uses Bessel's correction (divides by `n − 1`), so at least 2 elements
/// are required — returns `None` otherwise.
pub fn std_dev<N: Number>(values: &[N]) -> Option<N>
where
    <N as TryFrom<usize>>::Error: Debug,
{
    if values.len() < 2 {
        return None;
    }

    let avg = average(values);

    let variance_sum = values.iter().copied().fold(N::default(), |acc, x| {
        let diff = if x >= avg { x - avg } else { avg - x };
        acc + diff * diff
    });

    // Bessel's correction
    let variance = variance_sum / N::try_from(values.len() - 1).unwrap();

    Some(variance.sqrt())
}
