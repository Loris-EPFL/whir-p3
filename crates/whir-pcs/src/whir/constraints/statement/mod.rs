/// Equality statement for polynomial evaluation constraints.
pub mod eq;
pub mod initial;
pub mod linear;

/// Selection statement for conditional constraints.
pub mod select;

// Re-export main types for convenient access.
pub use eq::EqStatement;
pub use initial::InitialClaim;
pub use linear::LinearStatement;
pub use select::SelectStatement;
