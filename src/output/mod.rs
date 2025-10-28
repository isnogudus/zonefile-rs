#[cfg(feature = "nsd")]
pub mod nsd;
#[cfg(feature = "unbound")]
pub mod unbound;

/// Column width for name field in Unbound output
#[cfg(feature = "unbound")]
pub const UNBOUND_COLUMN_WIDTH: usize = 46;

/// Column width for name field in NSD output
#[cfg(feature = "nsd")]
pub const NSD_COLUMN_WIDTH: usize = 32;

