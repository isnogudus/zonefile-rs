// Compile-time check: At least one format must be enabled
#[cfg(not(any(feature = "yaml", feature = "toml")))]
compile_error!("At least one of the features 'yaml' or 'toml' must be enabled");
#[cfg(not(any(feature = "nsd", feature = "unbound")))]
compile_error!("At least one of the features 'nsd' or 'unbound' must be enabled");

pub mod args;
pub mod constants;
pub mod output;
pub mod parser;
pub mod record;
pub mod serial;
pub mod transform;
pub mod validation;
