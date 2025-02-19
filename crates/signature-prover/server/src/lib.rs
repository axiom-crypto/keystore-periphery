mod api;
pub use api::*;

mod cli;
pub use cli::*;

mod server;
pub use server::{load_server_config, SignatureProverServer};

pub mod error;

pub mod keystore_types;

mod types;
pub use types::*;

/// Traits to implement for additional validation logic for the signature prover proving server.
/// These validations are meant to be done before the more computationally intensive proof generation
/// to ensure only correctly formatted inputs are used for proving.
pub mod validator;
