//! A client for a TessariDB OAuth issuer: a resource server's validation of the access tokens it is handed, and in
//! time a relying party's sign-in. It speaks the protocol and nothing of the server's code.

mod error;
pub mod resource;

pub use error::{Error, Result};
