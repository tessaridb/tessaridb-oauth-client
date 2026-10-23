//! The relying party's half: a user sent to the issuer to sign in, and the return checked before anything is
//! exchanged for it.

mod flow;

pub use flow::{Client, Pending, ReturnRefusal, begin};
