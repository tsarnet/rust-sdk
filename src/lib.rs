// TSAR
// (c) 2024 TSAR, under MIT license

//! Official Rust SDK for TSAR

mod errors;
mod structs;

#[cfg(test)]
mod tests;

pub use structs::client::Client;
pub use structs::client::ClientOptions;
pub use structs::user::Subscription;
pub use structs::user::User;
