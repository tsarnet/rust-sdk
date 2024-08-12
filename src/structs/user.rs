use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{errors::TsarError, Client};

/// User object which gets returned from the `client.authenticate()` function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    /// Name of the user. This could be their display name, username, or null.
    pub name: Option<String>,
    /// Avatar of the user. This can either be an image URL or null.
    pub avatar: Option<String>,

    pub subscription: Subscription,

    /// The current session of the user.
    /// This is used to authenticate any requests from the user after they've been initialized.
    pub session: String,

    // A public decryption key which will be used to verify packets signed by a unique private key that was made from `authentication()`
    // This is NOT the client_key.
    pub session_key: String,
}

/// Subscription object which is used within the `User` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    /// The tier of the user's subscription set by the app's purchase flow. Default is 0.
    pub tier: u32,
    /// Timestamp of when the subscription expires. If null then the subscription is lifetime.
    pub expires: Option<u64>,
}

impl User {
    pub fn heartbeat(&self) -> Result<(), TsarError> {
        self.user_api_call("heartbeat")
    }

    pub fn user_api_call<T: DeserializeOwned>(&self, path: &str) -> Result<T, TsarError> {
        let params = vec![("session", self.session.as_str())];
        Client::encrypted_api_call::<T>(path, &self.session_key, params)
    }
}
