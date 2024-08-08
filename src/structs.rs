use serde::{Deserialize, Serialize};

/// Data returned by the server when initializing.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct InitData {
    pub subscription: Subscription,
    pub timestamp: u64,
    pub hwid: String,
    pub session: String,
}

/// Subscription object which gets returned as part of `authenticate_user()` or `validate_user()`.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    /// Timestamp of when the subscription expires
    pub expires: Option<u64>,
    /// The user which owns the subscription.
    pub user: User,
    /// The tier of the user's subscription, set by the app's purchase flow. Default is 0.
    pub tier: u32,
}

/// User object which gets returned as part of `authenticate_user()` or `validate_user()`.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: Option<String>,
    pub avatar: Option<String>,
}

/// Data returned by the server when validating a client session.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ValidateData {
    pub hwid: String,
    pub timestamp: u64,
}
