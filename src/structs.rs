use serde::{Deserialize, Serialize};

/// Data returned by the server when fetching a subscription.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Data {
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
    pub expires: Option<i64>,
    /// The user which owns the subscription.
    pub user: User,
}

/// User object which gets returned as part of `authenticate_user()` or `validate_user()`.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: Option<String>,
    pub avatar: Option<String>,
}
