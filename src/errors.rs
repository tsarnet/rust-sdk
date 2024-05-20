use thiserror::Error;

/// Possible failure cases for [Client::new()].
#[derive(Debug, Error)]
pub enum InitError {
    /// Failed to get the user's HWID.
    #[error("Failed to get HWID.")]
    FailedToGetHWID,

    #[error(transparent)]
    ValidateError(#[from] ValidateError),
}

/// Possible failure cases for [Client::authenticate_user()].
#[derive(Debug, Error)]
pub enum AuthError {
    /// Failed to open the user's default browser.
    #[error("Failed to open browser.")]
    FailedToOpenBrowser,
    /// User is not authorized to use the application.
    #[error("User is not authorized to use the application.")]
    Unauthorized,

    #[error(transparent)]
    ValidateError(#[from] ValidateError),
}

/// Possible failure cases from communicating to the API
#[derive(Debug, Error)]
pub enum ValidateError {
    /// Request to the TSAR server failed, server may be down.
    #[error("Request to TSAR server failed.")]
    RequestFailed,
    /// The APP ID passed does not match to a TSAR APP.
    #[error("App ID not found.")]
    AppNotFound,
    /// The HWID passed does not match to a user.
    #[error("HWID does not match to user.")]
    UserNotFound,
    /// TSAR server had an error and did not return an OK status.
    #[error("TSAR server did not return OK.")]
    ServerError,
    /// Failed to parse returned body into JSON.
    #[error("Failed to parse returned body into JSON.")]
    FailedToParseBody,

    /// Failed to get the `data` field from the parsed JSON body.
    #[error("Failed to get data field from parsed JSON body.")]
    FailedToGetData,
    /// Failed to get the `signature` field from the parsed JSON body.
    #[error("Failed to get signature field from parsed JSON body.")]
    FailedToGetSignature,

    /// Failed to decode the `data` field from the parsed JSON body.
    #[error("Failed to decode data field from parsed JSON body.")]
    FailedToDecodeData,
    /// Failed to decode the `signature` field from the parsed JSON body.
    #[error("Failed to decode signature field from parsed JSON body.")]
    FailedToDecodeSignature,
    /// Failed to decode the client key from base64.
    #[error("Failed to decode client key from base64.")]
    FailedToDecodePubKey,

    /// Failed to parse the `data` field into JSON.
    #[error("Failed to parse data field into JSON.")]
    FailedToParseData,
    /// Failed to get the `timestamp` field.
    #[error("Failed to get timestamp field.")]
    FailedToGetTimestamp,
    /// Failed to parse the `timestamp` field into u64.
    #[error("Failed to parse timestamp field into u64.")]
    FailedToParseTimestamp,

    /// Failed to build the verification key using der.
    #[error("Failed to build verification key using der.")]
    FailedToBuildKey,
    /// Failed to build signature using buffer.
    #[error("Failed to build signature using buffer.")]
    FailedToBuildSignature,

    /// Local HWID and HWID returned from server dont match.
    #[error("Local HWID and HWID returned from server dont match.")]
    HWIDMismatch,
    /// The response is old. Data may have been tampered with.
    #[error("Response is old.")]
    OldResponse,
    /// Signature is not authentic. Data may have been tampered with.
    #[error("Signature is not authentic.")]
    InvalidSignature,
}
