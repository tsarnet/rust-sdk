use thiserror::Error;

/// Possible failure cases for [Client::authenticate_user()].
#[derive(Debug, Error)]
pub enum AuthError {
    /// Failed to open the user's default browser.
    #[error("Failed to open browser.")]
    FailedToOpenBrowser,
    /// Failed to get the user's HWID.
    #[error("Failed to get HWID.")]
    FailedToGetHWID,
    /// User did not authenticate for over 10 minutes, client automatically timed out.
    #[error("User did not authenticate for over 10 minutes.")]
    Timeout,

    #[error(transparent)]
    ValidateError(#[from] ValidateError),
}

/// Possible failure cases for [Client::validate_user()].
#[derive(Debug, Error)]
pub enum ValidateError {
    /// Request to the TSAR server failed, server may be down.
    #[error("Request to the TSAR server failed.")]
    RequestFailed,
    /// The HWID passed does not match to a user.
    #[error("The HWID passed does not match to a user.")]
    UserNotFound,
    /// TSAR server had an error and did not return an OK status.
    #[error("TSAR server did not return OK.")]
    ServerError,
    /// Failed to parse returned body into JSON.
    #[error("Failed to parse returned body into JSON.")]
    FailedToParse,

    /// Failed to get the `data` field from the parsed JSON body.
    #[error("Failed to get the data field from the parsed JSON body.")]
    FailedToGetData,
    /// Failed to get the `signature` field from the parsed JSON body.
    #[error("Failed to get the signature field from the parsed JSON body.")]
    FailedToGetSignature,

    /// Failed to decode the `data` field from the parsed JSON body.
    #[error("Failed to decode the data field from the parsed JSON body.")]
    FailedToDecodeData,
    /// Failed to decode the `signature` field from the parsed JSON body.
    #[error("Failed to decode the signature field from the parsed JSON body.")]
    FailedToDecodeSignature,
    /// Failed to decode the public key from base64.
    #[error("Failed to decode the public key from base64.")]
    FailedToDecodePubKey,

    /// Failed to build the verifying key using der.
    #[error("Failed to build the verifying key using der.")]
    FailedToBuildKey,
    /// Failed to build signature using buffer.
    #[error("Failed to build signature using buffer.")]
    FailedToBuildSignature,

    /// Signature is not authentic. Data may have been tampered with.
    #[error("Signature is not authentic.")]
    InvalidSignature,
}
