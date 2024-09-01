use thiserror::Error;

/// TSAR Errors.
#[derive(Debug, Error)]
pub enum TsarError {
    /// The App ID provided is not in the right format. Must be in UUID (00000000-0000-0000-0000-000000000000) format.
    #[error("Invalid App ID format. Must be in UUID format.")]
    InvalidAppId,
    /// The Client Key provided is not in the right format. Must be in Base64 (MFk...qA==) format.
    #[error("Invalid Client Key format. Must be in Base64 format.")]
    InvalidClientKey,

    /// Failed to get the user's HWID.
    #[error("Failed to get HWID.")]
    FailedToGetHWID,

    /// Failed to get the program's hash.
    #[error("Failed to get program's hash.")]
    FailedToGetHash,

    /// A public key is invalid.
    #[error("Invalid public key. Make sure that your key starts with \"MFk...\".")]
    InvalidPublicKey,

    /// Failed to send a request to the TSAR API.
    #[error("Failed to send a request to the TSAR API.")]
    RequestFailed,

    /// Failed to decode TSAR API response.
    #[error("Failed to decode TSAR API response.")]
    FailedToDecode,

    /// Data returned from TSAR API does not match local data.
    #[error("Data returned from TSAR API does not match local data.")]
    StateMismatch,

    /// The API response has been tampered with.
    #[error("The API response has been tampered with.")]
    TamperedResponse,

    /// The TSAR API returned a 400: Bad Request status code.
    /// This means that the parameters passed to the endpoint were not correct.
    #[error("Bad request.")]
    BadRequest,
    /// The TSAR API returned a 404: Not Found status code.
    /// This means that the API failed to find a resource.
    #[error("App not found.")]
    AppNotFound,
    /// The TSAR API returned a 403: Forbidden status code.
    /// This means that the program's hash did not match to a valid app asset.
    #[error("The program hash is not authorized.")]
    HashUnauthorized,
    /// The TSAR API returned a 401: Unauthorized status code.
    /// This means that the user's HWID did not match to a subscription object.
    #[error("Your HWID is not authorized.")]
    Unauthorized,
    /// The TSAR API returned a 429: Too Many Requests status code.
    /// This means that you're sending requests too fast.
    #[error("You are being rate limited.")]
    RateLimited,
    /// The TSAR API returned a 503: Service Unavailable status code.
    /// This means that the app is paused.
    #[error("The app is paused.")]
    AppPaused,
    /// The TSAR API returned a server error.
    /// This is a catch-all for unusual error cases.
    #[error("Server error.")]
    ServerError,
}
