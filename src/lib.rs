// tsar
// (c) 2024 tsar, under MIT license

//! Official wrapper for the TSAR client API.

use base64::prelude::*;
use errors::{AuthError, ValidateError};
use hardware_id::get_id;
use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use reqwest::StatusCode;
use serde_json::Value;
use std::{
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod errors;

// Tester
#[cfg(test)]
mod tests {
    //  cargo test -- --nocapture

    use crate::Client;

    // These values are not valid on the public server, so make sure to change them if you want to run tests.
    const PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExtzBFzUUFyoXJO6nbJnS6fe67uJzcmOQFn/4cyf+4/4AB+oa375h75XVPJMrj0qHK8F+C+oZZXlXGm49tIAH5Q==";
    const APP_ID: &str = "5009e261-eac2-493e-a5d7-fa15e14f12a1";

    #[test]
    fn authenticate_user() {
        let api = Client::new(APP_ID, PUBLIC_KEY);

        let result = api.authenticate_user();

        if result.is_err() {
            println!("Test Error: {:?}", result.unwrap_err());
            assert!(false);
        }

        assert!(true);
    }
}

/// The TSAR Client struct. Used to interact with the API.
pub struct Client {
    /// The ID of your TSAR app. Should be in UUID format: 00000000-0000-0000-0000-000000000000
    app_id: String,
    // The public decryption key for your TSAR app. Should be in base64 format.
    public_key: String,
}

impl Client {
    /// Creates a new TSAR client using the `app_id` and `public_key` variables.
    pub fn new(app_id: &str, public_key: &str) -> Self {
        Self {
            app_id: app_id.to_string(),
            public_key: public_key.to_string(),
        }
    }

    /// Starts an authentication flow which attempts to authenticate the user.
    /// If the user's HWID is not already authorized, the function opens the user's default browser to authenticate them.
    pub fn authenticate_user(&self) -> Result<(), AuthError> {
        let hwid = get_id().map_err(|_| AuthError::FailedToGetHWID).unwrap();

        match self.validate_user(hwid.as_str()) {
            Ok(_) => return Ok(()),

            // Only continue execution if the user is not found, if any other part of the validate_user function fails then return an error
            Err(err) => match err {
                ValidateError::UserNotFound => {}
                _ => return Err(AuthError::ValidateError(err)),
            },
        };

        if let Err(_) = open::that(format!("https://tsar.cc/auth/{}/{}", self.app_id, hwid)) {
            return Err(AuthError::FailedToOpenBrowser);
        }

        let start_time = Instant::now();

        loop {
            thread::sleep(Duration::from_millis(5000));

            match self.validate_user(hwid.as_str()) {
                Ok(_) => return Ok(()),

                // Only continue execution if the user is not found, if any other part of the validate_user function fails then return an error
                Err(err) => match err {
                    ValidateError::UserNotFound => {}
                    _ => return Err(AuthError::ValidateError(err)),
                },
            };

            if start_time.elapsed() >= Duration::from_secs(600) {
                return Err(AuthError::Timeout);
            }
        }
    }

    /// Check if the passed HWID is authorized to use the application.
    pub fn validate_user(&self, hwid: &str) -> Result<(), ValidateError> {
        let url = format!(
            "https://tsar.cc/api/client/v1/apps/{}/subscribers/validate?hwid={}",
            self.app_id, hwid
        );

        let response = reqwest::blocking::get(&url)
            .map_err(|_| ValidateError::RequestFailed)
            .unwrap();

        if !response.status().is_success() {
            match response.status() {
                StatusCode::NOT_FOUND => return Err(ValidateError::UserNotFound),
                _ => return Err(ValidateError::ServerError),
            }
        }

        // Parse body into JSON
        let data = response
            .json::<Value>()
            .map_err(|_| ValidateError::FailedToParseBody)
            .unwrap();

        // Get the base64-encoded data from the response
        let base64_data = data
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or(ValidateError::FailedToGetData)
            .unwrap();

        // Get the base64-encoded signature from the response
        let base64_signature = data
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or(ValidateError::FailedToGetSignature)
            .unwrap();

        // Decode the base64-encoded data (turns into buffer)
        let data_bytes = BASE64_STANDARD
            .decode(base64_data)
            .map_err(|_| ValidateError::FailedToDecodeData)
            .unwrap();

        // Get the decoded body in JSON
        let json: Value = serde_json::from_str(
            &String::from_utf8(data_bytes.clone())
                .map_err(|_| ValidateError::FailedToParseData)
                .unwrap(),
        )
        .map_err(|_| ValidateError::FailedToParseData)
        .unwrap();

        // Get the timestamp value
        let timestamp = json
            .get("timestamp")
            .ok_or(ValidateError::FailedToGetTimestamp)
            .unwrap()
            .as_number()
            .ok_or(ValidateError::FailedToParseTimestamp)
            .unwrap()
            .as_u64()
            .ok_or(ValidateError::FailedToParseTimestamp)
            .unwrap();

        // Verify that the timestamp is less than least 30 seconds old
        let timestamp_system_time = UNIX_EPOCH + Duration::from_secs(timestamp / 1000);
        let thirty_seconds_ago = SystemTime::now() - Duration::from_secs(30);

        if timestamp_system_time < thirty_seconds_ago {
            return Err(ValidateError::OldResponse);
        }

        // Decode the base64-encoded signature (turns into buffer)
        let signature_bytes = BASE64_STANDARD
            .decode(base64_signature)
            .map_err(|_| ValidateError::FailedToDecodeSignature)
            .unwrap();

        let pub_key_bytes = BASE64_STANDARD
            .decode(self.public_key.as_str())
            .map_err(|_| ValidateError::FailedToDecodePubKey)
            .unwrap();

        // Build key from public key pem
        let v_pub_key: VerifyingKey =
            VerifyingKey::from_public_key_der(pub_key_bytes[..].try_into().unwrap())
                .map_err(|_| ValidateError::FailedToBuildKey)
                .unwrap();

        // Build signature from buffer
        let mut signature = Signature::from_der(signature_bytes[..].try_into().unwrap())
            .map_err(|_| ValidateError::FailedToBuildSignature)
            .unwrap();

        // NodeJS sucks so we need to normalize the sig
        signature = signature.normalize_s().unwrap_or(signature);

        // Verify the signature
        let result = v_pub_key.verify(&data_bytes, &signature);

        if result.is_ok() {
            return Ok(());
        }

        Err(ValidateError::InvalidSignature)
    }
}
