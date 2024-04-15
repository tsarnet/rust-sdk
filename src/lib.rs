// TSAR
// (c) 2024 TSAR, under MIT license

//! Official wrapper for the TSAR client API.

#![allow(non_camel_case_types)]

use base64::prelude::*;
use errors::{AuthError, ValidateError};
use goldberg::goldberg_stmts;
use hardware_id::get_id;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use reqwest::StatusCode;
use rsntp::SntpClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(all(target_os = "linux", not(debug_assertions)))]
use debugoff;

macro_rules! dbo {
    () => {
        #[cfg(all(target_os = "linux", not(debug_assertions)))]
        debugoff::multi_ptraceme_or_die();
    };
}

mod errors;

// Tester [ cargo test -- --nocapture ]
#[cfg(test)]
mod tests {
    use crate::Client;

    const PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELlyGTmNEv3AarudyshJUUA9ig1pOfSl5qWX8g/hkPiieeKlWvv9o4IZmWI4cCrcR0fteVEcUhBvu5GAr/ITBqA==";
    const APP_ID: &str = "58816206-b24c-41d4-a594-8500746a78ee";

    #[test]
    fn authenticate_user() {
        let api = Client::new(APP_ID, PUBLIC_KEY);

        match api.authenticate_user() {
            Ok(data) => println!("\x1b[32m[TEST SUCCESS] Data\x1b[0m: {:?}", data),
            Err(err) => println!("\x1b[31m[TEST ERROR] {:?}\x1b[0m: {}", err, err),
        }

        assert!(true);
    }
}

/// Data returned by the server when running `authenticate_user()` or `validate_user()`.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Data {
    pub user: User,
    pub subscription: Subscription,
    pub timestamp: u64,
    pub hwid: String,
}

/// User object which gets returned as part of `authenticate_user()` or `validate_user()`.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: Option<String>,
    pub avatar: Option<String>,
}

/// Subscription object which gets returned as part of `authenticate_user()` or `validate_user()`.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    /// Timestamp of when the subscription expires
    pub expires: Option<i64>,
}

/// The TSAR Client struct. Used to interact with the API after it's initialized.
pub struct Client {
    /// The ID of your TSAR app. Should be in UUID format: 00000000-0000-0000-0000-000000000000
    pub app_id: String,
    /// The public decryption key for your TSAR app. Should be in base64 format.
    pub client_key: String,
}

impl Client {
    /// Creates a new TSAR client using an `app_id` and `client_key` variables.
    pub fn new(app_id: &str, client_key: &str) -> Self {
        goldberg_stmts! {{
            Self {
                app_id: app_id.to_string(),
                client_key: client_key.to_string(),
            }
        }}
    }

    /// Starts an authentication flow which attempts to authenticate the user.
    /// If the user's HWID is not already authorized, the function opens the user's default browser to authenticate them.
    pub fn authenticate_user(&self) -> Result<Data, AuthError> {
        let hwid = goldberg_stmts! {{
            dbo!();

            get_id().or(Err(AuthError::FailedToGetHWID))?
        }};

        // Attempt to validate user
        match self.validate_user(hwid.as_str()) {
            Ok(data) => return Ok(data),

            // Only continue execution if the user is not found, if any other part of the validate_user function fails then return an error
            Err(err) => match err {
                ValidateError::UserNotFound => {}
                _ => return Err(AuthError::ValidateError(err)),
            },
        };

        goldberg_stmts! {{
            dbo!();

            // Open default browser
            if let Err(_) = open::that(format!("https://tsar.cc/auth/{}/{}", self.app_id, hwid)) {
                return Err(AuthError::FailedToOpenBrowser);
            }
        }};

        // Start validation loop
        let start_time = goldberg_stmts! {{
            Instant::now()
        }};

        loop {
            thread::sleep(Duration::from_millis(5000));

            dbo!();

            match self.validate_user(hwid.as_str()) {
                Ok(data) => return Ok(data),

                // Only continue execution if the user is not found, if any other part of the validate_user function fails then return an error
                Err(err) => match err {
                    ValidateError::UserNotFound => {}
                    _ => return Err(AuthError::ValidateError(err)),
                },
            };

            goldberg_stmts! {{
                if start_time.elapsed() >= Duration::from_secs(600) {
                    return Err(AuthError::Timeout);
                }
            }};
        }
    }

    /// Check if a HWID is authorized to use the application.
    pub fn validate_user(&self, hwid: &str) -> Result<Data, ValidateError> {
        let pub_key_bytes = goldberg_stmts! {{
            dbo!();

            BASE64_STANDARD
                .decode(self.client_key.as_str())
                .or(Err(ValidateError::FailedToDecodePubKey))?
        }};

        dbo!();

        // Build key from public key pem
        let pub_key: VerifyingKey =
            VerifyingKey::from_public_key_der(pub_key_bytes[..].try_into().unwrap())
                .or(Err(ValidateError::FailedToBuildKey))?;

        goldberg_stmts! {{
            dbo!();

            let url = format!(
                "https://tsar.cc/api/client/v1/subscriptions/validate?app={}&hwid={}",
                self.app_id, hwid
            );

            let response = reqwest::blocking::get(&url).or(Err(ValidateError::RequestFailed))?;

            if !response.status().is_success() {
                match response.status() {
                    StatusCode::NOT_FOUND => return Err(ValidateError::AppNotFound),
                    StatusCode::UNAUTHORIZED => return Err(ValidateError::UserNotFound),
                    _ => return Err(ValidateError::ServerError),
                }
            }

            // Parse body into JSON
            let data = response
                .json::<Value>()
                .or(Err(ValidateError::FailedToParseBody))?;

            // Get the base64-encoded data from the response
            let base64_data = data
                .get("data")
                .and_then(|v| v.as_str())
                .ok_or(ValidateError::FailedToGetData)?;

            // Get the base64-encoded signature from the response
            let base64_signature = data
                .get("signature")
                .and_then(|v| v.as_str())
                .ok_or(ValidateError::FailedToGetSignature)?;

            // Decode the base64-encoded data (turns into buffer)
            let data_bytes = BASE64_STANDARD
                .decode(base64_data)
                .or(Err(ValidateError::FailedToDecodeData))?;

            // Get json string
            let json_string =
                String::from_utf8(data_bytes.clone()).or(Err(ValidateError::FailedToParseData))?;

            // Turn string to json
            let json: Data =
                serde_json::from_str(&json_string).or(Err(ValidateError::FailedToParseData))?;

            dbo!();

            if hwid != json.hwid {
                return Err(ValidateError::OldResponse);
            }

            // Get the timestamp value
            let timestamp = UNIX_EPOCH + Duration::from_secs(json.timestamp / 1000);

            // Get NTP time
            let client = SntpClient::new();
            let ntp_time = client.synchronize("time.cloudflare.com").unwrap().datetime()
                .into_system_time()
                .unwrap();

            // Get system time
            let system_time = SystemTime::now();

            let duration = if ntp_time > system_time {
                ntp_time.duration_since(system_time).unwrap()
            } else {
                system_time.duration_since(ntp_time).unwrap()
            };

            if duration.as_millis() > 1000
                || timestamp < system_time - Duration::from_secs(5)
            {
                return Err(ValidateError::OldResponse);
            }

            // Decode the base64-encoded signature (turns into buffer)
            let signature_bytes = BASE64_STANDARD
                .decode(base64_signature)
                .or(Err(ValidateError::FailedToDecodeSignature))?;

            // Build signature from buffer
            let mut signature = Signature::from_bytes(signature_bytes[..].try_into().unwrap())
                .or(Err(ValidateError::FailedToBuildSignature))?;

            // NodeJS sucks so we need to normalize the sig
            signature = signature.normalize_s().unwrap_or(signature);

            dbo!();

            // Verify the signature
            let result = pub_key.verify(&data_bytes, &signature);

            if result.is_ok() {
                return Ok(json);
            }

            Err(ValidateError::InvalidSignature)
        }}
    }
}
