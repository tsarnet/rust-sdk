// TSAR
// (c) 2024 TSAR, under MIT license

//! Official Rust SDK for TSAR

// Prevents goldberg from throwing false warnings
#![allow(non_camel_case_types)]

use base64::prelude::*;
use colorful::Color;
use colorful::Colorful;
#[cfg(all(target_os = "linux", not(debug_assertions)))]
use debugoff;
use errors::{AuthError, InitError, ValidateError};
use goldberg::goldberg_stmts;
use hardware_id::get_id;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use reqwest::StatusCode;
use rsntp::SntpClient;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use structs::{Data, Subscription};

mod errors;
mod structs;

#[cfg(test)]
mod tests;

// Anti-debug macro
macro_rules! dbo {
    () => {
        #[cfg(all(target_os = "linux", not(debug_assertions)))]
        debugoff::multi_ptraceme_or_die();
    };
}

/// The TSAR Client struct. Used to interact with the API after it's initialized.
#[derive(Debug)]
pub struct Client {
    /// The ID of your TSAR app. Should be in UUID format: 00000000-0000-0000-0000-000000000000
    pub app_id: String,
    /// The public decryption key for your TSAR app. Should be in base64 format.
    pub client_key: String,
    /// Client session is used to query the client API as a user.
    pub session: String,
    /// The HWID of the authenticated user.
    pub hwid: String,
    /// The subscription object of the user that authenticated.
    pub subscription: Subscription,
}

/// The TSAR Client options struct. Used to form options and pass into the creation of the TSAR Client struct.
#[derive(Debug)]
pub struct ClientOptions {
    /// The ID of your TSAR app. Should be in UUID format: 00000000-0000-0000-0000-000000000000
    pub app_id: String,
    /// The public decryption key for your TSAR app. Should be in base64 format.
    pub client_key: String,
    /// Whether TSAR should print debug statements regarding auth.
    pub debug_print: bool,
}

/// The TSAR client.
impl Client {
    /// Initializes a new TSAR client using an `app_id` and `client_key` variables.
    pub fn new(options: ClientOptions) -> Result<Self, InitError> {
        dbo!();

        let hwid = goldberg_stmts! {{
             get_id().or(Err(InitError::FailedToGetHWID))?
        }};

        let data = Self::authenticate(
            options.app_id.as_str(),
            hwid.as_str(),
            options.client_key.as_str(),
            options.debug_print,
        )
        .unwrap();

        Ok(Self {
            app_id: options.app_id.to_string(),
            client_key: options.client_key.to_string(),
            session: data.session,
            hwid,
            subscription: data.subscription,
        })
    }

    /// Starts an authentication flow which attempts to authenticate the user.
    /// If the user's HWID is not already authorized, the function opens the user's default browser to authenticate them.
    pub fn authenticate(
        app_id: &str,
        hwid: &str,
        client_key: &str,
        debug_print: bool,
    ) -> Result<Data, AuthError> {
        dbo!();

        if debug_print {
            #[cfg(windows)]
            print!("[TSAR] Authenticating...");

            #[cfg(not(windows))]
            print!(
                "{}",
                "[TSAR] Authenticating...".gradient_with_color(Color::Cyan, Color::SpringGreen4)
            );
        }

        // Attempt to validate user
        match Self::validate_user(app_id, hwid, client_key) {
            Ok(data) => {
                if debug_print {
                    #[cfg(windows)]
                    println!("\r[TSAR] Authentication success.");

                    #[cfg(not(windows))]
                    println!(
                        "\r{}",
                        "[TSAR] Authentication success."
                            .gradient_with_color(Color::Cyan, Color::SpringGreen4)
                    );

                    let user = data
                        .subscription
                        .user
                        .username
                        .clone()
                        .unwrap_or(data.subscription.user.id.clone());

                    #[cfg(windows)]
                    println!("[TSAR] Welcome, {}.", user);

                    #[cfg(not(windows))]
                    println!(
                        "{} Welcome, {}.",
                        "[TSAR]".gradient_with_color(Color::Cyan, Color::SpringGreen4),
                        user.gradient_with_color(Color::SpringGreen4, Color::Cyan)
                    );
                }

                return Ok(data);
            }

            // Only continue execution if the user is not found, if any other part of the validate_user function fails then return an error
            Err(err) => match err {
                ValidateError::UserNotFound => {
                    if debug_print {
                        #[cfg(windows)]
                        println!("\r[TSAR] Authentication failed: HWID not authorized. If a browser window did not open, please visit https://auth.tsar.cc/{}/{} to update your HWID.", app_id, hwid);

                        #[cfg(not(windows))]
                        println!(
                            "\r{} If a browser window did not open, please visit {} to update your HWID.",
                            "[TSAR] Authentication failed: HWID not authorized."
                                .gradient_with_color(Color::Cyan, Color::SpringGreen4),
                            format!("https://auth.tsar.cc/{}/{}", app_id, hwid).color(Color::Blue)
                        );
                    };
                }
                _ => {
                    if debug_print {
                        #[cfg(windows)]
                        println!("\r[TSAR] Authentication failed: {} Please contact the software distributor for support.", err.to_string());

                        #[cfg(not(windows))]
                        println!(
                            "\r{} Please contact the software distributor for support.",
                            format!("[TSAR] Authentication failed: {}", err.to_string())
                                .gradient_with_color(Color::Cyan, Color::SpringGreen4)
                        );
                    }

                    return Err(AuthError::ValidateError(err));
                }
            },
        };

        goldberg_stmts! {{
            if let Err(_) = open::that(format!("https://tsar.cc/auth/{}/{}", app_id, hwid)) {
                return Err(AuthError::FailedToOpenBrowser);
            }
        }};

        Err(AuthError::Unauthorized)
    }

    /// Check if a HWID is authorized to use the application. Takes custom parameters.
    pub fn validate_user(
        app_id: &str,
        hwid: &str,
        client_key: &str,
    ) -> Result<Data, ValidateError> {
        dbo!();

        let url = goldberg_stmts! {{
            format!("https://tsar.cc/api/client/subscriptions/get?app={}&hwid={}", app_id, hwid)
        }};

        Self::custom_query::<Data>(url.as_str(), client_key, hwid)
    }

    /// Query an endpoint from the TSAR API.
    pub fn query<T: DeserializeOwned>(&self, path: &str) -> Result<T, ValidateError> {
        Self::custom_query(path, &self.client_key, &self.hwid)
    }

    /// Query an endpoint from the TSAR API, but with custom parameters.
    pub fn custom_query<T: DeserializeOwned>(
        path: &str,
        client_key: &str,
        hwid: &str,
    ) -> Result<T, ValidateError> {
        dbo!();

        // Build key from client_key pem
        let pub_key: VerifyingKey = goldberg_stmts! {{
            let pub_key_bytes = BASE64_STANDARD.decode(client_key).or(Err(ValidateError::FailedToDecodePubKey)).unwrap();

            VerifyingKey::from_public_key_der(pub_key_bytes[..].try_into().unwrap())
            .or(Err(ValidateError::FailedToBuildKey))?
        }};

        // Run the rest of the query
        goldberg_stmts! {{
            let response = reqwest::blocking::get(path).or(Err(ValidateError::RequestFailed))?;

            dbo!();

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
            let json: Value =
                serde_json::from_str(&json_string).or(Err(ValidateError::FailedToParseData))?;

            dbo!();

            // Verify that HWIDs match
            if let Some(hwid_value) = json.get("hwid") {
                if let Some(hwid_str) = hwid_value.as_str() {
                    if hwid != hwid_str {
                        return Err(ValidateError::OldResponse);
                    }
                } else {
                    return Err(ValidateError::FailedToParseData);
                }
            } else {
                return Err(ValidateError::FailedToParseData);
            }

            // Get the timestamp value
            let timestamp = match json.get("timestamp").and_then(|ts| ts.as_u64()) {
                Some(ts_secs) => {
                    let duration_secs = Duration::from_secs(ts_secs);
                    UNIX_EPOCH.checked_add(duration_secs).ok_or(ValidateError::FailedToParseData)?
                }
                None => return Err(ValidateError::FailedToParseData),
            };

            // Get NTP time
            let client = SntpClient::new();
            let ntp_time = client.synchronize("time.cloudflare.com").unwrap().datetime()
                .into_system_time().unwrap();

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

            signature = signature.normalize_s().unwrap_or(signature);

            dbo!();

            // Verify the signature
            let result = pub_key.verify(&data_bytes, &signature);

            if result.is_ok() {
                return Ok(serde_json::from_value(json).unwrap());
            }

            Err(ValidateError::InvalidSignature)
        }}
    }
}
