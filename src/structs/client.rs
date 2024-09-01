use super::user::User;
use crate::errors::TsarError;
use crate::Subscription;
use base64::prelude::*;
use hardware_id::get_id;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use reqwest::StatusCode;
use rsntp::SntpClient;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use std::env::current_exe;
use std::fs::File;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// TSAR Client. Used to interact with the TSAR API.
#[derive(Debug)]
pub struct Client {
    /// The ID of your TSAR app. Should be in UUID format: 00000000-0000-0000-0000-000000000000
    pub app_id: String,
    /// The client decryption key for your TSAR app. Should be in base64 format. Always starts with "MFk..."
    pub client_key: String,
    /// The hostname of your app's dashboard.
    pub dashboard_hostname: String,
}

/// TSAR Client options. Pass this into the `new()` function of the TSAR Client.
#[derive(Debug)]
pub struct ClientParams {
    /// The ID of your TSAR app. Should be in UUID format: 00000000-0000-0000-0000-000000000000
    pub app_id: String,
    /// The client decryption key for your TSAR app. Should be in base64 format. Always starts with "MFk..."
    pub client_key: String,
    /// Whether TSAR should print debug statements.
    pub debug: bool,
}

/// TSAR Client options. Pass this into the `new()` function of the TSAR Client.
#[derive(Debug)]
pub struct AuthParams {
    /// Whether authenticate() should automatically open the user's browser when auth fails.
    /// Disable this when using authenticate() more than once or in loops so that you dont spam the user's browser with tabs.
    pub open_browser: bool,
}

impl Default for AuthParams {
    fn default() -> Self {
        Self { open_browser: true }
    }
}

/// Data returned by the TSAR API when initializing.
#[derive(Deserialize)]
struct InitializeReturnData {
    dashboard_hostname: String,
}

/// Data returned by the `client.validate()` function.
#[derive(Deserialize)]
pub struct ValidateReturnData {
    pub id: String,
    /// Name of the user. This could be their display name, username, or null.
    pub name: Option<String>,
    /// Avatar of the user. This can either be an image URL or null.
    pub avatar: Option<String>,

    pub subscription: Subscription,
}

impl Client {
    /// Utility for getting a user's HWID across all platforms.
    pub fn get_hwid() -> Result<String, TsarError> {
        get_id().or(Err(TsarError::FailedToGetHWID))
    }

    /// Get the hash of the current binary
    pub fn get_hash() -> Result<String, TsarError> {
        let current_exe = current_exe().or(Err(TsarError::FailedToGetHash))?;

        let mut file = File::open(&current_exe).or(Err(TsarError::FailedToGetHash))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1024];

        loop {
            let count = file.read(&mut buffer).or(Err(TsarError::FailedToGetHash))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }

        let hash_result = hasher.finalize();
        Ok(format!("{:x}", hash_result))
    }

    /// Creates a new TSAR client.
    pub fn create(options: ClientParams) -> Result<Self, TsarError> {
        // Verify that all options passed are in the right format
        if options.app_id.len() != 36 {
            return Err(TsarError::InvalidAppId);
        }

        if options.client_key.len() != 124 {
            return Err(TsarError::InvalidClientKey);
        }

        // Make the init request
        let params = vec![("app_id", options.app_id.as_str())];

        let init_result = Client::encrypted_api_call::<InitializeReturnData>(
            "initialize",
            options.client_key.as_str(),
            params,
        )?;

        Ok(Self {
            app_id: options.app_id.to_string(),
            client_key: options.client_key.to_string(),
            dashboard_hostname: init_result.dashboard_hostname,
        })
    }

    /// Attempts to authenticate the user.
    /// If the user's HWID is not authorized, the function opens the user's default browser to prompt a login.
    pub fn authenticate(&self, options: AuthParams) -> Result<User, TsarError> {
        let params = vec![("app_id", self.app_id.as_str())];

        let auth_result =
            Client::encrypted_api_call::<User>("authenticate", &self.client_key, params);

        let hwid = Self::get_hwid()?;

        match auth_result {
            Ok(user) => return Ok(user),
            Err(TsarError::Unauthorized) => {
                if options.open_browser {
                    let _ =
                        open::that(format!("https://{}/auth/{}", self.dashboard_hostname, hwid));
                }
                return Err(TsarError::Unauthorized);
            }
            Err(TsarError::HashUnauthorized) => {
                if options.open_browser {
                    let _ = open::that(format!(
                        "https://{}/assets?outdated=true",
                        self.dashboard_hostname
                    ));
                }
                return Err(TsarError::HashUnauthorized);
            }
            Err(err) => return Err(err),
        }
    }

    /// Query an endpoint from the TSAR API.
    pub fn encrypted_api_call<T: DeserializeOwned>(
        path: &str,
        public_key: &str,
        // The request's query parameters
        params: Vec<(&str, &str)>,
    ) -> Result<T, TsarError> {
        let hwid = Client::get_hwid()?;
        let hash = Client::get_hash()?;

        // Convert client_key der to buffer
        let pub_key_bytes = BASE64_STANDARD
            .decode(public_key)
            .or(Err(TsarError::InvalidPublicKey))
            .unwrap();

        // Build public key from buffer
        let pub_key: VerifyingKey =
            VerifyingKey::from_public_key_der(pub_key_bytes[..].try_into().unwrap())
                .or(Err(TsarError::InvalidPublicKey))?;

        // Append a / to path if it does not start with one
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };

        // Add HWID to the params
        let mut full_params = params.to_vec();
        full_params.push(("hwid", &hwid));
        full_params.push(("hash", &hash));

        // Send the request
        let url = reqwest::Url::parse_with_params(
            &format!("https://tsar.cc/api/client{}", path),
            &full_params,
        )
        .or(Err(TsarError::RequestFailed))?;

        let response = reqwest::blocking::get(url).or(Err(TsarError::RequestFailed))?;

        if !response.status().is_success() {
            match response.status() {
                StatusCode::BAD_REQUEST => return Err(TsarError::BadRequest),
                StatusCode::NOT_FOUND => return Err(TsarError::AppNotFound),
                StatusCode::UNAUTHORIZED => return Err(TsarError::Unauthorized),
                StatusCode::TOO_MANY_REQUESTS => return Err(TsarError::RateLimited),
                StatusCode::SERVICE_UNAVAILABLE => return Err(TsarError::AppPaused),
                StatusCode::FORBIDDEN => return Err(TsarError::HashUnauthorized),
                _ => return Err(TsarError::ServerError),
            }
        }

        // Parse body into JSON
        let data = response
            .json::<Value>()
            .or(Err(TsarError::FailedToDecode))?;

        // Get the base64-encoded data from the response
        let base64_data = data
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or(TsarError::FailedToDecode)?;

        // Get the base64-encoded signature from the response
        let base64_signature = data
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or(TsarError::FailedToDecode)?;

        // Decode the base64-encoded data (turns into buffer)
        let data_bytes = BASE64_STANDARD
            .decode(base64_data)
            .or(Err(TsarError::FailedToDecode))?;

        // Get json string
        let json_string =
            String::from_utf8(data_bytes.clone()).or(Err(TsarError::FailedToDecode))?;

        // Turn string to json
        let json: Value = serde_json::from_str(&json_string).or(Err(TsarError::FailedToDecode))?;

        // Verify that HWIDs match
        if let Some(hwid_value) = json.get("hwid") {
            if let Some(hwid_str) = hwid_value.as_str() {
                if hwid != hwid_str {
                    return Err(TsarError::StateMismatch);
                }
            } else {
                return Err(TsarError::FailedToDecode);
            }
        } else {
            return Err(TsarError::FailedToDecode);
        }

        // Get the timestamp value
        let timestamp = match json.get("timestamp").and_then(|ts| ts.as_u64()) {
            Some(ts_secs) => {
                let duration_secs = Duration::from_secs(ts_secs);
                UNIX_EPOCH
                    .checked_add(duration_secs)
                    .ok_or(TsarError::FailedToDecode)?
            }
            None => return Err(TsarError::FailedToDecode),
        };

        // Get NTP time
        let client = SntpClient::new();
        let ntp_time = client
            .synchronize("time.cloudflare.com")
            .unwrap()
            .datetime()
            .into_system_time()
            .unwrap();

        // Get system time
        let system_time = SystemTime::now();

        let duration = if ntp_time > system_time {
            ntp_time.duration_since(system_time).unwrap()
        } else {
            system_time.duration_since(ntp_time).unwrap()
        };

        // Check that time is synced within a 30 second leeway
        if duration.as_millis() > 30000 || timestamp < (system_time - Duration::from_secs(30)) {
            return Err(TsarError::TamperedResponse);
        }

        // Decode the base64-encoded signature (turns into buffer)
        let signature_bytes = BASE64_STANDARD
            .decode(base64_signature)
            .or(Err(TsarError::FailedToDecode))?;

        // Build signature from buffer
        let mut signature = Signature::from_bytes(signature_bytes[..].try_into().unwrap())
            .or(Err(TsarError::FailedToDecode))?;

        signature = signature.normalize_s().unwrap_or(signature);

        // Verify the signature
        let result = pub_key.verify(&data_bytes, &signature);

        if result.is_ok() {
            if std::any::type_name::<T>() == "()" {
                return Ok(serde_json::from_value(Value::Null).unwrap());
            }

            // Extract the actual data object
            let actual_data = json.get("data").ok_or(TsarError::FailedToDecode)?;
            return Ok(serde_json::from_value(actual_data.clone()).unwrap());
        }

        Err(TsarError::FailedToDecode)
    }
}
