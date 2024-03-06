use std::thread;
use std::time::Duration;

use base64::prelude::*;
use ecdsa::signature::Verifier;
use ecdsa::{Signature, VerifyingKey};
use k256::pkcs8::DecodePublicKey;
use k256::Secp256k1;
use serde_json::Value;

pub struct API {
    app_id: String,
    public_key: String,
}

impl API {
    // TODO: Make HWID optional, get it automatically if not passed
    pub fn new(app_id: &str, public_key: &str) -> Self {
        Self {
            app_id: app_id.to_string(),
            public_key: public_key.to_string(),
        }
    }

    pub fn authenticate_user(&self, hwid: &str) -> Result<(), String> {
        // Check if already authenticated
        if self.validate_subscriber(hwid).is_ok() {
            return Ok(());
        }

        // If not, prompt a login
        open::that(format!(
            "http://localhost:5173/apps/{}/validate/{}",
            self.app_id, hwid
        ))
        .expect("Failed to open login page on browser");

        loop {
            thread::sleep(Duration::from_millis(5000));

            println!("REQUESTING UPDATE");

            if self.validate_subscriber(hwid).is_ok() {
                println!("HWID UPDATE SUCCESS");
                return Ok(());
            }
        }
    }

    pub fn validate_subscriber(&self, hwid: &str) -> Result<(), String> {
        // Build the URL
        let url = format!(
            "http://localhost:5173/api/v1/apps/{}/subscribers/validate?hwid={}",
            self.app_id, hwid
        );

        // Make the request and get the response
        let response = reqwest::blocking::get(&url).expect("Request failed");

        if !response.status().is_success() {
            Err(format!(
                "Response returned an error: {}",
                response.status().as_str()
            ))
        } else {
            // Parse body into JSON
            let data = response
                .json::<Value>()
                .expect("Failed to parse body into JSON");

            // Get the base64-encoded data from the response
            let base64_data = data
                .get("data")
                .and_then(|v| v.as_str())
                .expect("Failed to get encoded data from response");

            // Get the base64-encoded signature from the response
            let base64_signature = data
                .get("signature")
                .and_then(|v| v.as_str())
                .expect("Failed to get encoded signature from response");

            // Decode the base64-encoded data and signature (both become buffers)
            let data_bytes = BASE64_STANDARD
                .decode(base64_data)
                .expect("Failed to decode data into buffer");
            let signature_bytes = BASE64_STANDARD
                .decode(base64_signature)
                .expect("Failed to decode signature into buffer");

            // Build key from public key pem
            let v_pub_key: VerifyingKey<Secp256k1> =
                VerifyingKey::from_public_key_pem(self.public_key.as_str())
                    .expect("Failed to build VerifyingKey using pem");

            // Build signature from buffer
            let mut signature = Signature::from_der(signature_bytes[..].try_into().unwrap())
                .expect("Failed to build Signature from buffer");

            // NodeJS sucks so we need to normalize the sig
            signature = signature.normalize_s().unwrap_or(signature);

            // Verify the signature
            let result = v_pub_key.verify(&data_bytes, &signature);

            if result.is_ok() {
                println!("WE GOOD");
                return Ok(());
            }
            println!("WE NOT GOOD");

            Err("Data failed validation: invalid signature.".to_string())
        }
    }
}
