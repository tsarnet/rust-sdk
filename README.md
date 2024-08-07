# TSAR Rust SDK

The official Rust SDK for TSAR. Rust is our primary focus, so this SDK will be the most maintained.

![banner](/banner.png)

## Example Import

```toml
tsar-client = "0.1.0-alpha.7"
```

## Example Usage

```rs
use tsar_client::Client;

// Get these credentials from: https://tsar.cc/app/*/settings
const CLIENT_KEY: &str = "MFkwEwY...GAr/ITBqA==";
const APP_ID: &str = "00000000-0000-0000-0000-000000000000";

fn main() {
    let options = ClientOptions {
        app_id: APP_ID.to_string(),
        client_key: CLIENT_KEY.to_string(),
        debug_print: true,
        dashboard_hostname: None,
    };

    // Initialize the client
    let client = Client::init(options).expect("Authentication failed.");

    // If client formed successfully, then the user is authorized
    // Access user info directly from the client

    println!("User ID: {}", client.subscription.user.id);

    // All subscriptions have "tiers" which can be set through key options. Default tier is 0.

    if client.subscription.tier >= 3 {
      println!("Woah you're special.");
    }

    // Perform a heart-beat check to validate that the user session is still valid
    if client.validate().is_err() {
      // Client session is no longer valid
    }
}
```

## Want to contribute?

This SDK is open for community contribution! All pull requests will be reviewed by our team.

## Need help?

Join our [discord community](https://discord.com/invite/JReXjQCVPw) if you have any questions. For other contact options, please [visit here](https://tsar.cc/about/social).
