# TSAR Rust SDK

The official Rust SDK for TSAR. Rust is our primary focus, so this SDK will be the most maintained.

![banner](/banner.png)

## Example Import

```toml
tsar-client = "0.1.0-alpha.1"
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
    };

    let client = Client::new(options).expect("Failed to initialize client.");

    // If client formed successfully, then the user is authorized
    // Access user info directly from the client

    println!("User ID: {}", client.subscription.user.id);
}
```

## Want to contribute?

This SDK is open for community contribution! All pull requests will be reviewed by our team.

## Need help?

Join our [discord community](https://discord.com/invite/JReXjQCVPw) if you have any questions. For other contact options, please [visit here](https://tsar.cc/about/social).
