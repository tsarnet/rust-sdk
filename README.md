# TSAR Rust SDK

The official Rust SDK for TSAR. Rust is our primary focus, so this SDK will be the most maintained.

![banner](/banner.png)

## Example Import

```toml Cargo.toml
tsar-sdk = "0.1.0-beta.0"
```

## Example Usage

```rs main.rs
use tsar_sdk::{Client, ClientOptions};

// You should have gotten these values after creating your app
// You can find them in your app's configuration settings
const CLIENT_KEY: &str = "MFk...";
const APP_ID: &str = "00000000-0000-0000-0000-000000000000";

fn main() {
  let options = ClientOptions {
      app_id: APP_ID.to_string(),
      client_key: CLIENT_KEY.to_string(),
      debug: true, // Print out debug statements
  };

  // This will create a new client & perform a hash check on your binary (if enabled)
  let client_init = Client::new(options);

  match client_init {
      Ok(client) => {
          println!("Client initialized!");

          // Attempt to authenticate user
          match client.authenticate() {
              Ok(user) => {
                  println!("Successfully authenticated. User ID: {}", user.id);

                  // Start a heartbeat check loop
                  loop {
                      match user.heartbeat() {
                          Ok(_) => println!("Heartbeat OK."),
                          Err(err) => println!("Heartbeat failed: {:?}: {}", err, err),
                      }
                      std::thread::sleep(std::time::Duration::from_secs(30));
                  }
              }
              Err(err) => println!("Failed to authenticate: {:?}: {}", err, err),
          }
      }
      Err(err) => println!("Failed to initialize client: {:?}: {}", err, err),
  }
}
```

## Want to contribute?

This SDK is open for community contribution! All pull requests will be reviewed by our team.

## Need help?

Join our [discord community](https://tsar.cc/discord) if you have any questions. For other contact options, please [visit here](https://tsar.cc/about/social).
