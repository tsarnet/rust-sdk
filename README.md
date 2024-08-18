# TSAR Rust SDK

The official Rust SDK for TSAR. Rust is our primary focus, so this SDK will be the most maintained.

![banner](/banner.png)

## Example Import

```toml Cargo.toml
tsar-sdk = "0.1.0-beta.0"
```

## Example Usage

```rs main.rs
use tsar_sdk::{AuthParams, Client, ClientParams};

// You should have gotten these values after creating your app
// You can find them in your app's configuration settings
const APP_ID: &str = "00000000-0000-0000-0000-000000000000";
const CLIENT_KEY: &str = "MFk...";

fn main() {
  let options = ClientParams {
      app_id: APP_ID.to_string(),
      client_key: CLIENT_KEY.to_string(),
      debug: true, // Print out debug statements
  };

  // This will create a new client & perform a hash check on your binary
  let client_init = Client::create(options);

  // Check if client init was successful
  match client_init {
      Ok(client) => {
        println!(
            "Client successfully initialized. Hostname returned by server: {}",
            client.dashboard_hostname
        );

        // Check if user is authorized. Default AuthParams open the user's browser when auth fails.
        let mut user_result = client.authenticate(AuthParams::default());

        // If they aren't authorized, continue to check until they've authenticated themselves in their browser.
        while user_result.is_err() {
            println!("Attempting to check if user is valid...");
            std::thread::sleep(std::time::Duration::from_secs(3)); // Keep a delay of at least 3 seconds to prevent rate-limiting.

            // Make sure to set open_browser to false when in a loop, or else the browser will keep opening nonstop.
            user_result = client.authenticate(AuthParams {
                open_browser: false,
            });
        }

        // At this point the user is authenticated
        let user = user_result.unwrap();

        println!("User authorized. User ID: {}", user.id);

        // Start a heartbeat loop to continue checking if the user is authorized (we recommend running this in a background thread)
        //
        // **MAKE SURE THE LOOP RUNS ONLY ONCE EVERY 20 - 30 SECONDS**
        // Otherwise, your users might get rate-limited.
        //
        // Using a heartbeat thread will allow you to delete user sessions and have them be kicked off of your software live.
        // Additionally, if their subscription expires they will also be kicked during the heartbeat check.
        loop {
            match user.heartbeat() {
                Ok(_) => println!("Heartbeat success"),
                Err(err) => {
                    println!("Heartbeat failed: {:?}: {}", err, err)
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(30));
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
