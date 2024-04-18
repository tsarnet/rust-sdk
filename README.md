# TSAR Client API

This is the official TSAR Client SDK for rust.

## Example Import

```toml
tsar-client = "*"
```

## Example Usage

```rs
use tsar_client::Client;

let client = Client::new(APP_ID, PUBLIC_KEY).expect("Failed to initialize client");

// If client formed successfully, then the user is authorized
// Access user info using the client directly

println!("Username: ", client.subscription.user.username);
```
