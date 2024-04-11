# TSAR Client API

This is the official TSAR Client API wrapper for rust.

## Example Import

```toml
tsar-client = "*"
```

## Example Usage

```rs
use tsar_client::Client;

let api = Client::new(APP_ID, PUBLIC_KEY);

match api.authenticate_user() {
    Ok(data) => println!("Success: {:?}", data), // Auth Success
    Err(err) => println!("\x1b[31m[AUTH ERROR] {:?}\x1b[0m: {}", err, err), // Auth Failed
}
```
