# TSAR Client API

This is the official TSAR Client API wrapper for rust.

---

## Example Import

```toml
tsar = "1.0.0"
```

## Example Usage

```rs
use tsar::Client;

let api = Client::new(APP_ID, PUBLIC_KEY);

let result = api.authenticate_user();

if result.is_ok() {
    // User authenticated
}
```
