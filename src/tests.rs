use crate::{Client, ClientOptions};

const CLIENT_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELlyGTmNEv3AarudyshJUUA9ig1pOfSl5qWX8g/hkPiieeKlWvv9o4IZmWI4cCrcR0fteVEcUhBvu5GAr/ITBqA==";
const APP_ID: &str = "58816206-b24c-41d4-a594-8500746a78ee";

#[test]
fn client_test() {
    let options = ClientOptions {
        app_id: APP_ID,
        client_key: CLIENT_KEY,
        debug_print: true,
    };

    let client = Client::new(options);

    match client {
        Ok(data) => {
            println!("\x1b[32m[TEST SUCCESS] Data\x1b[0m: {:?}", data);
        }
        Err(err) => println!("\x1b[31m[TEST ERROR] {:?}\x1b[0m: {}", err, err),
    }

    assert!(true);
}
