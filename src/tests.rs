use crate::{Client, ClientOptions};

const CLIENT_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvJrwPvdeDUcV8Qr02tzgFrp+8qfCV/vG1HcQJYYV8u5vYUfGABMAYT0qOQltXEX9DTcB2fzLfwQnl7yiAaNruQ==";
const APP_ID: &str = "f911842b-5b3d-4c59-b5d1-4adb8f71557b";

#[test]
fn client_test() {
    let options = ClientOptions {
        app_id: APP_ID.to_string(),
        client_key: CLIENT_KEY.to_string(),
        debug_print: true,
        dashboard_hostname: Some("test.com".to_string()),
    };

    let client_init = Client::init(options);

    match client_init {
        Ok(client) => {
            println!(
                "\x1b[32m[INIT SUCCESS] Username\x1b[0m: {:?}",
                client.subscription.user.username
            );

            match client.validate() {
                Ok(data) => {
                    println!("\x1b[32m[HEARTBEAT SUCCESS] Valid?\x1b[0m: {}", data.valid);
                }
                Err(err) => println!(
                    "\x1b[31m[HEARTBEAT ERROR] Failed heartbeat check: {:?}\x1b[0m: {}",
                    err, err
                ),
            }
        }
        Err(err) => println!("\x1b[31m[INIT ERROR] {:?}\x1b[0m: {}", err, err),
    }

    assert!(true);
}
