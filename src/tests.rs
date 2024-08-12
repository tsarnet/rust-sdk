use crate::{Client, ClientOptions};

const CLIENT_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ+N6c07hrVdt1FzX3+baICfl7nDIWJ+uMEyN5SA09ulN37mc7maQ8kOBwse9Yr4To5FIKMMx/BQwDTPu+TqvVQ==";
const APP_ID: &str = "35f5bc1b-9a6d-442f-8813-6579e443d4be";

#[test]
fn client_test() {
    let options = ClientOptions {
        app_id: APP_ID.to_string(),
        client_key: CLIENT_KEY.to_string(),
        debug: true,
    };

    let client_init = Client::new(options);

    match client_init {
        Ok(client) => {
            println!(
                "\x1b[32m[INIT SUCCESS] Hostname\x1b[0m: {}",
                client.dashboard_hostname
            );

            match client.authenticate() {
                Ok(user) => {
                    println!("\x1b[32m[AUTH SUCCESS] User ID\x1b[0m: {}", user.id);

                    println!("{}", user.session_key);

                    loop {
                        match user.heartbeat() {
                            Ok(_) => println!("\x1b[32m[HEARTBEAT SUCCESS]\x1b[0m"),
                            Err(err) => {
                                println!("\x1b[31m[HEARTBEAT ERROR] Err: {:?}\x1b[0m: {}", err, err)
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
                Err(err) => println!(
                    "\x1b[31m[AUTH ERROR] Failed auth: {:?}\x1b[0m: {}",
                    err, err
                ),
            }
        }
        Err(err) => println!("\x1b[31m[INIT ERROR] {:?}\x1b[0m: {}", err, err),
    }

    assert!(true);
}
