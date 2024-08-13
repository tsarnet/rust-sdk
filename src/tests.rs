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
                "Client successfully initialized. Hostname returned by server: {}",
                client.dashboard_hostname
            );

            let mut user_result = client.authenticate();

            while user_result.is_err() {
                println!("Attempting to check if user is valid...");
                std::thread::sleep(std::time::Duration::from_secs(3));

                if client.validate().is_ok() {
                    user_result = client.authenticate();
                }
            }

            let user = user_result.unwrap();

            println!("User authorized. User ID: {}", user.id);

            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                match user.heartbeat() {
                    Ok(_) => println!("Heartbeat success"),
                    Err(err) => {
                        println!("Heartbeat failed: {:?}: {}", err, err)
                    }
                }
            }
        }
        Err(err) => println!("Failed to initialize client: {:?}: {}", err, err),
    }

    assert!(true);
}
