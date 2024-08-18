use crate::{AuthParams, Client, ClientParams};

const CLIENT_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvJrwPvdeDUcV8Qr02tzgFrp+8qfCV/vG1HcQJYYV8u5vYUfGABMAYT0qOQltXEX9DTcB2fzLfwQnl7yiAaNruQ==";
const APP_ID: &str = "f911842b-5b3d-4c59-b5d1-4adb8f71557b";

#[test]
fn client_test() {
    let options = ClientParams {
        app_id: APP_ID.to_string(),
        client_key: CLIENT_KEY.to_string(),
        debug: true,
    };

    let client_init = Client::create(options);

    match client_init {
        Ok(client) => {
            println!(
                "Client successfully initialized. Hostname returned by server: {}",
                client.dashboard_hostname
            );

            let mut user_result = client.authenticate(AuthParams::default());

            while user_result.is_err() {
                println!("Attempting to check if user is valid...");
                std::thread::sleep(std::time::Duration::from_secs(3));

                user_result = client.authenticate(AuthParams {
                    open_browser: false,
                });
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
