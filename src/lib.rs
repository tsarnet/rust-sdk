pub mod v1;

// Tester
#[cfg(test)]
mod tests {
    #[test]
    fn authenticate_user() {
        let pub_key_str = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEWkFYjN1Lkkm6OrmB1Bxx4OutLz1Ecvx9\na7+MKFAqWsAGpMqCuyzlXoFszWEirWkn/WqocyJ6ty0L2fZdosusPw==\n-----END PUBLIC KEY-----";
        let app_id = "56e15ddc-d0ac-489e-add2-9b1d742a6cf6";

        let api = crate::v1::API::new(app_id, pub_key_str);

        assert!(api.authenticate_user("NEW_HWID").is_ok());
    }
}
