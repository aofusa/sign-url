use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Eq, PartialEq, Debug)]
pub struct Account {
    pub username: String,
    pub password: String,
}

impl Account {
    pub fn hash(&self) -> Account {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(self.password.as_bytes(), &salt).unwrap().to_string();
        Account {
            username: self.username.clone(),
            password: password_hash,
        }
    }

    pub fn compress(&self) -> (String, String) {
        (self.username.clone(), self.password.clone())
    }

    pub fn decompress(x: (String, String)) -> Account {
        Account {
            username: x.0,
            password: x.1,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.username.len() > 255 { return Err("username must be 256 characters or less".to_string()); }
        if !self.username.is_ascii() { return Err("username must be ascii characters".to_string()); }
        Ok(())
    }

    pub fn verify(&self, password: &str) -> argon2::password_hash::Result<()> {
        let hash_string = &self.password;
        let password_hash = PasswordHash::new(hash_string).expect("invalid password hash");
        let algorithms: &[&dyn PasswordVerifier] = &[&Argon2::default()];
        password_hash.verify_password(algorithms, password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account() {
        let account = Account {
            username: "user".to_string(),
            password: "user".to_string(),
        }.hash();
        let compressed = account.compress();
        let decompressed = Account::decompress(compressed);
        decompressed.validate().unwrap();
        decompressed.verify("user").unwrap();
        assert_eq!(account, decompressed);
    }

    #[test]
    fn test_validate() {
        let account = Account {
            username: "a".repeat(256).to_string(),
            password: "user".to_string(),
        }.hash();
        let err = account.validate();
        assert!(err.is_err());
    }

    #[test]
    fn test_verify() {
        let account = Account {
            username: "user".to_string(),
            password: "user".to_string(),
        }.hash();
        let err = account.verify("abc");
        assert!(err.is_err());
    }
}
