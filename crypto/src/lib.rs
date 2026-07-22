use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "decryption failed"),
        }
    }
}

impl Error for CryptoError {}

pub mod encryption {
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce, aead::Aead};
    use serde::{Serialize, Deserialize};
    use rand::Rng;
    use super::CryptoError;

    #[derive(Serialize, Deserialize)]
    pub struct EncryptedPayload {
        pub data: Vec<u8>,
        pub nonce: [u8; 12],
    }

    pub fn encrypt_payload(data: &[u8], key: &[u8; 16]) -> Result<EncryptedPayload, CryptoError> {
        let cipher = Aes128Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        match cipher.encrypt(nonce, data) {
            Ok(encrypted) => Ok(EncryptedPayload {
                data: encrypted,
                nonce: nonce_bytes,
            }),
            Err(_) => Err(CryptoError::EncryptionFailed),
        }
    }

    pub fn decrypt_payload(encrypted: &EncryptedPayload, key: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes128Gcm::new(key.into());
        let nonce = Nonce::from_slice(&encrypted.nonce);

        match cipher.decrypt(nonce, &encrypted.data) {
            Ok(decrypted) => Ok(decrypted),
            Err(_) => Err(CryptoError::DecryptionFailed),
        }
    }
}
