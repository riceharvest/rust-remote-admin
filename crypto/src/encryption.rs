use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
        }
    }
}

impl Error for CryptoError {}

pub fn encrypt_payload(data: &[u8], key: &[u8; 16]) -> Result<EncryptedPayload, CryptoError> {
    use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let cipher = Aes128Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, data) {
        Ok(encrypted) => Ok(EncryptedPayload {
            data: encrypted,
            nonce: nonce_bytes,
        }),
        Err(_) => Err(CryptoError::EncryptionFailed),
    }
}

pub fn decrypt_payload(
    encrypted: &EncryptedPayload,
    key: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};

    let cipher = Aes128Gcm::new(key.into());
    let nonce = Nonce::from_slice(&encrypted.nonce);

    match cipher.decrypt(nonce, encrypted.data.as_slice()) {
        Ok(decrypted) => Ok(decrypted),
        Err(_) => Err(CryptoError::DecryptionFailed),
    }
}

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub data: Vec<u8>,
    pub nonce: [u8; 12],
}

#[cfg(test)]
mod tests {
    use super::{decrypt_payload, encrypt_payload};

    const KEY: [u8; 16] = [0x11; 16];
    const WRONG_KEY: [u8; 16] = [0x22; 16];

    #[test]
    fn round_trip_preserves_plaintext() {
        let payload = encrypt_payload(b"hello", &KEY).expect("encryption should succeed");
        let plaintext = decrypt_payload(&payload, &KEY).expect("decryption should succeed");
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn encryptions_use_distinct_nonces() {
        let first = encrypt_payload(b"same", &KEY).expect("first encryption should succeed");
        let second = encrypt_payload(b"same", &KEY).expect("second encryption should succeed");
        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn wrong_key_is_reported_as_an_error() {
        let payload = encrypt_payload(b"secret", &KEY).expect("encryption should succeed");
        assert!(decrypt_payload(&payload, &WRONG_KEY).is_err());
    }

    #[test]
    fn tampering_is_reported_as_an_error() {
        let mut payload = encrypt_payload(b"secret", &KEY).expect("encryption should succeed");
        payload.data[0] ^= 1;
        assert!(decrypt_payload(&payload, &KEY).is_err());
    }
}
