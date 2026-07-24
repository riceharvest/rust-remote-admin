//! Payload-level encryption supplementing TLS.
//!
//! This module provides AES-128-GCM authenticated encryption for
//! application payloads. It is intended as an additional layer of
//! protection on top of TLS, not as a replacement for it.
//!
//! # Production key management
//!
//! Production deployments **MUST** use [`KeyManager::from_password`] or a
//! proper key-exchange mechanism to obtain encryption keys. Hard-coded
//! keys (such as all-0x11 arrays) must never appear outside of tests.

use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    KeyDerivationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
        }
    }
}

impl Error for CryptoError {}

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub data: Vec<u8>,
    pub nonce: [u8; 12],
}

/// A managed AES-128-GCM encryption key.
///
/// Wraps a 16-byte key and provides authenticated encryption and
/// decryption for application payloads. Use [`KeyManager::new`] when you
/// already have a raw key from an established key-exchange, or
/// [`KeyManager::from_password`] to derive a key from a password and salt.
pub struct KeyManager {
    key: [u8; 16],
}

impl KeyManager {
    /// Construct a `KeyManager` from a raw 16-byte AES-128 key.
    ///
    /// Prefer [`KeyManager::from_password`] or a key-exchange protocol
    /// over hard-coded keys.
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    /// Derive a 16-byte key from a password and salt using HKDF-SHA256.
    ///
    /// The salt should be a cryptographically random value at least 16
    /// bytes long. The same salt must be used for encryption and
    /// decryption.
    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self, CryptoError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let prk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
        let mut okm = [0u8; 16];
        prk.expand(&[], &mut okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        Ok(Self { key: okm })
    }

    /// Encrypt `data` and return the [`EncryptedPayload`].
    ///
    /// A fresh random nonce is generated for every call.
    pub fn encrypt(&self, data: &[u8]) -> Result<EncryptedPayload, CryptoError> {
        encrypt_payload(data, &self.key)
    }

    /// Decrypt `payload` and return the original plaintext.
    ///
    /// Returns [`CryptoError::DecryptionFailed`] if the payload has been
    /// tampered with or was encrypted with a different key.
    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, CryptoError> {
        decrypt_payload(payload, &self.key)
    }
}

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

#[cfg(test)]
mod tests {
    use super::{decrypt_payload, encrypt_payload, KeyManager};

    // Test-only key — never use this or any hard-coded value in production.
    // Production deployments MUST use KeyManager::from_password() or a
    // proper key-exchange mechanism.
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

    #[test]
    fn key_manager_new_round_trip() {
        let km = KeyManager::new(KEY);
        let payload = km.encrypt(b"hello from KeyManager").expect("encrypt");
        let plaintext = km.decrypt(&payload).expect("decrypt");
        assert_eq!(plaintext, b"hello from KeyManager");
    }

    #[test]
    fn key_manager_from_password_derives_different_key() {
        let salt = b"unique-salt-for-testing!";
        let km = KeyManager::from_password("my password", salt).expect("key derivation");
        let payload = km.encrypt(b"derived key test").expect("encrypt");
        let plaintext = km.decrypt(&payload).expect("decrypt");
        assert_eq!(plaintext, b"derived key test");
    }

    #[test]
    fn key_manager_wrong_key_fails() {
        let km1 = KeyManager::new(KEY);
        let km2 = KeyManager::new(WRONG_KEY);
        let payload = km1.encrypt(b"secret data").expect("encrypt");
        assert!(km2.decrypt(&payload).is_err());
    }
}
