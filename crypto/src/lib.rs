pub mod encryption {
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce, aead::Aead};
    use serde::{Deserialize, Serialize};
    use rand::Rng;

    #[derive(Serialize, Deserialize)]
    pub struct EncryptedPayload {
        pub data: Vec<u8>,
        pub nonce: [u8; 12],
    }

    pub fn encrypt_payload(data: &[u8], key: &[u8; 16]) -> Option<EncryptedPayload> {
        let cipher = Aes128Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        match cipher.encrypt(nonce, data) {
            Ok(encrypted) => Some(EncryptedPayload {
                data: encrypted,
                nonce: nonce_bytes,
            }),
            Err(_) => None,
        }
    }

    pub fn decrypt_payload(encrypted: &EncryptedPayload, key: &[u8; 16]) -> Option<Vec<u8>> {
        let cipher = Aes128Gcm::new(key.into());
        let nonce = Nonce::from_slice(&encrypted.nonce);

        match cipher.decrypt(nonce, &encrypted.data) {
            Ok(decrypted) => Some(decrypted),
            Err(_) => None,
        }
    }
}
