use anyhow::*;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use rand_core::{ OsRng, RngCore };

pub struct CipherContainer {
    cipher: ChaCha20Poly1305,
    nonce: Nonce
}

impl CipherContainer {
    pub fn new(key: [u8; 32]) -> CipherContainer {
        let key = Key::from_slice(&key);
        CipherContainer {
            cipher: ChaCha20Poly1305::new(key),
            nonce: generate_nonce()
        }
    }

    pub fn update_key(&mut self, key: [u8; 32]) {
        let key = Key::from_slice(&key);
        self.cipher = ChaCha20Poly1305::new(key);
    }

    pub fn set_nonce(&mut self, nonce: [u8; 12]) {
        self.nonce = *Nonce::from_slice(&nonce);
    }

    pub fn refresh_nonce(&mut self) {
        self.nonce = generate_nonce()
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self.cipher.encrypt(&self.nonce, msg) {
            Ok(cipher_text) => { Ok(cipher_text) },
            Err(_) => { bail!("") }
        }
    }

    pub fn encrypt_with_aad(&self, msg: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload { msg, aad };
        match self.cipher.encrypt(&self.nonce, payload) {
            Ok(cipher_text) => { Ok(cipher_text) },
            Err(_) => { bail!("") }
        }
    }

    pub fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self.cipher.decrypt(&self.nonce, msg) {
            Ok(plain_text) => { Ok(plain_text) },
            Err(_) => { bail!("") }
        }
    }

    pub fn decrypt_with_aad(&self, msg: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload { msg, aad };
        match self.cipher.decrypt(&self.nonce, payload) {
            Ok(plain_text) => { Ok(plain_text) },
            Err(_) => { bail!("") }
        }
    }
}

fn generate_nonce() -> Nonce {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    *Nonce::from_slice(&nonce)
}
