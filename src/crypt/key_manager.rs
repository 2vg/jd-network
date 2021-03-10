use x25519_dalek::{PublicKey, StaticSecret};

pub struct KeyStorage {
    secret: StaticSecret,
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
}

pub trait KeyManage {
    fn generate_shared_secret_key(&self, public_key: &[u8; 32]) -> [u8; 32];
}

impl KeyStorage {
    pub fn new() -> KeyStorage {
        let secret = StaticSecret::new(rand_core::OsRng);
        let public = PublicKey::from(&secret);
        let secret_key = (&secret).to_bytes();
    
        KeyStorage {
            secret,
            public_key: public.to_bytes(),
            secret_key,
        }
    }

    pub fn generate_shared_secret_key(&self, public_key: &[u8; 32]) -> [u8; 32] {
        self.secret.diffie_hellman(&PublicKey::from(*public_key)).to_bytes()
    }
}
