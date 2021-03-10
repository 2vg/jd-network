use crate::error::*;

use anyhow::*;
use ring_compat::signature::{
    ed25519::{Signature, SigningKey, VerifyKey},
    Signature as _, Signer, Verifier,
};

pub fn sign(data: &[u8], key: &[u8]) -> Result<[u8; 64]> {
    match SigningKey::from_seed(key) {
        Ok(signing_key) => {
            Ok(signing_key.sign(data).to_bytes())
        },
        Err(_) => { Err(VerifierError::FailedToGenerateSigningKey)
                        .with_context(|| format!("data is {:?}, key is {:?}", data, key))? }
    }
}

pub fn verify(data: &[u8], sig: &[u8], key: &[u8]) -> Result<bool> {
    match VerifyKey::new(key) {
        Ok(verify_key) => {
            match Signature::from_bytes(sig) {
                Ok(signature) => {
                    Ok(verify_key.verify(data, &signature).is_ok())
                },
                Err(_) => { Err(VerifierError::Unknown)
                    .with_context(|| format!("something happened in signature::from_bytes.\ndata is {:?}, sig is {:?}, key is {:?}", data, sig, key))? }
            }
        },
        Err(_) => { Err(VerifierError::FailedToGenerateVerifyKey)
            .with_context(|| format!("data is {:?}, sig is {:?}, key is {:?}", data, sig, key))? }
    }
}
