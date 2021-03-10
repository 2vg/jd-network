use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("could not generate signing key.")]
    FailedToGenerateSigningKey,
    #[error("could not generate verify key.")]
    FailedToGenerateVerifyKey,
    #[error("could not verify the signature.")]
    FailedToVerify,
    #[error("unknown error.")]
    Unknown,
}

#[derive(Error, Debug)]
pub enum CryptionError {
    #[error("could not encrypt the text.")]
    FailedToEncrypt,
    #[error("could not decrypt the text")]
    FailedToDecrypt,
}
