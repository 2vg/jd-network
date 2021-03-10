use jd_network::crypt::cipher::*;

const FIXED_AAD: [u8; 12] = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
const FIXED_NONCE: [u8; 12] = [0x12, 0x14, 0x16, 0x18, 0x22, 0x24, 0x26, 0x28, 0x32, 0x34, 0x36, 0x38];
const FIXED_KEY: [u8; 32] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];

const ENCRYPTED_TEXT_FOR_BASIC: [u8; 28] = [
    0xa1, 0x29, 0xfa, 0x8b, 0x3e, 0xa, 0xd5, 0xed, 0x14, 0x92, 0x70, 0xb6, 0x9a, 0xd7, 0x27, 0x3e,
    0xef, 0x2c, 0xa6, 0x66, 0xc1, 0x61, 0x9f, 0x69, 0xca, 0xeb, 0xa3, 0x28
];

const ENCRYPTED_TEXT_FOR_BASIC_WITH_AAD: [u8; 28] = [
    0xa1, 0x29, 0xfa, 0x8b, 0x3e, 0xa, 0xd5, 0xed, 0x14, 0x92, 0x70, 0xb6, 0x77, 0x2f, 0x5d, 0x2b,
    0xce, 0xfb, 0xc3, 0x19, 0xa, 0xb0, 0x31, 0xc5, 0x91, 0x2f, 0x17, 0x2c
];

#[test]
fn basic_encrypt_with_fixed_nonce_success() {
    let mut container = CipherContainer::new(FIXED_KEY);
    container.set_nonce(FIXED_NONCE);
    let result = container.encrypt("hello, world".as_bytes());

    assert_eq!(true, result.is_ok());
    assert_eq!(Vec::from(ENCRYPTED_TEXT_FOR_BASIC), result.unwrap());
}


#[test]
fn basic_encrypt_with_random_nonce_success() {
    let container = CipherContainer::new(FIXED_KEY);
    let result = container.encrypt("hello, world".as_bytes());

    assert_eq!(true, result.is_ok());
    assert_ne!(Vec::from(ENCRYPTED_TEXT_FOR_BASIC), result.unwrap());
}

#[test]
fn basic_encrypt_with_fixed_aad_and_with_fixed_nonce_success() {
    let mut container = CipherContainer::new(FIXED_KEY);
    container.set_nonce(FIXED_NONCE);
    let result = container.encrypt_with_aad("hello, world".as_bytes(), &FIXED_AAD);

    assert_eq!(true, result.is_ok());
    assert_eq!(Vec::from(ENCRYPTED_TEXT_FOR_BASIC_WITH_AAD), result.unwrap());
}

#[test]
fn basic_encrypt_with_fixed_aad_and_with_random_nonce_success() {
    let container = CipherContainer::new(FIXED_KEY);
    let result = container.encrypt_with_aad("hello, world".as_bytes(), &FIXED_AAD);

    assert_eq!(true, result.is_ok());
    assert_ne!(Vec::from(ENCRYPTED_TEXT_FOR_BASIC_WITH_AAD), result.unwrap());
}

#[test]
fn basic_decrypt_success() {
    let mut container = CipherContainer::new(FIXED_KEY);
    container.set_nonce(FIXED_NONCE);
    let result = container.decrypt(&ENCRYPTED_TEXT_FOR_BASIC);

    assert_eq!(true, result.is_ok());
    assert_eq!(Vec::from("hello, world".as_bytes()), result.unwrap());
}

#[test]
fn basic_decrypt_with_aad_success() {
    let mut container = CipherContainer::new(FIXED_KEY);
    container.set_nonce(FIXED_NONCE);
    let result = container.decrypt_with_aad(&ENCRYPTED_TEXT_FOR_BASIC_WITH_AAD, &FIXED_AAD);

    assert_eq!(true, result.is_ok());
    assert_eq!(Vec::from("hello, world".as_bytes()), result.unwrap());
}
