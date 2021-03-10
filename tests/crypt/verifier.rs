use jd_network as jd;

const PUBLIC_KEY: &[u8; 32] = b"\xD7\x5A\x98\x01\x82\xB1\x0A\xB7\xD5\x4B\xFE\xD3\xC9\x64\x07\x3A\x0E\xE1\x72\xF3\xDA\xA6\x23\x25\xAF\x02\x1A\x68\xF7\x07\x51\x1A";
const SECRET_KEY: &[u8; 32] = b"\x9D\x61\xB1\x9D\xEF\xFD\x5A\x60\xBA\x84\x4A\xF4\x92\xEC\x2C\xC4\x44\x49\xC5\x69\x7B\x32\x69\x19\x70\x3B\xAC\x03\x1C\xAE\x7F\x60";
const SIGNATURE: &[u8; 64] = b"\xE5\x56\x43\x00\xC3\x60\xAC\x72\x90\x86\xE2\xCC\x80\x6E\x82\x8A\x84\x87\x7F\x1E\xB8\xE5\xD9\x74\xD8\x73\xE0\x65\x22\x49\x01\x55\x5F\xB8\x82\x15\x90\xA3\x3B\xAC\xC6\x1E\x39\x70\x1C\xF9\xB4\x6B\xD2\x5B\xF5\xF0\x59\x5B\xBE\x24\x65\x51\x41\x43\x8E\x7A\x10\x0B";

#[test]
fn basic_sign_success() {
    let signature = jd::crypt::verifier::sign(b"", SECRET_KEY);

    assert_eq!(true, signature.is_ok());
    assert_eq!(SIGNATURE, &signature.unwrap());
}

#[test]
fn basic_verify_success() {
    let verify_result = jd::crypt::verifier::verify(b"", SIGNATURE, PUBLIC_KEY);

    assert_eq!(true, verify_result.is_ok());
}

#[test]
fn basic_sign_failed() {
    let signature = jd::crypt::verifier::sign(b"", PUBLIC_KEY);

    assert_eq!(false, signature.is_err());
}

#[test]
fn basic_verify_failed() {
    let verify_result = jd::crypt::verifier::verify(b"", SIGNATURE, SECRET_KEY);

    assert_eq!(false, verify_result.is_err());
}
