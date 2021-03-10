use jd_network::crypt::key_manager::KeyStorage;

#[test]
fn basic_shared_secret_is_correct() {
    let alice = KeyStorage::new();
    let bob = KeyStorage::new();

    assert_eq!(alice.generate_shared_secret_key(&bob.public_key),
               bob.generate_shared_secret_key(&alice.public_key));
}

#[test]
fn basic_shared_secret_is_incorrect() {
    let alice = KeyStorage::new();
    let bob = KeyStorage::new();

    assert_ne!(alice.generate_shared_secret_key(&alice.public_key),
               bob.generate_shared_secret_key(&bob.public_key));
}
