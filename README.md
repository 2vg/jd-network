Jiami de Network
=========================

This library provides an easy-to-use end-to-end encrypted network.
Still development, my plan is to release TCP module first, then UDP.

## How does it work?

It's a TLS tick, but there's no such thing as a digital signature check, it just does a simple check using Ed25519.</br>
After exchanging the public key and completing the simple signing process, the server and client generate a shared secret key with x25519.</br>
Subsequent communications will use chacha20poly1305 (using the generated shared secret key) and the encrypted data will pass through the network.</br>

## usage

in `Cargo.toml`,
```
jd_network = { git = "https://github.com/2vg/jd_network" }
```
or use `cargo add https://github.com/2vg/mini-assert` with `cargo-edit`(recommemded)

## TODO
- [ ] TCP
- [ ] UDP
