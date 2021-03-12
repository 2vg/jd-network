Jiami de Network
=========================

**NO LONGER DEVELOP!**</br>
There was already a project with almost the same structure, although it was a bit more complicated than the protocol I had imagined.</br>
I checked this and it's very nice.</br>
The protocol specification is also well written, which is pretty much what I imagined.</br>

so this is recommanded: https://github.com/mcginty/snow
===
This library provides an easy-to-use end-to-end encrypted network.
Still development, my plan is to release TCP module first, then UDP.

## How does it work?

It's a TLS tick, but there's no such thing as a digital signature check, it just does a simple check using Ed25519.</br>
After exchanging the public key and completing the simple signing process, the server and client generate a shared secret key with x25519.</br>
Subsequent communications will use chacha20poly1305 (using the generated shared secret key) and the encrypted data will pass through the network.</br>

this is pseudo code flow:
```
server(S)
client(C)

0: S.listen
   C.connect(S)

1: S.accept

2: C.send(S, C.public_key)

3: S.send(C, S.public_key)

4: C.generate_sign_key::from(C.secret_key)) as signing_key
   C.sign(**S.publick_key**, signing_key) as sig
   C.send(S, sig)

5: S.recv() as sig
   S.generate_verify_key::from(C.publick_key)) as verify_key
   S.verify(**S.publick_key**, sig) as result
   match result
       is_ok  => C.publick_key is C cuz sign_key and verify_key are correct
       is_err => C.publick_key is not C cuz sign_key or verify_key are incorrect

6: S <-> C is established

7: S.generate_shared_secret::from(C.publick_key)
   C.generate_shared_secret::from(S.publick_key)
   both shared_secrets are guaranteed to be the same
   from now on, shared_secret will be called SS

8: S <-> C handles data encrypted by chacha20poly1305 using SS as a key in communication...
```

## usage

in `Cargo.toml`,
```
jd_network = { git = "https://github.com/2vg/jd_network" }
```
or use `cargo add https://github.com/2vg/mini-assert` with `cargo-edit`(recommemded)

## TODO
- [ ] TCP
- [ ] UDP
