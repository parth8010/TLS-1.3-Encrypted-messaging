# TLS 1.3 Encrypted messaging
### This application demonstrates working of TLS 1.3 as form of real time encrypted server and client communication by messaging.

## Features
* TLS 1.3 implementation
* Authenticated encryption - AES 256 GCM and ChaCha20
* Secure key derivation - HKDF based key schedule
* Real time messaging
* Local testing

## Components & description

| Component | Description |
| --- | --- |
| Handshake Protocol | ClientHello, ServerHello, key exchange |
| Record Layer | Message framing and encryption/decryption |
| Key Schedule | HKDF based key schedule |
| Cipher Suites | AES 256 GCM, ChaCha20 |
| Cryptographic Foundation | ECDHE, X25519, secure random generation |

## Basic Flow
<img width="361" height="604" alt="image" src="https://github.com/user-attachments/assets/d4138b16-200b-4dbd-91eb-767e072f89e3" />

