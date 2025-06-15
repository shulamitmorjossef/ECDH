# ECDH 

This project demonstrates a secure communication protocol using elliptic curve cryptography (ECDSA, ECDH), HKDF key derivation, AES-GCM encryption/decryption, and message signing/verification. It also includes test vectors for encryption validation and a visualization of an elliptic curve with key extraction.

---

## Contents

- `simulate_communication()`: Simulates key generation, signing, verification, shared secret derivation, key derivation, message encryption, transmission, and decryption between two parties.
- `test_vector()`: Runs predefined AES-GCM encryption/decryption test vectors to validate correctness.
- `demo_elliptic_curve_and_public_key()`: Plots an elliptic curve and extracts the public key point coordinates.
- Utility functions for cryptographic operations and message packing/unpacking.

---

## Requirements

- Python 3.7+
- `cryptography` library
- `matplotlib` library
- `numpy` library

Install dependencies via pip:

```bash
pip install cryptography matplotlib numpy
```

## How to Run
Run the script with Python:

```bash
main.py
```
This will:

- Simulate a full secure communication protocol between two parties with signing, key exchange, encryption, and decryption.

- Execute several AES-GCM test vectors, printing encryption details and verifying correctness.

- Plot an elliptic curve and print the public key point coordinates.


## Main Functions Overview
### simulate_communication()
- Generates ECDSA key pairs for two parties (A and B).

- Signs and verifies public keys.

- Exchanges public keys and derives shared ECDH secrets.

- Derives symmetric AES keys from shared secrets using HKDF.

- Encrypts a message from party A using AES-GCM.

- Sends and decrypts the encrypted message at party B.

- Prints all major steps and verification statuses.

### test_vector()
- Defines multiple AES-GCM encryption test vectors with keys, IVs, and plaintexts.

- Encrypts and decrypts each test vector, asserting that decryption matches the original plaintext.

- Prints ciphertexts and validation messages.

### demo_elliptic_curve_and_public_key()
- Plots the elliptic curve defined by the equation: y^2 = x^3 + ax + b with parameters a = -3, b = 5.

- Generates an ECDSA key pair on the SECP256R1 curve.

- Extracts and prints the public key's (x, y) coordinates.


## Example Output Snippet
```bash
=== Key Generation ===
[A] Private and public keys generated.
[B] Private and public keys generated.
[A] Signed own public key.
[B] Signed own public key.
[A] Verified B's signature on B's public key.
[B] Verified A's signature on A's public key.

=== Public Key Exchange ===
[A] Sent public key to B.
[B] Sent public key to A.

=== Shared Secret Derivation (ECDH) ===
[A] Derived shared secret using B's public key.
[B] Derived shared secret using A's public key.
[✓] Do shared secrets match? True

=== Symmetric Key Derivation (HKDF) ===
[A] Derived AES key from shared secret.
[B] Derived AES key from shared secret.

=== Message Encryption by A ===
[A] Original message: Hello from Party A!
[A] Encrypted message (base64) ready to send.
[A] Message packet to send: {"iv": "...", "ciphertext": "...", "tag": "..."}

=== Message Reception and Decryption by B ===
[B] Decrypted message from A: Hello from Party A!

=== End of Communication ===
```
Enjoy  coding :)
