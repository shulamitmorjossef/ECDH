from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import json

print("=== Key Generation ===")
# Generate private and public keys for Party A
private_key_a = ec.generate_private_key(ec.SECP256R1())
public_key_a = private_key_a.public_key()
print("[A] Private and public keys generated.")

# Generate private and public keys for Party B
private_key_b = ec.generate_private_key(ec.SECP256R1())
public_key_b = private_key_b.public_key()
print("[B] Private and public keys generated.")

print("\n=== Public Key Exchange ===")
# Serialize public keys to bytes (simulate sending over network)
public_bytes_a = public_key_a.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
public_bytes_b = public_key_b.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("[A] Sent public key to B.")
print("[B] Sent public key to A.")

# Deserialize received public keys
loaded_public_key_a = serialization.load_pem_public_key(public_bytes_a)
loaded_public_key_b = serialization.load_pem_public_key(public_bytes_b)
print("[A] Received public key from B.")
print("[B] Received public key from A.")

print("\n=== Shared Secret Derivation (ECDH) ===")
# Derive shared secrets
shared_secret_a = private_key_a.exchange(ec.ECDH(), loaded_public_key_b)
shared_secret_b = private_key_b.exchange(ec.ECDH(), loaded_public_key_a)
print("[A] Derived shared secret using B's public key.")
print("[B] Derived shared secret using A's public key.")
print("[✓] Do shared secrets match?", shared_secret_a == shared_secret_b)

print("\n=== Symmetric Key Derivation (HKDF) ===")
def derive_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)

symmetric_key_a = derive_key(shared_secret_a)
symmetric_key_b = derive_key(shared_secret_b)
print("[A] Derived AES key from shared secret.")
print("[B] Derived AES key from shared secret.")

print("\n=== Message Encryption by A ===")
def encrypt_message(key, plaintext):
    iv = os.urandom(12)  # 96-bit nonce for GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

message_from_a = b"Hello from Party A!"
iv, ciphertext, tag = encrypt_message(symmetric_key_a, message_from_a)
print(f"[A] Original message: {message_from_a.decode()}")
print("[A] Encrypted message (base64) ready to send.")

# Pack encrypted message parts into JSON with base64 encoding (simulate network send)
message_packet = json.dumps({
    "iv": base64.b64encode(iv).decode(),
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "tag": base64.b64encode(tag).decode()
})
print("[A] Message packet to send:", message_packet)

print("\n=== Message Reception and Decryption by B ===")
# Simulate B receiving and decoding the message packet
received_packet = json.loads(message_packet)
recv_iv = base64.b64decode(received_packet["iv"])
recv_ciphertext = base64.b64decode(received_packet["ciphertext"])
recv_tag = base64.b64decode(received_packet["tag"])

def decrypt_message(key, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag)
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

decrypted_message = decrypt_message(symmetric_key_b, recv_iv, recv_ciphertext, recv_tag)
print("[B] Decrypted message from A:", decrypted_message.decode())

print("\n=== End of Communication ===")
