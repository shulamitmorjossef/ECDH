from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import os
import base64
import json

def sign_data(private_key, data: bytes) -> bytes:
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def run_test_vector():
    print("\n=== Running Test Vector ===")
    # וקטור בדיקה: מפתח סימטרי ידוע, IV ידוע, והודעה קבועה
    key = b'\x00' * 32  # 256-bit key filled with zeros
    iv = b'\x01' * 12   # 96-bit nonce filled with ones
    plaintext = b'Test vector message'

    # הצפנה
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # הדפסה לצורך בדיקה
    print("Ciphertext (base64):", base64.b64encode(ciphertext).decode())
    print("Tag (base64):", base64.b64encode(tag).decode())

    # פענוח
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag)
    ).decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    print("Decrypted:", decrypted.decode())
    assert decrypted == plaintext, "Test vector failed!"
    print("[✓] Test vector passed.")

def encrypt_message(key, plaintext):
    iv = os.urandom(12)  # 96-bit nonce for GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def derive_key(shared_secret, salt):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data'
    ).derive(shared_secret)

def decrypt_message(key, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag)
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def generate_public_and_private_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key, encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo):
    return public_key.public_bytes(
        encoding=encoding,
        format=format
    )

def verify_key_signatures(pub_key_a, sig_a, data_a, pub_key_b, sig_b, data_b) -> bool:
    valid_a = verify_signature(pub_key_a, sig_a, data_a)
    valid_b = verify_signature(pub_key_b, sig_b, data_b)
    return valid_a and valid_b

def shared_secrets_match(secret1: bytes, secret2: bytes) -> bool:
    return secret1 == secret2

def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)

def pack_encrypted_message(iv: bytes, ciphertext: bytes, tag: bytes) -> str:
    return json.dumps({
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    })

def unpack_encrypted_message(packet: str) -> tuple[bytes, bytes, bytes]:
    decoded = json.loads(packet)
    iv = base64.b64decode(decoded["iv"])
    ciphertext = base64.b64decode(decoded["ciphertext"])
    tag = base64.b64decode(decoded["tag"])
    return iv, ciphertext, tag

def simulate_communication():
    print("=== Key Generation ===")

    # Generate private and public keys for Party B
    private_key_a, public_key_a = generate_public_and_private_key()
    print("[A] Private and public keys generated.")

    # Generate private and public keys for Party B
    private_key_b, public_key_b = generate_public_and_private_key()
    print("[B] Private and public keys generated.")


    # Serialize public keys to bytes (simulate sending over network)
    public_bytes_a = serialize_public_key(public_key_a)
    public_bytes_b = serialize_public_key(public_key_b)

    # Each side signs its own public key
    signature_a = sign_data(private_key_a, public_bytes_a)
    signature_b = sign_data(private_key_b, public_bytes_b)
    print("[A] Signed own public key.")
    print("[B] Signed own public key.")

    # Each side verifies the signature received from the other side
    if verify_key_signatures(public_key_a, signature_a, public_bytes_a, public_key_b, signature_b, public_bytes_b):
        print("[A] Verified B's signature on B's public key.")
        print("[B] Verified A's signature on A's public key.")
    else:
        raise Exception("Signature verification failed! Aborting.")


    print("\n=== Public Key Exchange ===")
    public_bytes_a = serialize_public_key(public_key_a, encoding=serialization.Encoding.PEM)
    public_bytes_b = serialize_public_key(public_key_b, encoding=serialization.Encoding.PEM)
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
    print("[✓] Do shared secrets match?", shared_secrets_match(shared_secret_a, shared_secret_b))

    print("\n=== Symmetric Key Derivation (HKDF) ===")

    salt = generate_salt()
    symmetric_key_a = derive_key(shared_secret_a, salt)
    symmetric_key_b = derive_key(shared_secret_b, salt)
    print("[A] Derived AES key from shared secret.")
    print("[B] Derived AES key from shared secret.")

    print("\n=== Message Encryption by A ===")

    message_from_a = b"Hello from Party A!"
    iv, ciphertext, tag = encrypt_message(symmetric_key_a, message_from_a)
    print(f"[A] Original message: {message_from_a.decode()}")
    print("[A] Encrypted message (base64) ready to send.")

    # Pack encrypted message parts into JSON with base64 encoding (simulate network send)
    message_packet = pack_encrypted_message(iv, ciphertext, tag)
    print("[A] Message packet to send:", message_packet)


    print("\n=== Message Reception and Decryption by B ===")
    recv_iv, recv_ciphertext, recv_tag = unpack_encrypted_message(message_packet)


    decrypted_message = decrypt_message(symmetric_key_b, recv_iv, recv_ciphertext, recv_tag)
    print("[B] Decrypted message from A:", decrypted_message.decode())

    print("\n=== End of Communication ===")


if __name__ == "__main__":
    simulate_communication()
    run_test_vector()