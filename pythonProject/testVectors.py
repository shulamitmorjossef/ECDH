import binascii
import hashlib
from ecdsa import ECDH, SECP256k1, SigningKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import json

# מפתחות פרטיים
privkey0_hex = "30fbc0d41cd01885333211ff53b9ed29bcbdccc3ff13625a82db61a7bb8eae19"
privkey1_hex = "a795c287c132154a8b96dc81dc8b4e2f02bbbad78dab0567b59db1d1540751f6"
privkey0 = bytes.fromhex(privkey0_hex)
privkey1 = bytes.fromhex(privkey1_hex)

# מפתחות ציבוריים בפורמט uncompressed
pubkey0_hex = "04591775168f328a2adbcb887acd287d55a1025d7d2b15e1937278a5efd1d48b19c00cf07559320e6d278a71c9e58bae5d9ab041d7905c66291f4d08459c946e18"
pubkey1_hex = "043ee7314407753d1ba296de29f07b2cd5505ca94b614f127e71f3c19fc7845daf49c9bb4bf4d00d3b5411c8eb86d59a2dcadc5a13115fa9fef44d1e0b7ef11cab"
pubkey0 = bytes.fromhex(pubkey0_hex)
pubkey1 = bytes.fromhex(pubkey1_hex)

# יצירת shared secret עם sk2 + pk1
sk2 = SigningKey.from_string(privkey1, curve=SECP256k1)
ecdh1 = ECDH(curve=SECP256k1)
ecdh1.load_private_key(sk2)
ecdh1.load_received_public_key_bytes(pubkey0)
shared_secret = ecdh1.generate_sharedsecret_bytes()

print("Shared secret (hex):", binascii.hexlify(shared_secret).decode().upper())

# נגזור מפתח סימטרי עם HKDF (SHA-256)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_secret)

print("Derived AES key:", binascii.hexlify(derived_key).decode())

# הצפנה עם AES-GCM
def encrypt_message(key, plaintext):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def decrypt_message(key, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag)
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# הודעה
plaintext = b"Hello from ECDH!"
iv, ciphertext, tag = encrypt_message(derived_key, plaintext)

# שליחה כ־JSON מדומה
packet = json.dumps({
    "iv": base64.b64encode(iv).decode(),
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "tag": base64.b64encode(tag).decode()
})
print("\nEncrypted packet to send:")
print(packet)

# פיענוח בצד השני
received = json.loads(packet)
recv_iv = base64.b64decode(received["iv"])
recv_ct = base64.b64decode(received["ciphertext"])
recv_tag = base64.b64decode(received["tag"])

decrypted = decrypt_message(derived_key, recv_iv, recv_ct, recv_tag)
print("\nDecrypted message:", decrypted.decode())
