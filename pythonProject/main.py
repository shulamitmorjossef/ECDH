from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import ec
import matplotlib.pyplot as plt
import numpy as np

def sign_data(private_key, data: bytes) -> bytes:
    """
    Sign the given data using the provided ECDSA private key and SHA-256.

    Args:
        private_key: An Elliptic Curve private key object.
        data (bytes): Data to sign.

    Returns:
        bytes: The signature of the data.
    """
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    """
    Verify a signature for the given data using the ECDSA public key.

    Args:
        public_key: An Elliptic Curve public key object.
        signature (bytes): Signature to verify.
        data (bytes): Data that was signed.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def get_test_vectors():
    """
    Provides a list of test vectors containing keys, IVs, and plaintexts for encryption tests.

    Returns:
        list of dict: Each dict contains 'key' (bytes), 'iv' (bytes), and 'plaintext' (bytes).
    """
    return [
        {
            "key": b'\x00' * 32,
            "iv": b'\x01' * 12,
            "plaintext": b'Test vector message'
        },
        {
            "key": b'\x0f' * 32,
            "iv": b'\x02' * 12,
            "plaintext": b'Another test message with different key and IV'
        },
        {
            "key": b'\xff' * 32,
            "iv": b'\x00' * 12,
            "plaintext": b''
        },
        {
            "key": b'\x01' * 32,
            "iv": b'\x0a' * 12,
            "plaintext": b'Short'
        },
        {
            "key": b'\x12' * 32,
            "iv": b'\x0b' * 12,
            "plaintext": b'A longer message that tests encryption and decryption over more bytes'
        }
    ]

def run_test_vector(vector_id, key, iv, plaintext):
    """
    Runs encryption and decryption on a test vector and validates correctness.

    Args:
        vector_id (int): Identifier for the test vector.
        key (bytes): AES key.
        iv (bytes): Initialization vector (nonce).
        plaintext (bytes): Plaintext message to encrypt and decrypt.
    """
    print(f"\n=== Running Test Vector #{vector_id} ===")
    print(f"Key (hex): {key.hex()}")
    print(f"IV (hex): {iv.hex()}")
    print(f"Plaintext: {plaintext}")

    iv, ciphertext, tag = encrypt_message(key, plaintext, iv)

    print("Ciphertext (base64):", base64.b64encode(ciphertext).decode())
    print("Tag (base64):", base64.b64encode(tag).decode())

    decrypted = decrypt_message(key, iv, ciphertext, tag)
    print("Decrypted:", decrypted)

    assert decrypted == plaintext, f"Test vector #{vector_id} failed!"
    print(f"[✓] Test vector #{vector_id} passed.")

def test_vector():
    """
    Runs all predefined test vectors through the encryption/decryption process.
    """
    vectors = get_test_vectors()
    for i, vector in enumerate(vectors, start=1):
        run_test_vector(i, vector["key"], vector["iv"], vector["plaintext"])

def encrypt_message(key, plaintext, iv=None):
    """
    Encrypt a plaintext message using AES-GCM with the provided key and IV.

    Args:
        key (bytes): AES symmetric key.
        plaintext (bytes): Message to encrypt.
        iv (bytes, optional): Initialization vector (nonce). If None, generates random 12 bytes.

    Returns:
        tuple: (iv (bytes), ciphertext (bytes), tag (bytes))
    """
    if iv is None:
        iv = os.urandom(12)  # 96-bit nonce for GCM

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def derive_key(shared_secret, salt):
    """
    Derive a symmetric AES key from the ECDH shared secret using HKDF with SHA-256.

    Args:
        shared_secret (bytes): Shared secret from ECDH key exchange.
        salt (bytes): Salt for HKDF.

    Returns:
        bytes: Derived symmetric key of length 32 bytes.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data'
    ).derive(shared_secret)

def decrypt_message(key, iv, ciphertext, tag):
    """
    Decrypt ciphertext encrypted with AES-GCM.

    Args:
        key (bytes): AES symmetric key.
        iv (bytes): Initialization vector (nonce).
        ciphertext (bytes): Encrypted message.
        tag (bytes): Authentication tag.

    Returns:
        bytes: Decrypted plaintext.
    """
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag)
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def generate_public_and_private_key():
    """
    Generate an ECDSA private and public key pair using the SECP256R1 curve.

    Returns:
        tuple: (private_key, public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key, encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo):
    """
    Serialize a public key to bytes in the specified encoding and format.

    Args:
        public_key: Elliptic Curve public key object.
        encoding: Encoding type (DER or PEM).
        format: Public key format.

    Returns:
        bytes: Serialized public key.
    """
    return public_key.public_bytes(
        encoding=encoding,
        format=format
    )

def verify_key_signatures(pub_key_a, sig_a, data_a, pub_key_b, sig_b, data_b) -> bool:
    """
    Verify two signatures on their respective data with the given public keys.

    Args:
        pub_key_a: Public key A.
        sig_a (bytes): Signature from private key A.
        data_a (bytes): Data signed by private key A.
        pub_key_b: Public key B.
        sig_b (bytes): Signature from private key B.
        data_b (bytes): Data signed by private key B.

    Returns:
        bool: True if both signatures are valid, False otherwise.
    """
    valid_a = verify_signature(pub_key_a, sig_a, data_a)
    valid_b = verify_signature(pub_key_b, sig_b, data_b)
    return valid_a and valid_b

def shared_secrets_match(secret1: bytes, secret2: bytes) -> bool:
    """
    Check if two shared secrets are identical.

    Args:
        secret1 (bytes): First shared secret.
        secret2 (bytes): Second shared secret.

    Returns:
        bool: True if secrets match, False otherwise.
    """
    return secret1 == secret2

def generate_salt(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt.

    Args:
        length (int): Length of salt in bytes. Default is 16.

    Returns:
        bytes: Randomly generated salt.
    """
    return os.urandom(length)

def pack_encrypted_message(iv: bytes, ciphertext: bytes, tag: bytes) -> str:
    """
    Pack the encrypted message components into a JSON string with base64 encoding.

    Args:
        iv (bytes): Initialization vector.
        ciphertext (bytes): Encrypted data.
        tag (bytes): Authentication tag.

    Returns:
        str: JSON string containing base64 encoded parts.
    """
    return json.dumps({
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    })

def unpack_encrypted_message(packet: str) -> tuple[bytes, bytes, bytes]:
    """
    Unpack a JSON string with base64 encoded encrypted message parts.

    Args:
        packet (str): JSON string containing the encrypted message.

    Returns:
        tuple: (iv (bytes), ciphertext (bytes), tag (bytes))
    """
    decoded = json.loads(packet)
    iv = base64.b64decode(decoded["iv"])
    ciphertext = base64.b64decode(decoded["ciphertext"])
    tag = base64.b64decode(decoded["tag"])
    return iv, ciphertext, tag

def simulate_communication():
    """
    Simulates a secure communication protocol between two parties using ECDSA signatures,
    ECDH key exchange, HKDF key derivation, AES-GCM encryption, and message packing/unpacking.

    Prints the steps and outcomes of each phase.
    """
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

def plot_elliptic_curve(a, b, x_range=(-3, 3)):
    """
    Plot an elliptic curve defined by y^2 = x^3 + a*x + b over the specified x range.

    Args:
        a (float): Coefficient 'a' in the elliptic curve equation.
        b (float): Coefficient 'b' in the elliptic curve equation.
        x_range (tuple): Range of x values (min, max) to plot.
    """
    x = np.linspace(x_range[0], x_range[1], 400)
    y_squared = x ** 3 + a * x + b
    y_positive = np.sqrt(np.clip(y_squared, 0, None))
    y_negative = -y_positive

    plt.plot(x, y_positive, label="Elliptic Curve")
    plt.plot(x, y_negative)
    plt.title("Elliptic Curve y^2 = x^3 + ax + b")
    plt.xlabel("x")
    plt.ylabel("y")
    plt.grid(True)
    plt.legend()
    plt.show()

def extract_public_key_point(pubkey):
    """
    Extract the (x, y) coordinates of an elliptic curve public key point.

    Args:
        pubkey: Elliptic curve public key object.

    Returns:
        tuple: (x, y) as integers.
    """
    numbers = pubkey.public_numbers()
    return (numbers.x, numbers.y)


def demo_elliptic_curve_and_public_key():
    def demo_elliptic_curve_and_public_key():
        """
        Demonstrates plotting an elliptic curve and extracting the public key point from a generated key pair.

        Steps:
        1. Defines an elliptic curve with parameters a = -3 and b = 5.
        2. Plots the elliptic curve based on these parameters.
        3. Generates an elliptic curve private and public key pair.
        4. Extracts the (x, y) coordinates from the generated public key.
        5. Prints the public key point coordinates.

        This function is intended as a simple demonstration of elliptic curve properties
        and public key extraction.
        """
    a = -3
    b = 5
    plot_elliptic_curve(a, b)

    priv, pub = generate_public_and_private_key()
    x, y = extract_public_key_point(pub)
    print(f"Public key point on curve: x={x}, y={y}")


if __name__ == "__main__":
    # Run demonstration of secure communication protocol.
    simulate_communication()

    # Run AES-GCM encryption/decryption test vectors.
    test_vector()

    # Demonstrate elliptic curve plotting and public key extraction.
    demo_elliptic_curve_and_public_key()