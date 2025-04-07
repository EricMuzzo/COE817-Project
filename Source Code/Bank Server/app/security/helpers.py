# -------------------------
# Security Functions for Encryption and Authentication
# (These functions implement the authenticated key distribution protocol and secure message operations.)
# -------------------------

import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


module_dir = os.path.dirname(os.path.abspath(__file__))
key_file_path = os.path.join(module_dir, "shared_key.key")


def generate_key(path: str = "shared_key.key") -> bytes:
    """Generates a random 32 byte key and saves it to a filepath"""
    key = os.urandom(32)
    key_file_path = os.path.join(module_dir, path)
    with open(key_file_path, 'wb') as key_file:
        key_file.write(key)
    return key

        
def fetch_shared_key() -> bytes:
    """Fetches the 32 byte pre-shared key from the `shared_key.key` file"""
    with open(key_file_path, 'rb') as key_file:
        return key_file.read()
    

def fetch_audit_key() -> bytes:
    """Fetches the 32 byte audit key from the `audit_key.key` file"""
    audit_key_file_path = os.path.join(module_dir, "audit_key.key")
    with open(audit_key_file_path, 'rb') as key_file:
        return key_file.read()


def generate_nonce():
    """Generate a secure random nonce."""
    return os.urandom(16)

def encrypt_with_key(data: dict, key: bytes = None) -> dict:
    """
    Encrypt a dictionary (data) using AES-CBC with the provided key.
    The data is first converted to a JSON string.
    Returns a dictionary containing the IV and ciphertext in hexadecimal.
    """
    if key is None:
        key = fetch_shared_key()
        
    plaintext = json.dumps(data).encode('utf-8')
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return {"iv": iv.hex(), "ciphertext": ciphertext.hex()}

def decrypt_with_key(encrypted_data: dict, key: bytes = None) -> dict:
    """
    Decrypt data encrypted by encrypt_with_key using AES-CBC.
    Expects a dictionary with hexadecimal 'iv' and 'ciphertext'.
    Returns the original dictionary.
    """
    if key is None:
        key = fetch_shared_key()
    
    iv = bytes.fromhex(encrypted_data["iv"])
    ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return json.loads(plaintext.decode('utf-8'))

def compute_master_secret(psk, client_nonce: bytes, bank_nonce: bytes) -> bytes:
    """
    Compute the Master Secret using an HMAC over the concatenation of client_nonce and bank_nonce with the PSK.
    Returns the derived master secret bytes.
    """
    h_obj = hmac.HMAC(psk, hashes.SHA256(), backend=default_backend())
    h_obj.update(client_nonce + bank_nonce)
    return h_obj.finalize()

def hkdf_derive(master_secret: bytes, info: bytes, length: int) -> bytes:
    """
    Derive a key of 'length' bytes from the master_secret using HKDF with SHA-256.
    """
    hkdf_obj = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf_obj.derive(master_secret)

def derive_keys_from_master(master_secret: bytes, encryption_key_length: int = 32, mac_key_length: int = 32) -> tuple[bytes, bytes]:
    """
    Derive two keys from the provided master_secret using HKDF:
      - An encryption key for data confidentiality.
      - A MAC key for message authentication.
    
    This function uses the existing hkdf_derive helper to derive a total of
    (encryption_key_length + mac_key_length) bytes, and then splits the result.
    
    :param master_secret: The shared master secret generated during key distribution.
    :param encryption_key_length: The desired length of the encryption key in bytes (default 32).
    :param mac_key_length: The desired length of the MAC key in bytes (default 32).
    :return: A tuple containing (encryption_key, mac_key).
    """
    total_length = encryption_key_length + mac_key_length
    info = b"banking key derivation"  # This info string can be adjusted based on your design.
    key_material = hkdf_derive(master_secret, info, total_length)
    encryption_key = key_material[:encryption_key_length]
    mac_key = key_material[encryption_key_length:]
    return encryption_key, mac_key


def aes_encrypt(plaintext: bytes, encryption_key: bytes = None) -> tuple:
    """
    Encrypt plaintext bytes using AES-CBC with the provided encryption key.
    Returns the IV and ciphertext.
    """
    if encryption_key is None:
        encryption_key = fetch_shared_key()
    
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

def aes_decrypt(iv: bytes, ciphertext: bytes, encryption_key: bytes = None) -> bytes:
    """
    Decrypt ciphertext using AES-CBC with the provided encryption key and IV.
    Returns the decrypted plaintext bytes.
    """
    if encryption_key is None:
        encryption_key = fetch_shared_key()
    
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

def compute_hmac(message: bytes, mac_key: bytes):
    """
    Compute an HMAC (SHA-256) for the given message using the mac_key.
    """
    h_obj = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h_obj.update(message)
    return h_obj.finalize()

def verify_hmac(message: bytes, mac_key: bytes, received_mac: bytes) -> bool:
    """
    Verify the HMAC for the given message matches the received_mac.
    Returns True if the MAC is valid, otherwise False.
    """
    h_obj = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h_obj.update(message)
    try:
        h_obj.verify(received_mac)
        return True
    except Exception:
        return False

def secure_message(plaintext: str | bytes, encryption_key: bytes, mac_key: bytes) -> dict:
    """
    Secure a plaintext message by:
    - Encrypting it using AES-CBC.
    - Computing an HMAC over the ciphertext.
    Returns a dictionary with the IV, ciphertext, and MAC (all in hexadecimal).
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    iv, ciphertext = aes_encrypt(plaintext, encryption_key)
    mac = compute_hmac(ciphertext, mac_key)
    return {
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "mac": mac.hex()
    }

def verify_and_decrypt_message(secure_msg, encryption_key: bytes, mac_key: bytes) -> str:
    """
    Verify the MAC of a secure message and, if valid, decrypt and return the plaintext string.
    Raises an exception if MAC verification fails.
    """
    iv = bytes.fromhex(secure_msg["iv"])
    ciphertext = bytes.fromhex(secure_msg["ciphertext"])
    received_mac = bytes.fromhex(secure_msg["mac"])
    if not verify_hmac(ciphertext, mac_key, received_mac):
        raise Exception("MAC verification failed")
    plaintext = aes_decrypt(iv, ciphertext, encryption_key)
    return plaintext.decode('utf-8')