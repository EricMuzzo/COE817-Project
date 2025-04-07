import logging
from datetime import datetime
import os
import base64

from ..security.helpers import fetch_audit_key, aes_encrypt, aes_decrypt

module_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(module_dir)
log_file_path = os.path.join(parent_dir, "audit.log")

audit_key = fetch_audit_key()

logger = logging.getLogger("transactions")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(log_file_path)
file_handler.setLevel(logging.INFO)

formatter = logging.Formatter("%(message)s")
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


def encrypt_log(message: str) -> dict:
    """Encrpyt the message to be logged"""
    iv, ciphertext = aes_encrypt(message.encode(), audit_key)
    return iv, ciphertext


def log_transaction(user_id: int, action: str, timestamp: datetime):
    """Logs the transaction to the audit log"""
    log_msg = f"{user_id},{action},{timestamp}"
    iv, ciphertext = encrypt_log(log_msg)
    logger.info(f"{base64.b64encode(iv).decode()},{base64.b64encode(ciphertext).decode()}")
    
def read_audit():
    """Prints the decrypted audit log to the console"""
    with open(log_file_path, 'r') as audit_file:
        for enc_record in audit_file:
            enc_record = enc_record.split(",")
            iv = base64.b64decode(enc_record[0])
            ciphertext = base64.b64decode(enc_record[1])
            decrypted_record = aes_decrypt(iv, ciphertext, audit_key)
            print(decrypted_record.decode())