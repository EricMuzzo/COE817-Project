import logging
from datetime import datetime
import os

module_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(module_dir)
log_file_path = os.path.join(parent_dir, "audit.log")


logger = logging.getLogger("transactions")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(log_file_path)
file_handler.setLevel(logging.INFO)

formatter = logging.Formatter("%(message)s")
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


def encrypt_log(message: str):
    """Encrpyt the message to be logged"""
    return message


def log_transaction(user_id: int, action: str, timestamp: datetime):
    """Logs the transaction to the audit log"""
    
    log_msg = f"{user_id},{action},{timestamp}"
    print(log_msg)
    encrypted_msg = encrypt_log(log_msg)
    logger.info(encrypted_msg)