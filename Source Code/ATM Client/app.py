import os
import json
import base64
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash

# Cryptography and WebSocket imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import websocket

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a strong secret key

# File path for the JSON log file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "transaction_log.txt")

# Global persistent WebSocket Connection
persistent_ws = None

def get_timestamp():
    """Returns the current UTC time in the format 'YYYY-MM-DD HH:MM:SS'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def log_transaction(data):
    """Appends the JSON data as a string to the log file and prints a debug statement."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
        print("Logged transaction:", data)
    except Exception as e:
        print("Error logging transaction:", e)

# -------------------------
# Local Security Helper Functions
# -------------------------
def fetch_shared_key() -> bytes:
    key_file = os.path.join(BASE_DIR, "shared_key.key")
    with open(key_file, 'rb') as f:
        return f.read()

def generate_nonce():
    return os.urandom(16)

def encrypt_with_key(data: dict, key: bytes = None) -> dict:
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

def compute_master_secret(psk: bytes, client_nonce: bytes, bank_nonce: bytes) -> bytes:
    h_obj = hmac.HMAC(psk, hashes.SHA256(), backend=default_backend())
    h_obj.update(client_nonce + bank_nonce)
    return h_obj.finalize()

def hkdf_derive(master_secret: bytes, info: bytes, length: int) -> bytes:
    hkdf_obj = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf_obj.derive(master_secret)

def derive_keys_from_master(master_secret: bytes, encryption_key_length: int = 32, mac_key_length: int = 32) -> tuple:
    total_length = encryption_key_length + mac_key_length
    info = b"banking key derivation"
    key_material = hkdf_derive(master_secret, info, total_length)
    return key_material[:encryption_key_length], key_material[encryption_key_length:]

def aes_encrypt(plaintext: bytes, encryption_key: bytes = None) -> tuple:
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
    if encryption_key is None:
        encryption_key = fetch_shared_key()
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

def compute_hmac(message: bytes, mac_key: bytes) -> bytes:
    h_obj = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h_obj.update(message)
    return h_obj.finalize()

def verify_hmac(message: bytes, mac_key: bytes, received_mac: bytes) -> bool:
    h_obj = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h_obj.update(message)
    try:
        h_obj.verify(received_mac)
        return True
    except Exception:
        return False

def secure_message(plaintext: str, encryption_key: bytes, mac_key: bytes) -> dict:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    iv, ciphertext = aes_encrypt(plaintext, encryption_key)
    mac = compute_hmac(ciphertext, mac_key)
    return {"iv": iv.hex(), "ciphertext": ciphertext.hex(), "mac": mac.hex()}

def verify_and_decrypt_message(secure_msg: dict, encryption_key: bytes, mac_key: bytes) -> str:
    iv = bytes.fromhex(secure_msg["iv"])
    ciphertext = bytes.fromhex(secure_msg["ciphertext"])
    received_mac = bytes.fromhex(secure_msg["mac"])
    if not verify_hmac(ciphertext, mac_key, received_mac):
        raise Exception("MAC verification failed")
    plaintext = aes_decrypt(iv, ciphertext, encryption_key)
    return plaintext.decode('utf-8')

# -------------------------
# WebSocket Communication Functions (ATM Client Side)
# -------------------------
def connect_to_bank_server():
    ws_url = "ws://localhost:8765"
    try:
        ws = websocket.create_connection(ws_url)
        print("Connected to bank server at", ws_url)
        return ws
    except Exception as e:
        print("Error connecting to bank server:", e)
        return None

def send_message_via_websocket(ws, message):
    try:
        if isinstance(message, dict):
            message = json.dumps(message)
        ws.send(message)
        print("Sent message:", message)
    except Exception as e:
        print("Error sending message:", e)

def receive_message_from_bank_server(ws):
    try:
        message = ws.recv()
        print("Received message:", message)
        try:
            return json.loads(message)
        except Exception:
            return message
    except Exception as e:
        print("Error receiving message:", e)
        return None

def send_to_bank_server(message):
    global persistent_ws
    if persistent_ws is None:
        persistent_ws = connect_to_bank_server()
    if persistent_ws is not None:
        send_message_via_websocket(persistent_ws, message)
        return receive_message_from_bank_server(persistent_ws)
    else:
        return None

# -------------------------
# Flask Routes
# -------------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        submit_action = request.form.get('submit')
        if username and password:
            client_nonce = generate_nonce()
            nonce_str = base64.b64encode(client_nonce).decode('utf-8')
            timestamp = get_timestamp()
            if submit_action == "login":
                message_plain = {
                    "type": "login",
                    "nonce": nonce_str,
                    "data": {"timestamp": timestamp, "username": username, "password": password}
                }
            else:
                name = request.form.get('name')
                if not name:
                    error = "Please provide your name for registration."
                    return render_template('login.html', error=error)
                message_plain = {
                    "type": "register",
                    "nonce": nonce_str,
                    "data": {"timestamp": timestamp, "username": username, "name": name, "password": password}
                }

            psk = fetch_shared_key()
            encrypted_message = encrypt_with_key(message_plain, psk)
            log_transaction(encrypted_message)
            encrypted_response = send_to_bank_server(encrypted_message)
            if not encrypted_response or 'iv' not in encrypted_response:
                error = "Could not contact bank server or invalid response."
                return render_template('login.html', error=error)

            try:
                response_decrypted = decrypt_with_key(encrypted_response, psk)
            except Exception as e:
                error = f"Failed to decrypt response: {e}"
                return render_template('login.html', error=error)

            if response_decrypted.get("status") == "success":
                session['user_id'] = response_decrypted['data'].get('user_id')
                session['account_id'] = response_decrypted['data'].get('account_id')
                session['username'] = response_decrypted['data'].get('username')
                session['name'] = response_decrypted['data'].get('name')
                bank_nonce_b64 = response_decrypted.get('bank_nonce')
                if not bank_nonce_b64:
                    error = "Bank server did not return a bank_nonce."
                    return render_template('login.html', error=error)
                bank_nonce = base64.b64decode(bank_nonce_b64)
                master_key = compute_master_secret(psk, client_nonce, bank_nonce)
                encryption_key, mac_key = derive_keys_from_master(master_key)
                session['encryption_key'] = encryption_key.hex()
                session['mac_key'] = mac_key.hex()
                return redirect(url_for('dashboard'))
            else:
                error = response_decrypted.get("message", "Authentication failed.")
        else:
            error = "Please provide username and password."
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or 'account_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html',
                           username=session.get('username'),
                           account_id=session.get('account_id'),
                           name=session.get('name'))

@app.route('/transaction/deposit', methods=['POST'])
def deposit_route():
    if 'user_id' not in session or 'account_id' not in session:
        return redirect(url_for('login'))
    data = {
        "timestamp": get_timestamp(),
        "user_id": session['user_id'],
        "account_id": session['account_id'],
        "amount": request.form.get('amount')
    }
    message_plain = {"type": "deposit", "data": data}
    encryption_key = bytes.fromhex(session['encryption_key'])
    mac_key = bytes.fromhex(session['mac_key'])
    secure_msg = secure_message(json.dumps(message_plain), encryption_key, mac_key)
    log_transaction(secure_msg)

    # Send and print raw response
    response = send_to_bank_server(secure_msg)
    print("Bank server raw response for deposit:", response)

    # Decrypt and print
    try:
        decrypted = verify_and_decrypt_message(response, encryption_key, mac_key)
        print("Decrypted bank server response for deposit:", decrypted)
    except Exception as e:
        print("Failed to decrypt bank server response for deposit:", e)

    return redirect(url_for('dashboard'))

@app.route('/transaction/withdrawal', methods=['POST'])
def withdrawal_route():
    if 'user_id' not in session or 'account_id' not in session:
        return redirect(url_for('login'))
    data = {
        "timestamp": get_timestamp(),
        "user_id": session['user_id'],
        "account_id": session['account_id'],
        "amount": request.form.get('amount')
    }
    message_plain = {"type": "withdrawal", "data": data}
    encryption_key = bytes.fromhex(session['encryption_key'])
    mac_key = bytes.fromhex(session['mac_key'])
    secure_msg = secure_message(json.dumps(message_plain), encryption_key, mac_key)
    log_transaction(secure_msg)

    response = send_to_bank_server(secure_msg)
    print("Bank server raw response for withdrawal:", response)

    try:
        decrypted = verify_and_decrypt_message(response, encryption_key, mac_key)
        print("Decrypted bank server response for withdrawal:", decrypted)
    except Exception as e:
        print("Failed to decrypt bank server response for withdrawal:", e)

    return redirect(url_for('dashboard'))

@app.route('/transaction/balance_inquiry', methods=['POST'])
def balance_inquiry_route():
    if 'user_id' not in session or 'account_id' not in session:
        return redirect(url_for('login'))
    data = {
        "timestamp": get_timestamp(),
        "user_id": session['user_id'],
        "account_id": session['account_id']
    }
    message_plain = {"type": "balance", "data": data}
    encryption_key = bytes.fromhex(session['encryption_key'])
    mac_key = bytes.fromhex(session['mac_key'])
    secure_msg = secure_message(json.dumps(message_plain), encryption_key, mac_key)
    log_transaction(secure_msg)

    response = send_to_bank_server(secure_msg)
    print("Bank server raw response for balance inquiry:", response)

    try:
        decrypted = verify_and_decrypt_message(response, encryption_key, mac_key)
        print("Decrypted bank server response for balance inquiry:", decrypted)
    except Exception as e:
        print("Failed to decrypt bank server response for balance inquiry:", e)

    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    global persistent_ws
    if persistent_ws:
        persistent_ws.close()
        persistent_ws = None
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
