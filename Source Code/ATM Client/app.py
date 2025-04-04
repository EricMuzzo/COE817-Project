import os
import json
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash

# Cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# For WebSocket client functionality; install via: pip install websocket-client
import websocket

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a strong secret key

# File path for the JSON log file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "transaction_log.txt")

def get_timestamp():
    """Returns the current UTC time in ISO 8601 format with 'Z' suffix using a timezone-aware datetime."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def log_transaction(data):
    """Appends the JSON data as a string to the log file and prints a debug statement."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
        print("Logged transaction:", data)
    except Exception as e:
        print("Error logging transaction:", e)

# -------------------------
# WebSocket Communication Functions (ATM Client Side)
# -------------------------

def connect_to_bank_server():
    """
    Establish a WebSocket connection to the bank server.
    Expected bank server endpoint: "ws://BANK_SERVER_ADDRESS:8765"
    (Replace BANK_SERVER_ADDRESS with the actual server address.)
    The bank server must implement a matching WebSocket endpoint.
    Returns the WebSocket connection object.
    """
    ws_url = "ws://BANK_SERVER_ADDRESS:8765"  # TODO: Update with actual bank server URL.
    try:
        ws = websocket.create_connection(ws_url)
        print("Connected to bank server at", ws_url)
        return ws
    except Exception as e:
        print("Error connecting to bank server:", e)
        return None

def send_message_via_websocket(ws, message):
    """
    Send a message to the bank server via the established WebSocket connection.
    The message should be a JSON string or a dictionary (converted to JSON).
    It is expected that the message is already secured (if required).
    """
    try:
        if isinstance(message, dict):
            message = json.dumps(message)
        ws.send(message)
        print("Sent message:", message)
    except Exception as e:
        print("Error sending message:", e)

def receive_message_from_bank_server(ws):
    """
    Wait for and receive a message from the bank server via the WebSocket connection.
    Returns the received message (attempts to parse it as JSON).
    """
    try:
        message = ws.recv()
        print("Received message:", message)
        try:
            message = json.loads(message)
        except Exception:
            pass
        return message
    except Exception as e:
        print("Error receiving message:", e)
        return None

def send_to_bank_server(message):
    """
    Helper function that connects to the bank server, sends a message,
    receives the response, and then closes the connection.
    """
    ws = connect_to_bank_server()
    if ws is not None:
        send_message_via_websocket(ws, message)
        response = receive_message_from_bank_server(ws)
        ws.close()
        return response
    else:
        return None

# -------------------------
# Flask Routes
# -------------------------

@app.route('/')
def index():
    """
    Always redirect to the login page when accessing the root URL.
    """
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    GET: Render the login page for user ID, account number, and password input.
    
    POST: Process the login form submission.
         - Collect the user ID, account number, and password.
         - Construct a JSON message with type "login" including:
             • timestamp
             • user_id
             • account_id (account number)
             • password
         - Send the message via WebSocket to the bank server.
           (The bank server is expected to decrypt, validate, and reply accordingly.)
         - Log the transaction and, for now, accept any credentials.
         - Store the user ID and account number in the session and redirect to the dashboard.
    """
    error = None
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        account_number = request.form.get('account_number')
        password = request.form.get('password')
        
        if user_id and account_number and password:
            login_data = {
                "type": "login",
                "data": {
                    "timestamp": get_timestamp(),
                    "user_id": user_id,
                    "account_id": account_number,
                    "password": password
                }
            }
            log_transaction(login_data)
            
            # Send login message via WebSocket to bank server
            response = send_to_bank_server(login_data)
            print("Bank server response for login:", response)
            # (In a complete implementation, check response for successful authentication.)
            
            # Save user ID and account number in session and redirect to dashboard
            session['user_id'] = user_id
            session['account_number'] = account_number
            return redirect(url_for('dashboard'))
        else:
            error = "Please provide user ID, account number, and password."
    
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    """
    Render the dashboard for transactions.
    This page displays the user's account number and provides forms for deposit,
    withdrawal, and balance inquiry.
    """
    if 'account_number' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', account_number=session['account_number'], user_id=session['user_id'])

@app.route('/transaction/deposit', methods=['POST'])
def deposit():
    """
    Process the deposit form submission.
    - Collect the deposit amount.
    - Construct a JSON message with type "deposit" including:
         • timestamp
         • user_id
         • account_id
         • amount
    - Send the message via WebSocket to the bank server.
      (The bank server is expected to process the deposit and return a response.)
    - Log the transaction and redirect to the dashboard.
    """
    if 'account_number' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    
    amount = request.form.get('amount')
    account_number = session['account_number']
    user_id = session['user_id']
    
    deposit_data = {
        "type": "deposit",
        "data": {
            "timestamp": get_timestamp(),
            "user_id": user_id,
            "account_id": account_number,
            "amount": amount
        }
    }
    log_transaction(deposit_data)
    response = send_to_bank_server(deposit_data)
    print("Bank server response for deposit:", response)
    return redirect(url_for('dashboard'))

@app.route('/transaction/withdrawal', methods=['POST'])
def withdrawal():
    """
    Process the withdrawal form submission.
    - Collect the withdrawal amount.
    - Construct a JSON message with type "withdrawal" including:
         • timestamp
         • user_id
         • account_id
         • amount
    - Send the message via WebSocket to the bank server.
      (The bank server is expected to process the withdrawal and return a response.)
    - Log the transaction and redirect to the dashboard.
    """
    if 'account_number' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    
    amount = request.form.get('amount')
    account_number = session['account_number']
    user_id = session['user_id']
    
    withdrawal_data = {
        "type": "withdrawal",
        "data": {
            "timestamp": get_timestamp(),
            "user_id": user_id,
            "account_id": account_number,
            "amount": amount
        }
    }
    log_transaction(withdrawal_data)
    response = send_to_bank_server(withdrawal_data)
    print("Bank server response for withdrawal:", response)
    return redirect(url_for('dashboard'))

@app.route('/transaction/balance_inquiry', methods=['POST'])
def balance_inquiry():
    """
    Process the balance inquiry form submission.
    - Construct a JSON message with type "balance" including:
         • timestamp
         • user_id
         • account_id
    - Send the message via WebSocket to the bank server.
      (The bank server is expected to process the inquiry and return the current balance.)
    - Log the transaction and redirect to the dashboard.
    """
    if 'account_number' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    
    account_number = session['account_number']
    user_id = session['user_id']
    
    balance_data = {
        "type": "balance",
        "data": {
            "timestamp": get_timestamp(),
            "user_id": user_id,
            "account_id": account_number
        }
    }
    log_transaction(balance_data)
    response = send_to_bank_server(balance_data)
    print("Bank server response for balance inquiry:", response)
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """
    Clear the user session and redirect to the login page.
    """
    session.clear()
    return redirect(url_for('login'))

# -------------------------
# Security Functions for Encryption and Authentication
# (These functions implement the authenticated key distribution protocol and secure message operations.)
# -------------------------

def generate_nonce():
    """Generate a secure random nonce."""
    return os.urandom(16)

def encrypt_with_key(data, key):
    """
    Encrypt a dictionary (data) using AES-CBC with the provided key.
    The data is first converted to a JSON string.
    Returns a dictionary containing the IV and ciphertext in hexadecimal.
    """
    plaintext = json.dumps(data).encode('utf-8')
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return {"iv": iv.hex(), "ciphertext": ciphertext.hex()}

def decrypt_with_key(encrypted_data, key):
    """
    Decrypt data encrypted by encrypt_with_key using AES-CBC.
    Expects a dictionary with hexadecimal 'iv' and 'ciphertext'.
    Returns the original dictionary.
    """
    iv = bytes.fromhex(encrypted_data["iv"])
    ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return json.loads(plaintext.decode('utf-8'))

def validate_bank_server(response):
    """
    Validate the bank server's response.
    This function should check for expected tokens or fields to confirm the response authenticity.
    For now, this is a stub that always returns True.
    """
    return True

def compute_master_secret(psk, client_nonce, bank_nonce):
    """
    Compute the Master Secret using an HMAC over the concatenation of client_nonce and bank_nonce with the PSK.
    Returns the derived master secret bytes.
    """
    h_obj = hmac.HMAC(psk, hashes.SHA256(), backend=default_backend())
    h_obj.update(client_nonce + bank_nonce)
    return h_obj.finalize()

def hkdf_derive(master_secret, info, length):
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

def aes_encrypt(plaintext, encryption_key):
    """
    Encrypt plaintext bytes using AES-CBC with the provided encryption key.
    Returns the IV and ciphertext.
    """
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

def aes_decrypt(iv, ciphertext, encryption_key):
    """
    Decrypt ciphertext using AES-CBC with the provided encryption key and IV.
    Returns the decrypted plaintext bytes.
    """
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

def compute_hmac(message, mac_key):
    """
    Compute an HMAC (SHA-256) for the given message using the mac_key.
    """
    h_obj = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h_obj.update(message)
    return h_obj.finalize()

def verify_hmac(message, mac_key, received_mac):
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

def secure_message(plaintext, encryption_key, mac_key):
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

def verify_and_decrypt_message(secure_msg, encryption_key, mac_key):
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

# -------------------------
# Main Entry Point
# -------------------------
if __name__ == '__main__':
    app.run(debug=True)
