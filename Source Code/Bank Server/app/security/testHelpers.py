import helpers
import json
from datetime import datetime

def demo1():
    
    client_nonce = helpers.generate_nonce()
    bank_nonce = helpers.generate_nonce()
    
    #======Client Side================
    key = helpers.fetch_shared_key()

    master_key = helpers.compute_master_secret(key, client_nonce, bank_nonce)

    encryption_key, mac_key = helpers.derive_keys_from_master(master_key)

    print("=========Client=================")
    request_data = {
        "type": "register",
        "data": {
            "timestamp": datetime.now().isoformat(),
            "account_id": 1234
        }
    }
    print("Raw request:", request_data)

    envelope = helpers.secure_message(json.dumps(request_data), encryption_key, mac_key)
    print("envelope:", envelope)


    #===========Server Side==================
    print("\n=========Server=================")
    key = helpers.fetch_shared_key()

    master_key = helpers.compute_master_secret(key, client_nonce, bank_nonce)
    encryption_key, mac_key = helpers.derive_keys_from_master(master_key)

    print("Received message:", envelope)

    message = helpers.verify_and_decrypt_message(envelope, encryption_key, mac_key)
    print("decrypted message:", message)

def register():
    #==========Registration Request=========
    client_nonce = helpers.generate_nonce()
    request_data = {
        "type": "register",
        "nonce": client_nonce.hex(),
        "data": {
            "timestamp": datetime.now().isoformat(),
            "username": "eric",
            "name": "Eric Muzzo",
            "password": "eric"
        }
    }
    encrypted_request = helpers.encrypt_with_key(request_data)
    print("\n-------Register--------\n", json.dumps(encrypted_request))
    
def register_response():
    response = {
        "iv": "20835b04369817286d8b603b7ff081a3",
        "ciphertext": "ece3241ac49cefbce9ad5d447cda7a8866410d6382b274a99f451322b9f907f33cf10d9808d5e6b927aba34ad1ff2ae497df5b56a82969d8f88ee93227c91ec3593e3006b2513128545bfae1357a17acb6733847d3d6025edc448dac10ffc66cff6f194aeca9a1ca19d5dcee1d995b118d387abb3b3ea7dffcaa03369caadff115cae2c6ddabd5835362b68dd6252a143a00214586ae85ac438945c0e8db4424b4974fea78624bf2a4bf593431bdf61e237973ec74ea8824868408b1b48d422e7720d4eed31e1f2400b4da0e4f4dcc66a47eaef5852453fadd3e5d9b42ae9bfd"
    }
    decrypted = helpers.decrypt_with_key(response)
    print(decrypted)
    
def login():
    client_nonce = helpers.generate_nonce()
    request_data = {
        "type": "login",
        "nonce": client_nonce.hex(),
        "data": {
            "timestamp": datetime.now().isoformat(),
            "username": "eric",
            "password": "eric"
        }
    }
    encrypted_request = helpers.encrypt_with_key(request_data)
    print("\n-------Login--------\n", json.dumps(encrypted_request))

register_response()