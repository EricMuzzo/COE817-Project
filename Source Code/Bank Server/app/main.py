import asyncio
import json
import websockets
import base64
from datetime import datetime
from websockets.asyncio.server import serve

from .actions.handlers import ACTION_HANDLERS
from .utils.transaction_logger import log_transaction
from .security.helpers import secure_message, derive_keys_from_master
from .security.helpers import verify_and_decrypt_message, decrypt_with_key, encrypt_with_key
from .memory import state
from .models.models import ServerException


async def handle_client(websocket: websockets.ServerConnection):
    print(f"[CONNECTION {websocket.id}] Client has connected")
    
    #======Login/Register Routine============
    authenticated = False
    
    while not authenticated:
        try:
            print(f"[CONNECTION {websocket.id}] Server is awaiting authentication protocol")
            initial_message = await websocket.recv()
            initial_message = json.loads(initial_message)
            decrypted_cipher = decrypt_with_key(initial_message)
            
            action = decrypted_cipher.get("type")
            nonce = base64.b64decode(decrypted_cipher.get("nonce"))
            data = decrypted_cipher.get("data", {})
            
            print(f"[CONNECTION {websocket.id}] Client requested {action} action")
            
            if action in ["login", "register"]:
                client = await ACTION_HANDLERS[action](data, nonce)
                
                log_transaction(client.account.user_id, action, datetime.now())
                
                # Derive session keys from master secret
                encryption_key, mac_key = derive_keys_from_master(client.master_key)
                client.encryption_key = encryption_key
                client.mac_key = mac_key
                
                authenticated = True
                state.authenticated_clients[websocket] = client
                
                if action == "register":
                    print(f"[CONNECTION {websocket.id}] {client.account.name} has been registered successfully")
                    res_message = f"{client.account.name} has registered"
                else:
                    print(f"[CONNECTION {websocket.id}] {client.account.name} has logged in")
                    res_message = f"{client.account.name} has logged in"
                
                response = {
                    "status": "success",
                    "message": res_message,
                    "bank_nonce": base64.b64encode(client.bank_nonce).decode(),
                    "data": client.account.model_dump()
                }
            else:
                response = {"status": "error", "message": "Message type must be login or register"}
            
            encrypted_response = encrypt_with_key(response)
            await websocket.send(json.dumps(encrypted_response))
        except websockets.exceptions.ConnectionClosed:
            print(f"[CONNECTION {websocket.id}] Client disconnected.")
            return
        except Exception as e:
            print(f"[CONNECTION {websocket.id}] Error occured:\n{str(e)}")
            await websocket.send(json.dumps({"status": "error", "message": str(e)}))
            return
    
    #==========Transaction Message Routine==========
    try:
        print(f"[CONNECTION {websocket.id}] Server is awaiting transactions")
        async for message in websocket:
            try:
                # 1) Parse incoming JSON envelope
                message = json.loads(message)

                # 2) Retrieve the session keys for this client
                client = state.authenticated_clients.get(websocket)
                encryption_key = client.encryption_key
                mac_key = client.mac_key
                if not encryption_key or not mac_key:
                    raise Exception("Dual keys not found. Please authenticate first.")

                # 3) Verify MAC and decrypt to a plaintext JSON string
                plaintext = verify_and_decrypt_message(message, encryption_key, mac_key)

                # 4) Parse that JSON string into a dict
                decrypted_message = json.loads(plaintext)

                # 5) Extract the transaction type
                action = decrypted_message.get("type")
                print(f"[CONNECTION {websocket.id}] Client requested transaction: {action}")

                # 6) Dispatch to the appropriate handler
                if action in ACTION_HANDLERS:
                    account = await ACTION_HANDLERS[action](decrypted_message["data"])
                    print(f"[CONNECTION {websocket.id}] Client {action} transaction was successful")
                    log_transaction(account.user_id, action, datetime.now())
                    
                    response = {
                        "status": "success",
                        "message": f"{action} transaction was successful",
                        "balance": float(account.balance)
                    }
                else:
                    response = {"status": "error", "message": "Unknown action"}

            except ServerException as se:
                print(f"[CONNECTION {websocket.id}] Server failure occured:\n{se.message}")
                response = {"status": "failure", "message": se.message}
            except Exception as e:
                print(f"[CONNECTION {websocket.id}] Error occured:\n{str(e)}")
                response = {"status": "error", "message": str(e)}

            # 7) Encrypt & send the response back
            encrypted_response = secure_message(json.dumps(response), encryption_key, mac_key)
            await websocket.send(json.dumps(encrypted_response))

    except websockets.exceptions.ConnectionClosed:
        print(f"[CONNECTION {websocket.id}] Client disconnected.")
    finally:
        state.authenticated_clients.pop(websocket, None)
        print(f"[CONNECTION {websocket.id}] Client successfully disconnected")
        

async def start_server(host="0.0.0.0", port=8765):
    async with serve(handle_client, host, port) as server:
        print(f"WebSocket server started on ws://{host}:{port}")
        await server.serve_forever()
    
if __name__ == "__main__":
    asyncio.run(start_server())
