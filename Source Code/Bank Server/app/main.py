import asyncio
import json
import websockets
from datetime import datetime
from websockets.asyncio.server import serve
from .actions.handlers import ACTION_HANDLERS
from .utils.transaction_logger import log_transaction
from .security.helpers import decrypt_with_key
from .memory import state


async def handle_client(websocket: websockets.ServerConnection):
    print("Client connected")
    
    #======Login/Register Routine============
    authenticated = False
    
    while not authenticated:
        try:
            initial_message = websocket.recv()
            initial_message = json.loads(initial_message)
            decrypted_cipher = decrypt_with_key(initial_message)
            
            action = decrypted_cipher.get("type")
            data = decrypted_cipher.get("data", {})
            
            if action in ["login", "register"]:
                client = await ACTION_HANDLERS[action](data)

                #Here need to check the output of response
                if client is not None:
                    authenticated = True
                    state.authenticated_clients[websocket] = client
                
            else:
                websocket.send(json.dumps({"status": "error", "message": "Message type must be login or register"}))
        except Exception as e:
            websocket.send(json.dumps({"status": "error", "message": str(e)}))
            
            
    #==========Transaction Message Routine==========
    try:
        async for message in websocket:
            try:
                message = json.loads(message)
                
                # Retrieve the master key for this client
                master_key = state.authenticated_clients.get(websocket).master_key
                if not master_key:
                    raise Exception("Master key not found. Please authenticate first.")
                
                decrypted_message = decrypt_with_key(message, master_key)
                
                if action in ACTION_HANDLERS:
                    response = await ACTION_HANDLERS[action](decrypted_message)
                    
                    #Need to finish processing response here
                else:
                    response = {"status": "error", "message": "Unknown action"}
            
            except Exception as e:
                response = {"status": "error", "message": str(e)}
            
            await websocket.send(json.dumps(response))
    except websockets.exceptions.ConnectionClosed:
        print("Client disconnected unexpectedly. Closing connection")
    finally:
        state.authenticated_clients.pop(websocket, None)
        print("Client successfully disconnected")
        
        
async def start_server(host="0.0.0.0", port=8765):
    async with serve(handle_client, host, port) as server:
        print(f"WebSocket server started on ws://{host}:{port}")
        await server.serve_forever()
    
if __name__ == "__main__":
    asyncio.run(start_server())