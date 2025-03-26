import asyncio
import json
import websockets
from datetime import datetime
from websockets.asyncio.server import serve
from handlers import ACTION_HANDLERS
from utils.transaction_logger import log_transaction


async def handle_client(websocket: websockets.ServerConnection):
    print("Client connected")
    try:
        async for message in websocket:
            try:
                msg = json.loads(message)
                action = msg.get("type")
                data = msg.get("data", {})
                
                if action != "register":
                    user_id = data["user_id"]
                    log_transaction(user_id, action, datetime.now())
                
                if action in ACTION_HANDLERS:
                    response = await ACTION_HANDLERS[action](data)
                    
                else:
                    response = {"status": "error", "message": "Unknown action"}
            
            except Exception as e:
                response = {"status": "error", "message": str(e)}
            
            await websocket.send(json.dumps(response))
    except websockets.exceptions.ConnectionClosed:
        print("Client disconnected unexpectedly. Closing connection")
    finally:
        print("Client successfully disconnected")
        
        
async def start_server(host="0.0.0.0", port=8765):
    async with serve(handle_client, host, port) as server:
        print(f"WebSocket server started on ws://{host}:{port}")
        await server.serve_forever()
    
if __name__ == "__main__":
    asyncio.run(start_server())