import json
from ..models.models import BalanceRequest, AccountAction, Account, EncryptedMessage, Client
from ..crud.accounts_crud import get_balance, deposit, withdraw, create_user, authenticate_account
from ..security.helpers import compute_master_secret, generate_nonce, encrypt_with_key, fetch_shared_key
from ..memory import state

#=======================================
# Data validation helper functions
#=======================================

def validate_encrypted_message(message: dict) -> EncryptedMessage | None:
    """Validates whether the incoming message has the right properties

    Args:
        message (dict): The incoming json message with encrypted fields

    Returns:
        EncryptedMessage | None: Returns `EncryptedMessage` if data is valid, `None` otherwise.
    """
    try:
        message = EncryptedMessage(**message)
        return message
    except:
        return None
    

#=======================================
# Handler functions
#=======================================

async def handle_deposit(data):
    """Websocket callback handler for the `deposit` action type"""
    
    deposit_request = AccountAction(**data)
    user_id = deposit_request.user_id
    amount = deposit_request.amount
    
    try:
        new_balance = await deposit(user_id, amount)
        
        if new_balance is None:
            return {"status": "error", "message": f"Could not find user with id {user_id}"}
            
        print(f"User {user_id} requested deposit for {amount}")
        return {
            "status": "success",
            "message": {
                "balance": f"{new_balance}"
            }
        }
    except Exception as e:
        return {
            "status": "failure",
            "message": f"{e}"
        }

    
async def handle_withdrawl(data):
    """Websocket callback handler for the `withdrawl` action type"""
    
    withdrawl_request = AccountAction(**data)
    user_id = withdrawl_request.user_id
    amount = withdrawl_request.amount
        
    try:
        new_balance = await withdraw(user_id, amount)
        
        if new_balance is None:
            return {"status": "error", "message": f"Could not find user with id {user_id}"}
        
        print(f"User {user_id} requested withdrawl for {amount}")
        return {
            "status": "success",
            "message": {
                "balance": f"{new_balance}"
            }
        }
    
    except ValueError:
        return {"status": "error", "message": "Insuffcient funds"}
    except Exception as e:
        return {
            "status": "failure",
            "message": f"{e}"
        }
    
    
async def handle_balance(data):
    """Websocket callback handler for the `balance` action type"""
    
    balance_request = BalanceRequest(**data)
    user_id = balance_request.user_id
    print(f"User {user_id} requested balance")
    
    try:
        balance = await get_balance(user_id)
        if balance is None:
            return {"status": "error", "message": f"Could not find user with id {user_id}"}
        return {
            "status": "success",
            "message": {
                "balance": f"{balance}"
            }
        }
    except Exception as e:
        return {
            "status": "failure",
            "message": f"{e}"
        }
    
    #After, add error handling if BalanceRequest init failed, indicated user sent bad format


async def handle_registration(data: dict) -> Client | None:
    """Handles the login action. Uses the pre-shared master key for enc/decry"""
    try:
        new_user = Account(**data)
    except:
        raise Exception("Incorrect or missing data passed. Please pass a name and password as strings")
        
    try:
        created_user = await create_user(new_user)
        if created_user is not None:
            bank_nonce = generate_nonce()
            client_nonce = data["nonce"]
            psk = fetch_shared_key()
            master_key = compute_master_secret(psk, client_nonce, bank_nonce)
            return Client(master_key=master_key, client_nonce=client_nonce, bank_nonce=bank_nonce)
        
        return None
    except Exception as e:
        raise Exception("An error occured while registering a new user")
        
        
async def handle_login(data: dict) -> Client | None:
    """Handles the login action. Uses the pre-shared master key for enc/decry
    Returns a `Client` object on success, otherwise `None`"""
    
    psk = fetch_shared_key()
    
    try:
        account_id = data["account_id"]
        password = data["password"]
        nonce = data["nonce"]
    except KeyError as ke:
        raise KeyError("Missing required arguments: account_id (int), password (str), nonce (bytes)")
    
    #Authenticate the client
    account = await authenticate_account(account_id, password)
    
    if account is None:
        raise Exception("Incorrect account_id or password")
    
    #Create reply message
    bank_nonce = generate_nonce()
    master_key = compute_master_secret(psk, nonce, bank_nonce)
    client = Client(master_key=master_key, client_nonce=nonce, bank_nonce=bank_nonce)
    return client
    

ACTION_HANDLERS = {
    "deposit": handle_deposit,
    "balance": handle_balance,
    "withdrawl": handle_withdrawl,
    "register": handle_registration,
    "login": handle_login
}