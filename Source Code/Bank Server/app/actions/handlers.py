import json
from sqlalchemy.exc import IntegrityError

from ..models.models import BalanceRequest, AccountAction, Account, AccountModel, EncryptedMessage, Client, ServerException
from ..crud.accounts_crud import get_account, deposit, withdraw, create_user, authenticate_account
from ..security.helpers import compute_master_secret, generate_nonce, fetch_shared_key

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

async def handle_deposit(data: dict) -> Account:
    """Websocket callback handler for the `deposit` action type"""
    
    deposit_request = AccountAction(**data)
    user_id = deposit_request.user_id
    amount = deposit_request.amount
    
    try:
        print(f"User {user_id} requested deposit for {amount}")
        account = await deposit(user_id, amount)
        
        if account is None:
            raise Exception(f"Could not find user with id {user_id}")
            
        return account
    except Exception as e:
        raise ServerException(message=f"{e}")

    
async def handle_withdrawal(data: dict) -> Account:
    """Websocket callback handler for the `withdrawl` action type"""
    
    withdrawl_request = AccountAction(**data)
    user_id = withdrawl_request.user_id
    amount = withdrawl_request.amount
        
    try:
        print(f"User {user_id} requested withdrawal for {amount}")
        account = await withdraw(user_id, amount)
        
        if account is None:
            raise Exception(f"Could not find user with id {user_id}")
        
        return account
    
    except ValueError:
        raise Exception("Insuffcient funds")
    except Exception as e:
        raise ServerException(message=f"{e}")
    
    
async def handle_balance(data: dict) -> Account:
    """Websocket callback handler for the `balance` action type"""
    
    balance_request = BalanceRequest(**data)
    user_id = balance_request.user_id
    
    try:
        print(f"User {user_id} requested balance")
        account = await get_account(user_id)
        if account is None:
            raise Exception(f"Could not find user with id {user_id}")
        return account
    except Exception as e:
        ServerException(message=f"{e}")
    
    #After, add error handling if BalanceRequest init failed, indicated user sent bad format


async def handle_registration(data: dict, nonce: bytes) -> Client | None:
    """Handles the login action. Uses the pre-shared master key for enc/decry"""
    try:
        new_user = Account(
            username = data["username"],
            name = data["name"],
            password = data["password"]
        )
    except Exception as e:
        raise Exception(f"Incorrect or missing data passed. {str(e)}")
        
    try:
        created_user = await create_user(new_user)
        if created_user is not None:
            bank_nonce = generate_nonce()
            psk = fetch_shared_key()
            master_key = compute_master_secret(psk, nonce, bank_nonce)
            return Client(account=AccountModel(**created_user.response_format()), master_key=master_key, client_nonce=nonce, bank_nonce=bank_nonce)
        
        raise Exception("An error occured while registering a new user")
    except IntegrityError:
        raise Exception("Database integrity error. User could not be created due to a conflicting record")
    except Exception as e:
        print(str(e))
        raise Exception("An error occured while registering a new user")
        
        
async def handle_login(data: dict, nonce: bytes) -> Client:
    """Handles the login action. Uses the pre-shared master key for enc/decry
    Returns a `Client` object on success, otherwise `None`"""
    
    try:
        username = data["username"]
        password = data["password"]
    except KeyError as ke:
        raise KeyError("Missing required arguments: username (str), password (str)")
    
    #Authenticate the client
    account = await authenticate_account(username, password)
    
    if account is None:
        raise Exception("Incorrect username or password")
    
    #Create reply message
    bank_nonce = generate_nonce()
    psk = fetch_shared_key()
    master_key = compute_master_secret(psk, nonce, bank_nonce)
    client = Client(account=AccountModel(**account.response_format()), master_key=master_key, client_nonce=nonce, bank_nonce=bank_nonce)
    return client
    

ACTION_HANDLERS = {
    "deposit": handle_deposit,
    "balance": handle_balance,
    "withdrawal": handle_withdrawal,
    "register": handle_registration,
    "login": handle_login
}