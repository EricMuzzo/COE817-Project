import json
from models import BalanceRequest, AccountAction, Account
from accounts_crud import get_balance, deposit, withdraw, create_user

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
    
    #After add error handling if BalanceRequest init failed, indicated user sent bad format


async def handle_registration(data):
    
    try:
        new_user = Account(**data)
    except:
        return {
            "status": "error",
            "message": "Incorrect or missing data passed. Please pass a name and password as strings"
        }
        
    try:
        created_user = await create_user(new_user)
        if created_user is not None:
            return {
                "status": "success",
                "message": "User created"
            }
        
        return {
            "status": "error",
            "message": "An error occured"
        }
    except Exception as e:
        return {
            "status": "failure",
            "message": "Server error"
        }

ACTION_HANDLERS = {
    "deposit": handle_deposit,
    "balance": handle_balance,
    "withdrawl": handle_withdrawl,
    "register": handle_registration
}