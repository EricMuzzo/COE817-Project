from decimal import Decimal
from ..utils.database import SessionLocal
from ..models.models import Account

async def get_account(user_id: int):
    """Fetch the account from the database for user `user_id`"""
    db = SessionLocal()
    try:
        account = db.query(Account).filter(Account.user_id == user_id).first()
        if account:
            return account
        return None
    finally:
        db.close()
        
        
async def deposit(user_id: int, amount: float):
    """Increment the balance field in the database by `amount` for user `user_id`"""
    db = SessionLocal()
    try:
        account = db.query(Account).filter(Account.user_id == user_id).first()
        if account is None:
            return None
        
        new_balance = account.balance + Decimal(amount)
        account.balance = new_balance
        db.commit()
        db.refresh(account)
        return account
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
        
        
async def withdraw(user_id: int, amount: float):
    """Decrement the balance field in the database by `amount` for user `user_id`"""
    db = SessionLocal()
    try:
        account = db.query(Account).filter(Account.user_id == user_id).first()
        if account is None:
            return None
        
        if account.balance < amount:
            raise ValueError()
        new_balance = account.balance - Decimal(amount)
        account.balance = new_balance
        db.commit()
        db.refresh(account)
        return account
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
        
        
async def create_user(account: Account)  -> Account:
    db = SessionLocal()
    try:
        db.add(account)
        db.commit()
        db.refresh(account)
        return account
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
        
        
async def authenticate_account(username: int, password: str):
    """Performs the login for a provided account and password"""
    db = SessionLocal()
    
    try:
        account = db.query(Account).filter(Account.username == username).first()
        if account is None:
            raise ValueError(f"Could not find username: {username}")
        if account.password != password:
            return None
        return account
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()