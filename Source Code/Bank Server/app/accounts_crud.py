from decimal import Decimal
from utils.database import SessionLocal
from models import Account

async def get_balance(user_id: int):
    """Fetch the balance from the database for user `user_id`"""
    db = SessionLocal()
    try:
        account = db.query(Account).filter(Account.user_id == user_id).first()
        if account:
            return account.balance
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
        return account.balance
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
        return account.balance
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