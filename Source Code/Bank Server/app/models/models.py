from pydantic import BaseModel
from datetime import datetime

class BalanceRequest(BaseModel):
    timestamp: datetime
    user_id: int
    account_id: int
    
class AccountAction(BalanceRequest):
    """A class representing the data field in a message. Used for
    both deposits and withdrawls"""
    amount: float


class EncryptedMessage(BaseModel):
    type: str
    iv: str
    ciphertext: str
    

from sqlalchemy import Column, Integer, String, Numeric, text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Account(Base):
    __tablename__ = "accounts"
    
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    account_id = Column(Integer, unique=True, nullable=False, server_default=text("next value for accountSeq"))
    balance = Column(Numeric(precision=10, scale=2), default=0.00)

    def __repr__(self):
        return f"<Account(user_id={self.user_id}, name='{self.name}', account_id={self.account_id}, balance={self.balance})>"
    
class Client(BaseModel):
    master_key: bytes
    client_nonce: bytes
    bank_nonce: bytes