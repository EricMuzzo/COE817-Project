from pydantic import BaseModel, ConfigDict
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
    username = Column(String(50), unique=True)
    name = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    account_id = Column(Integer, unique=True, nullable=False, server_default=text("next value for accountSeq"))
    balance = Column(Numeric(precision=10, scale=2), default=0.00)

    def __repr__(self):
        return f"<Account(user_id={self.user_id}, name='{self.name}', account_id={self.account_id}, balance={self.balance})>"
    
    def response_format(self) -> dict:
        """Returns a dictionary representation of the Account excluding the password"""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "name": self.name,
            "account_id": self.account_id,
            "balance": self.balance
        }
        
class AccountModel(BaseModel):
    user_id: int
    username: str
    name: str
    account_id: int
    balance: float

    model_config = ConfigDict(from_attributes=True)
    
class Client(BaseModel):
    account: AccountModel
    master_key: bytes
    client_nonce: bytes
    bank_nonce: bytes
    encryption_key: bytes = None
    mac_key: bytes = None
    
    model_config = ConfigDict(from_attributes=True)
    
class ServerException(Exception):
    """Raised when a server error occurs"""
    def __init__(self, message="Server error occured"):
        self.message = message
        super().__init__(self.message)