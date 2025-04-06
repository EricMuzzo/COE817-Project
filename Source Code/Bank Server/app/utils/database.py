import urllib.parse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import urllib
from .config import DB_CONNECTION_STRING


params = urllib.parse.quote_plus(DB_CONNECTION_STRING)
engine = create_engine("mssql+pyodbc:///?odbc_connect={}".format(params))
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Dependency generator for database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()