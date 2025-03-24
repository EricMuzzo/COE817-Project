import os

#Connection string to connect to Azure SQL db
DB_CONNECTION_STRING = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=coe817-banking-database-server.database.windows.net,1433;"
    "DATABASE=bank;"
    "UID=bankadmin;"
    "PWD=COE817bank;"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=30;"
)

#Websocket server settings
WEBSOCKET_HOST = "0.0.0.0"
WEBSOCKET_PORT = 8765