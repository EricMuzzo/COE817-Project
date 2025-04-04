"""In memory data storage"""
import websockets
from ..models.models import Client

variables = {}
authenticated_clients: dict[websockets.ServerConnection, Client] = {}