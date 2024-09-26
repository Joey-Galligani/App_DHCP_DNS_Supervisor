from pymongo import MongoClient
import os

USERNAME = os.getenv('DB_USERNAME')
PASSWORD = os.getenv('DB_PASSWORD')

CONNECTION_STRING = "mongodb://"+USERNAME+":"+PASSWORD+"@mongo"

db = MongoClient(CONNECTION_STRING)
