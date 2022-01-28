"""
Registration of a User
Each user get 10 tokens 
Sotore a sentece for 1 token
Retrive his stored sentence on our database for 1 token
"""

from flask import Flask
from flask_restful import Api

from pymongo import MongoClient
from debugger import initialize_debugger


app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")  # same name in docker compose
db = client.SentenceDatabase
users = db["Users"]


@app.route('/')
def hello_word():
    return 'Hello Word'


if __name__ == '__main__':
    initialize_debugger()

    app.run(host='0.0.0.0', port=5000, debug=True)
