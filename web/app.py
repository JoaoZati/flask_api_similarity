"""
Registration of a User
Each user get 10 tokens 
Sotore a sentece for 1 token
Retrive his stored sentence on our database for 1 token
"""

from flask import Flask, jsonify, request
from flask_restful import Api, Resource

from pymongo import MongoClient
from debugger import initialize_debugger

import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")  # same name in docker compose
db = client.SentenceDatabase
users = db["Users"]


@app.route('/')
def hello_word():
    return 'Hello Word'


def get_data(data=False):
    status_code = 200
    message = "Ok"

    try:
        post_data = request.get_json()

        username = post_data["username"]
        password = post_data["password"]

        if data:
            text_1 = post_data["Text_1"]
            text_2 = post_data["Text_2"]
    except Exception as e:
        status_code = 305
        message = str(e)
        username, password = [0] * 2
        text_1, text_2 = [''] * 2

    list_return = [status_code, message, username, password]
    if data:
        list_return.extend([text_1, text_2])
            
    return list_return


def user_already_exist(username):
    try:
        if users.find({}, {"Username": username})[0]['Username'] == username:
            return True
    except Exception as e:
        print(e)
    
    return False

class Register(Resource):
    def post(self):
        status_code, message, username, password = get_data()

        if status_code != 200:
            return jsonify(
                {
                    'Status Code': status_code,
                    'Message': message,
                }
            )
        
        if user_already_exist(username):
            return jsonify(
                {
                    'Status Code': 301,
                    'Message': "User already exists",
                }
            )

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        users.insert_one(
            {
                "Username": username,
                "Password": hashed_password,
                "Tokens": 5
            }
        )

        return jsonify(
            {
                'Status Code': status_code,
                'Message': message,
            }
        )


class Detect(Resource):
    def post(self):
        status_code, message, username, password, text_1, text_2 = get_data(data=True) 

        return jsonify(
            {
                'Status Code': status_code,
                'Message': message,
            }
        )


api.add_resource(Register, "/register")
api.add_resource(Detect, "/detect")

if __name__ == '__main__':
    initialize_debugger()

    app.run(host='0.0.0.0', port=5000, debug=True)
