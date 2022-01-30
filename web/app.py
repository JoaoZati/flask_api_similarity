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
import spacy
import en_core_web_sm

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
            text_1 = post_data["text_1"]
            text_2 = post_data["text_2"]
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


def valid_user_and_passoword(username, password):
    try:
        if not users.find({}, {"Username": username})[0]['Username']:
            return False
        hash_password = str(users.find({}, {"Username": username, "Password": 1})[0]["Password"])
        if bcrypt.hashpw(password, hash_password) == hash_password:
            return True
    except Exception as e:
        print(e)
    
    return False


def get_tokens(username):
    try:
        tokens = int(users.find({}, {"Username": username, "Tokens": 1})[0]["Tokens"])
    except Exception as e:
        print(e)
        tokens = 0
    
    return tokens


def set_username_tokens(username, tokens):

    users.update_one(
        {"Username": username},
        {
            "$set": {
                "Tokens": tokens
                }
        } 
    )


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

        if status_code != 200:
            return jsonify(
                {
                    'Status Code': status_code,
                    'Message': message,
                }
            )
        
        if not valid_user_and_passoword(username, password):
            return jsonify(
                {
                    'Status Code': 302,
                    'Message': "Invalid Username or Password",
                }
            )
        
        tokens = get_tokens(username)

        if tokens < 1:
            return jsonify(
                {
                    'Status Code': 303,
                    'Message': "You dont have enouth tokens",
                }
            )

        try:
            nlp = en_core_web_sm.load()

            text_1 = nlp(text_1)
            text_2 = nlp(text_2)

            ratio = text_1.similarity(text_2) # Ratio 0 to 1, more close to 1 more similar;

            set_username_tokens(username, tokens - 1)
        except Exception as e:
            print(e)
            return jsonify(
                {
                    'Status Code': 305,
                    'Message': "Sorry one internal error ocurred",
                }
            )

        return jsonify(
            {
                'Status Code': status_code,
                'Message': message,
                'Tokens': tokens - 1,
                "Similarity Ratio": ratio
            }
        )


api.add_resource(Register, "/register")
api.add_resource(Detect, "/detect")

if __name__ == '__main__':
    initialize_debugger()

    app.run(host='0.0.0.0', port=5000, debug=True)
