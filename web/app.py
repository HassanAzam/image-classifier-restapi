from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_restful import Api, Resource
import bcrypt
import requests
import json
import subprocess

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.ClassificationDB
users = db["Users"]

def UserExist(username):
    if users.find({"username": username}).count() == 0:
        return False
    else:
        return True

class Register(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]

        # todo: check incoming post variables

        if UserExist(username):
            resp = {
                "status": 301,
                "message": "Invalid username"
            }
            return jsonify(resp)
        
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "username": username,
            "password": hashed_pw,
            "Tokens": 6
        })

        resp = {
            "status": 200,
            "message": "Successfully signed up for the API"
        }

        return jsonify(resp)



def countTokens(username):
    return users.find({"username": username})[0]["Tokens"]

def verifyPw(username, pw):
     hashed_pw = users.find(
         {"username": username}
     )[0]["password"]

     if bcrypt.hashpw(pw.encode('utf8'), hashed_pw.encode('utf8')) == hashed_pw:
         return True
     else:
         return False

def generateResponse(status, message):
    resp = {
        "status": status,
        "message": message
    }
    
    return resp

def verifyCredentials(username, password):
    if not UserExist(username):
        return generateResponse(301, "Invalid username"), True

    correct_pw = verifyPw(username, password)
    if not correct_pw:
        return generateResponse(302, "Invalid password"), True
    
    return None, False

class Classify(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]
        url = posted_data["url"]
        
        # todo: check incoming post variables

        resp, error = verifyCredentials(username, password)
        if error:
            return jsonify(resp)
        
        tokens = countTokens(username)
        if tokens <= 0:
            return jsonify(generateResponse(303, "Not enough tokens"))
        
        r = requests.get(url)
        resp = {}
        with open("temp.jpg", "wb") as f:
            f.write(r.content)
            proc = subprocess.Popen('python classify_image.py --model_dir=. --image_file=./temp.jpg')
            proc.communicate()[0]
            proc.wait()
            with open("text.txt") as g:
                resp = json.load(g)


        users.update({"username":username},
        {
            "$set": {"Tokens": tokens - 1}
        })

        return jsonify(resp)

class Refill(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        refill = posted_data["refill"]
        admin_pw = posted_data["admin_pw"]

        if not UserExist(username):
            resp = {
                "status": 301,
                "message": "sorry, invalid username"
            }

            return jsonify(resp)
        
        if not admin_pw == "password":
            resp = {
                "status": 304,
                "message": "Invalid password"
            }

            return jsonify(resp)
        
        current_tokens = countTokens(username)

        users.update(
            { "username": username},
            {
                "$set": { "Tokens": refill+current_tokens}
            }
        )

        resp = {
            "status": 200,
            "message": "Refilled successfully"
        }

        return jsonify(resp)

api.add_resource(Register, "/register")
api.add_resource(Classify, "/detect")
api.add_resource(Refill, "/refill")

@app.route('/')
def hello():
    return "HelloWorld"

if __name__ == "__main__":
    app.run(host="0.0.0.0")