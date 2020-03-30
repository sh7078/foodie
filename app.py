from flask import Flask, jsonify, request, json, render_template
from flask_pymongo import PyMongo 
from bson.objectid import ObjectId 
from datetime import datetime 
from flask_bcrypt import Bcrypt 
from flask_cors import CORS
from flask_jwt_extended import JWTManager 
from flask_jwt_extended import create_access_token
import pymongo
import bcrypt

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'new'
app.config['MONGO_URI'] = 'mongodb+srv://shgpta:1234@cluster0-zjby1.mongodb.net/test?retryWrites=true&w=majority'
app.config['JWT_SECRET_KEY'] = 'secret'
#myclient = pymongo.MongoClient("mongodb+srv://shgpta:1234@cluster0-zjby1.mongodb.net/test?retryWrites=true&w=majority")
#mydb = myclient["cheif"]
#users = mydb["ids"]


mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

CORS(app)

@app.route('/')
def index():
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'name' : request.form['name']})

        if existing_user is None:
            #hashpass = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
            hashpass = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
            users.insert({'name' : request.form['name'], 'password' : hashpass})
            #session['name'] = request.form['name']
            return render_template('index.html')
        
        return 'That username already exists!'

    return render_template('register.html')

@app.route('/contact', methods=["GET","POST"])
def contact():
    if request.method == "POST":
        users = mongo.db.users 
        name = request.get_json()['name']
        resturant_name = request.get_json()['resturant_name']
        email = request.get_json()['email']
        address = request.get_json()['message']
        #password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
        created = datetime.utcnow()

        user_id = users.insert({
            'name': name,
            'resturant_name': resturant_name,
            'email': email,
            'address': address,
            'created': created 
        })

        new_user = users.find_one({'_id': user_id})

        result = {'email': new_user['email'] + ' registered'}
        return jsonify({'result':result})

    return render_template("contact.html")

@app.route('/', methods=['POST'])
def login():
    users = mongo.db.users 
    user = request.get_json()['User Name']
    password = request.get_json()['time']
    result = ""

    response = users.find_one({'User Name': user})

    if response:
        if bcrypt.check_password_hash(response['time'], password):
            access_token = create_access_token(identity = {
                'name': response['name'],
                'your_name': response['your_name'],
                'email': response['email']
            })
            result = jsonify({'token':access_token})
        else:
            result = jsonify({"error":"Invalid username and password"})
    else:
        result = jsonify({"result":"No results found"})
    return result 

if __name__ == '__main__':
    app.run(debug=True)