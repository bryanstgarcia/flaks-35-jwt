"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os, bcrypt
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
#from models import Person


app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
jwt = JWTManager(app)
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/hola')
def hola():
    return '<h1>Hola</h1>', 200

@app.route('/user', methods=['POST'])
def handle_hello():
    body = request.json
    salt_bytes = bcrypt.gensalt()
    salt = salt_bytes.decode()
    hashed_password = generate_password_hash(f'{body["password"]}{salt}')
    new_user = User(
                        email=body["email"], 
                        hashed_password=hashed_password,
                        salt=salt,
                        is_active=True
                    )
    db.session.add(new_user)
    db.session.commit()
    print("User: ", new_user)
    print("User serialized: ", new_user.serialize())
    return jsonify(body), 200

@app.route('/login', methods=['POST'])
def login():
    body = request.json
    user = User.query.filter_by(email=body["email"]).one_or_none()
    if user is None:
        return jsonify({
            "message": "Invalid credentials, email"
        }), 400 

    password_is_valid = check_password_hash(user.hashed_password, f'{body["password"]}{user.salt}')
    if not password_is_valid:
        return jsonify({
            "message": "Invalid credentials, password"
        }), 400 
    print("Password is valid: ", password_is_valid)
    access_token = create_access_token(identity=user.serialize())
    print(access_token)
    return jsonify({
        "token": access_token
    }), 201

@app.route("/user", methods=['GET'])
@jwt_required()
def get_user_info():
    user_email = get_jwt_identity()
    return jsonify({
        "message": "Hola ruta protegida",
        "user_id": user_email
    })
# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
