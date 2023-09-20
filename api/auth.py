from flask import Blueprint, request, make_response, jsonify
from flaskr.database.db import db, IntegrityError
from flaskr.models.User import User
from flaskr.utils.auth import guard, flask_praetorian
from flaskr.utils.util import blacklist
from flaskr.utils.encryption import generate_key, store_key

bp = Blueprint("auth", __name__, url_prefix="/auth")

@bp.post('/register')
def register():
    response = None

    if not request.is_json:
        return jsonify({'error': 'Invalid JSON data'}), 400

    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif not email:
            error = 'Email is required.'

        if error is None:
            try:
                user = User(
                    Username = username,
                    Email = email,
                    Password = guard.hash_password(password),
                    roles="User"
                )
                db.session.add(user)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                error = f"User {username} is already registered."
            except AttributeError:
                db.session.rollback()
                error = f"Column Constraint violated"
            else:
                response = make_response(jsonify({ "message" : "User registered successfully, Email sent" }), 201)
                try:
                    guard.send_registration_email(email, user=user)
                except Exception as err:
                    return jsonify(error="Couldn't send email"), 400
                    raise
                
                return response 

        response = make_response(jsonify({ "error" : error }), 400)

    return response

@bp.get("/finalize")
def finalize():
    try: 
        registration_token = guard.read_token_from_header()
    except Exception as err:
        return jsonify(error=err)
        raise
    user = guard.get_user_from_registration_token(registration_token)
    usr = db.first_or_404(db.select(User).filter_by(Username = user.Username))
    usr.is_active=True
    db.session.commit()
    return jsonify({"access_token": guard.encode_jwt_token(user)}), 200
    

@bp.post('/login')
def login():

    response = None

    if not request.is_json:
        response = make_response(jsonify({'error': 'Invalid JSON data'}), 400)
        return response
    
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        access_lifespan = data.get("access_lifespan")
        refresh_lifespan = data.get("refresh_lifespan")
        user = guard.authenticate(username, password)
        
        return jsonify(
            access_token=guard.encode_jwt_token(
                user,
                override_access_lifespan = access_lifespan,
                override_refresh_lifespan = refresh_lifespan,
                UserID = user.UserID,
                Username = user.Username,
                Email = user.Email,
                Password = user.Password,
            )
        ), 200
    response = make_response(jsonify({ "error" : "Failed to login" }), 400)
    return response

@bp.post("/refresh")
def refresh():
    old_token = guard.read_token_from_header()
    new_token = guard.refresh_jwt_token(old_token)
    return jsonify(access_token=new_token)

@bp.post("/disable-user")
@flask_praetorian.auth_required
def disable_user():
    if not request.is_json:
        return jsonify(error="Invalid JSON data"), 400
    
    if request.method == "POST":
        usrname=request.json.get("Username")
        user = db.first_or_404(db.select(User).filter_by(Username = usrname))
        user.is_active = False
        db.session.commit()
        return jsonify(message="Disabled User: "+usrname)

@flask_praetorian.auth_accepted
@bp.post("/blacklist-token")
def blacklist_token():
    if not request.is_json:
        return jsonify(error="Invalid JSON data"), 400
    
    if request.method == "POST":
        token=request.json.get("token")
        data = guard.extract_jwt_token(token)
        blacklist.add(data["jti"])
        return jsonify(message="Token blacklisted: "+ token)
    
@flask_praetorian.auth_accepted
@bp.post("/generate-AES")
def generate_AES():
    try:
        key = generate_key()
        store_key(key)
        return jsonify(
            message="Key Generation was successful"
        )
    except Exception as err:
        return jsonify(
            message=err
        )
