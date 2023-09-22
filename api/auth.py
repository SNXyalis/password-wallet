from flask import Blueprint, request, jsonify, current_app
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
        err = 'Invalid request data format'
        current_app.logger.warning("Client error, " +err)
        return jsonify(error= err), 400

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
                guard.send_registration_email(email, user=user)
            except IntegrityError:
                db.session.rollback()
                error = f"User {username} is already registered."
            except AttributeError:
                db.session.rollback()
                error = f"Column Constraint violated"
            except Exception as err:
                db.session.rollback()
                error="Couldn't send email, "+ err
            else:
                return jsonify(
                        message= "User registered successfully, Email sent" 
                    ), 201

        current_app.logger.warning(error)
        response = jsonify({ "error" : error }), 400

    return response

@bp.get("/finalize")
def finalize():
    try: 
        registration_token = guard.read_token_from_header()
    except Exception as err:
        return jsonify(error=err)
    
    user = None

    try:
        user = guard.get_user_from_registration_token(registration_token)
    except Exception as e:
        current_app.logger.warning(f"Failed to authenticate user during registration {e}")
        return jsonify(
            error="Failed to authenticate user"
        )
    
    try:
        usr = db.first_or_404(db.select(User).filter_by(Username = user.Username))
        usr.is_active=True
        db.session.commit()
        current_app.logger.info(f"User {usr.Username} is now registered.")
        return jsonify({"access_token": guard.encode_jwt_token(user)}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.warning(f"Error during user registration {e}")
        return jsonify(
            error="Failed to register user"
        )

@bp.post('/login')
def login():

    response = None

    if not request.is_json:
        err = 'Invalid request data format'
        current_app.logger.warning("Client error, " +err)
        return jsonify(error= err), 400
    
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        access_lifespan = data.get("access_lifespan")
        refresh_lifespan = data.get("refresh_lifespan")
        
        user = None

        try:
            user = guard.authenticate(username, password)
        except Exception as e:
            current_app.logger.warning(f"Failed to authenticate user{e}")
            return jsonify(
                error="Failed to authenticate user"
            )
        
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
    
    response = jsonify({ "error" : "Failed to login" }), 400
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
        err = 'Invalid request data format'
        current_app.logger.warning("Client error, " +err)
        return jsonify(error= err), 400
    
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
        err = 'Invalid request data format'
        current_app.logger.warning("Client error, " +err)
        return jsonify(error= err), 400
    
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
        current_app.logger.warning("Failed to generate AES key")
        return jsonify(
            message=err
        )
