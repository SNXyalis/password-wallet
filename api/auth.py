from flask import Blueprint, request, make_response, jsonify, session, g, redirect, url_for
from flaskr.database.db import db, IntegrityError
from flaskr.models.User import User
from flaskr.utils.auth import guard, flask_praetorian
from flaskr.utils.util import blacklist
from werkzeug.security import check_password_hash, generate_password_hash
import functools

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
        '''TO CHECK IF NEEDED'''
        error = None
        #user = db.first_or_404(db.select(User).filter_by(Username=username))

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user.Password, password):
            error = 'Incorrect password.'
        
        if error is None:
            session.clear()
            session['UserID'] = user.UserID
            response = make_response(jsonify({"message" : "Login successful" }), 200)
            response.set_cookie('session_id', str(session['UserID']))

            return response

        #flash(error)
    error=None #DELETE THIS LINE
    response = make_response(jsonify({ "error" : error }), 400)
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


'''@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('UserID')

    if user_id is None:
        g.user = None
    else:
        g.user = db.first_or_404(db.select(User).filter_by(UserID=user_id))

@bp.post('/logout')
def logout():
    print('lol')
    session.clear()
    response = make_response(jsonify({ 'message' : 'Logout successful'}), 200)
    response.set_cookie('session_id', '', expires=0)
    return response


def login_required(f):
    @functools.wraps(f)
    def is_user_auth(*args, **kwargs):
        if 'UserID' not in session:
            return jsonify({"message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return is_user_auth'''
