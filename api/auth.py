from flask import Blueprint, request, make_response, jsonify, session, g, redirect, url_for
from flaskr.database.db import db, IntegrityError, AttributeError
from flaskr.models.User import User
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
                '''db.execute(
                    "INSERT INTO User (Username, Email, Password) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password)),
                )
                db.commit()'''
                user = User(
                    Username = username,
                    Email = email,
                    Password = generate_password_hash(password)
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
                response = make_response(jsonify({ "message" : "User registered successfully" }), 201)
                return response 

        response = make_response(jsonify({ "error" : error }), 400)

    return response

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

        error = None
        user = db.first_or_404(db.select(User).filter_by(Username=username))
        '''user = db.execute(
            'SELECT * FROM User WHERE Username = ?', (username,)
        ).fetchone()'''

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
    response = make_response(jsonify({ "error" : error }), 400)
    return response

@bp.before_app_request
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
    return is_user_auth
