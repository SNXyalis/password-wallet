from flask import Blueprint, request, make_response, jsonify, session, g
from flaskr.db import get_db
from werkzeug.security import check_password_hash, generate_password_hash

bp = Blueprint("auth", __name__, url_prefix="/auth")

@bp.post('/register')
def register():
    response = make_response()

    if not request.is_json:
        return jsonify({'error': 'Invalid JSON data'}), 400

    if request.method == 'POST':
        data = request.json
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif not email:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO User (Username, Email, Password) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                response.data = jsonify({ "message" : "User registered successfully" }), 201
                return response 

        response.data = jsonify({ "error" : error }), 400

    return response

@bp.post('login')
def login():

    response = make_response()

    if not request.is_json:
        response.data = jsonify({'error': 'Invalid JSON data'}), 400
        return response
    
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')

        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM User WHERE Username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['Password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['UserID'] = user['UserID']
            response.data = jsonify({"message" : "Login successful" })
            response.set_cookie('session_id', str(session['UserID'], httponly=True))

            return response

        #flash(error)
    response.data = jsonify({ "error" : error }), 400
    return response

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('UserID')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM User WHERE UserID = ?', (user_id,)
        ).fetchone()

@bp.post('/logout')
def logout():
    session.clear()
    response = make_response()
    response.set_cookie('session_id', '', expires=0, httponly=True)
    response.data = jsonify({ 'message' : 'Logout successful'})
    return response