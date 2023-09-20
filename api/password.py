from flask import (
    Blueprint, flash, g, request,  jsonify
)
from werkzeug.exceptions import abort

#from flaskr.api.auth import login_required
from flaskr.database.db import db, IntegrityError
from flaskr.models.Password import Password
from flaskr.utils.auth import flask_praetorian, guard
from flaskr.utils.encryption import generate_nonce, enc_cipher, custom_encrypt, read_key, dec_cipher, custom_decrypt

bp = Blueprint('password', __name__, url_prefix="/password")

@bp.get('/all')
#@login_required
@flask_praetorian.auth_required
def index():

    user_id = guard.extract_jwt_token(guard.read_token_from_header())["UserID"]

    passwords = Password.query.filter(Password.FK_UserID == user_id)
    l = []

    key = None
    try:
        key = read_key()
    except Exception as err:
        print(err)

    for e in passwords:
        ct = e.EncryptedPassword[8:]
        n = e.EncryptedPassword[:8]
        dc = dec_cipher(key,n)
        EncryptedPassword = custom_decrypt(dc, ct)
        l.append({ "title": e.Title, "id": e.PasswordID, "username" : e.Username, "encrypted_password": EncryptedPassword, "user_id": e.FK_UserID})

    return jsonify({"passwords": l}), 200

@bp.post('/')
#@login_required
@flask_praetorian.auth_required
def create():

    if not request.is_json:
        return jsonify({'error': 'Invalid JSON data'}), 400

    if request.method == 'POST':
        data = request.json
        Title = data.get('Title')
        Username = data.get('Username')
        EncryptedPassword = data.get('EncryptedPassword')
        error = None

        n = generate_nonce()
        key = None
        try:
            key = read_key()
        except Exception as err:
            error = err
        
        cipher = enc_cipher(key, n)
        ct = custom_encrypt(cipher, EncryptedPassword)
        message = n + ct
        EncryptedPassword = message
        n, key = None, None

        if not Title:
            error = 'Title is required.'
        elif not Username:
            error = 'Username is required.'
        elif not EncryptedPassword:
            error = 'Password is required.'
    

        if error is not None:
            return jsonify({"message": error}), 400
        else:
            try:
                password = Password(
                    Title = Title,
                    Username = Username,
                    EncryptedPassword = EncryptedPassword,
                    FK_UserID = guard.extract_jwt_token(guard.read_token_from_header())["UserID"]
                )
                db.session.add(password)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                error = f"Password with {Username} on Title {Title} is already registered."
            except AttributeError:
                db.session.rollback()
                error = f"Column Constraint violated"
            else:
                return jsonify({"message": "Password added succesfully"}), 201

    return jsonify({"message": "Failed to add password"}), 400

def get_password(PasswordID, check_author=True):
    password = db.first_or_404(db.select(Password).filter_by(PasswordID=PasswordID))

    if password is None:
        abort(404, f"Password id {PasswordID} doesn't exist.")

    if check_author and password.FK_UserID != guard.extract_jwt_token(guard.read_token_from_header())["UserID"]:
        abort(403)

    return password

@bp.put('/<int:PasswordID>')
#@login_required
@flask_praetorian.auth_required
def update(PasswordID):

    if not request.is_json:
        return jsonify({'error': 'Invalid JSON data'}), 400
    if request.method == 'PUT':
        data = request.json
        Title = data.get('Title')
        Username = data.get('Username')
        EncryptedPassword = data.get('EncryptedPassword')
        error = None

        n = generate_nonce()
        key = None
        try:
            key = read_key()
        except Exception as err:
            error = err
        
        cipher = enc_cipher(key, n)
        ct = custom_encrypt(cipher, EncryptedPassword)
        message = n + ct
        EncryptedPassword = message
        n, key = None, None

        if not Title:
            error = 'Title is required.'
        elif not Username:
            error = 'Username is required.'
        elif not EncryptedPassword:
            error = 'Password is required.'

        if not Title:
            error = 'Title is required.'
        elif not Username:
            error = 'Username is required.'
        elif not EncryptedPassword:
            error = 'Password is required.'

        if error is not None:
            return jsonify({"message": error}), 400
        else:
            try:
                p = get_password(PasswordID)
                p.Title = Title
                p.Username = Username
                p.EncrypedPassword = EncryptedPassword
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                error = f"Password with {Username} on Title {Title} is already registered."
            except AttributeError:
                db.session.rollback()
                error = f"Column Constraint violated"
            else:
                return jsonify({"message": "Password updated"}), 200

    return jsonify({"message": "Bad request"}), 400

@bp.delete('/<int:PasswordID>')
#@login_required
@flask_praetorian.auth_required
def delete(PasswordID):
    p = get_password(PasswordID)
    db.session.delete(p)
    db.session.commit()
    return jsonify({"message": "Password deleted successfully"}), 200