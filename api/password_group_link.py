from flask import (
    Blueprint, request, g, jsonify, current_app
)
from flaskr.database.db import db, IntegrityError
from flaskr.models.PasswordGroupLink import PasswordGroupLink
from flaskr.utils.auth import flask_praetorian, guard
from werkzeug.exceptions import abort

bp = Blueprint('password_group_link', __name__, url_prefix='/password-group-link')

@bp.get('/')
@flask_praetorian.auth_required
def index():
    links = PasswordGroupLink.query.filter(PasswordGroupLink.FK_UserID == guard.extract_jwt_token(guard.read_token_from_header())["UserID"])
    l=[]
    for i in links:
        l.append({"group" : i.password_group_id, "password" : i.PasswordID})
    return jsonify(
        links = l
    ), 200

#Adds passwords in a group
#params: single group id, array of password ids
@bp.post('/')
@flask_praetorian.auth_required
def add_link():

    error = None

    if not request.is_json:
        err = 'Invalid request data format'
        current_app.logger.warning("Client error, " +err)
        return jsonify(error= err), 400
    
    if request.method == 'POST':
        data = request.json
        password_id = data.get("password_id")
        group_id = data.get("group_id")

        if password_id is None:
            error = "No passwords provided"

        if group_id is None:
            error = "No group provided"

        if error is not None:
            current_app.logger.warning("Client error, " +error)
            return jsonify(
                message = error
            ), 400

        group_link = []

        
        try:
            db.session.begin()
            for e in password_id:
                group_link.append(
                    PasswordGroupLink(
                        PasswordID = e,
                        password_group_id = group_id,
                        FK_UserID = guard.extract_jwt_token(guard.read_token_from_header())["UserID"]
                    )
                )
            
            db.session.add_all(group_link)

            db.session.commit()

        except IntegrityError:
                db.session.rollback()
                error = f"Link between password {password_id} and group {group_id} already exists."
        except AttributeError:
                db.session.rollback()
                error = f"Column Constraint violated"
        except Exception as err:
             return jsonify(
                  error = err
             ),400
        else:
            db.session.close()
            return jsonify({"message": "Link added succesfully"}), 201
    return jsonify(
         message= error
    ),400
        
def get_link(PasswordID, password_group_id, check_author=True):
    link = db.first_or_404(db.select(PasswordGroupLink).filter_by(password_group_id=password_group_id, PasswordID=PasswordID))

    if link is None:
        abort(404, f"Group id {password_group_id} doesn't exist.")

    if check_author and link.FK_UserID != guard.extract_jwt_token(guard.read_token_from_header())["UserID"]:
        abort(403)

    return link

@bp.delete('/')
@flask_praetorian.auth_required
def remove_link(): 
    error = None

    if not request.is_json:
        err = 'Invalid request data format'
        current_app.logger.warning("Client error, " +err)
        return jsonify(error= err), 400
    
    if request.method == 'DELETE':
        data = request.json
        password_id = data.get("password_id")
        group_id = data.get("group_id")

        if password_id is None:
            error = "No passwords provided"

        if group_id is None:
            error = "No group provided"

        if error is not None:
            current_app.logger.warning("Client error, " +error)
            return jsonify(
                message = error
            ), 400

        try:
            db.session.begin() 
            for e in password_id:
                link = get_link(e, group_id)
                db.session.delete(link)
            db.session.commit()
            return jsonify(
                message="Link deleted"
            ), 200
        except Exception as err:
            db.session.rollback()
            return jsonify(
                error = err
            ), 400

         
     