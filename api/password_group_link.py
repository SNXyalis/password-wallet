from flask import (
    Blueprint, request, g, jsonify
)
from flaskr.database.db import db, IntegrityError
from flaskr.models.Password import Password
from flaskr.models.PasswordGroup import PasswordGroup
from flaskr.models.PasswordGroupLink import PasswordGroupLink

bp = Blueprint('password_group_link', __name__, url_prefix='/password-group-link')

#Adds passwords in a group
#params: single group id, array of password ids
@bp.post('/')
def add_link():

    error = None

    if not request.is_json:
        return jsonify(
            error = "Invalid JSON data"
        ),400
    
    if request.method == 'POST':
        data = request.json
        password_id = data.get("password_id")
        group_id = data.get("group_id")

        group_link = []

        
        try:
            db.session.begin()
            for e in password_id:
                group_link.append(
                    PasswordGroupLink(
                        PasswordID = e,
                        password_group_id = group_id
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
        

#TODO

#REMOVE PASSWORD FROM GROUP