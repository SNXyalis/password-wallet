from flask import (
    Blueprint, flash, g, request,  jsonify
)
from werkzeug.exceptions import abort

#from flaskr.api.auth import login_required
from flaskr.database.db import db, IntegrityError
from flaskr.models.PasswordGroup import PasswordGroup
from flaskr.utils.auth import flask_praetorian

bp = Blueprint('password_group', __name__, url_prefix="/password-group")

@bp.get('/all')
def index():
    password_groups = PasswordGroup.query.filter(PasswordGroup.FK_UserID == g.user.UserID)
    l = []
    for i in password_groups:
        l.append({"id" : i.password_group_id, "title" : i.title})
    return jsonify(
        passwords = l
    ), 200

@bp.post('/')
@flask_praetorian.auth_required
def create():

    if not request.is_json:
        return jsonify(
            error = "Invalid JSON data"
        ), 400
    
    if request.method == 'POST':
        data = request.json
        title = data.get('title')
        description = None
        group_img = None
        if data.get('description'):
            description = data.get('description')
        if data.get('group_img'):
            group_img = data.get('group_img')

        if not title:
            error = 'Title is required.'

        if error is not None:
            return jsonify(
                message = error
            ), 400
        else:
            try:
                password_group = PasswordGroup(
                    title = title,
                    description = description,
                    group_img = group_img,
                    FK_UserID = g.user.UserID,
                    creator = g.user.Username,
                    modified_by = g.user.Username,
                )
            except IntegrityError:
                db.session.rollback()
                error = f"Group with Title {title} on user {g.user.Username} is already registered."
            except AttributeError:
                db.session.rollback()
                error = f"Column Constraint violated"
            else:
                return jsonify({"message": "Group added succesfully"}), 201

    return jsonify({"message": "Failed to create Group"}), 400

def get_password_group(password_group_id, check_author=True):
    group = db.first_or_404(db.select(PasswordGroup).filter_by(password_group_id=password_group_id))

    if group is None:
        abort(404, f"Group id {password_group_id} doesn't exist.")

    if check_author and group.FK_UserID != g.user.UserID:
        abort(403)

    return group

@bp.put('/<int:password_group_id>')
@flask_praetorian.auth_required
def update(password_group_id):
    if not request.is_json:
        return jsonify(
            error="Invalid JSON data"
        ), 400
    
    if request.method == "PUT":
        data = request.json
        title = data.get('title')
        description = None
        group_img = None
        if data.get('description'):
            description = data.get('description')
        if data.get('group_img'):
            group_img = data.get('group_img')

        if not title:
            error = 'Title is required.'

        if error is not None:
            return jsonify(
                message = error
            ), 400
        else:
            try:
                group = get_password_group(password_group_id)
                group.title = title
                group.description = description
                group.group_img = group_img
                group.modified_by = g.user.Username
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                error = f"Group with {title} is already registered."
            except AttributeError:
                db.session.rollback()
                error = f"Column Constraint violated"
            else:
                return jsonify({"message": "Group updated"}), 200

    return jsonify({"message": "Bad request"}), 400

@bp.delete('<int:password_group_id>')
@flask_praetorian.auth_required
def delete(password_group_id):
    group = get_password_group(password_group_id)
    db.session.delete(group)
    db.session.commit()
    return jsonify(
        message="Group deleted successfully"
    ), 200

