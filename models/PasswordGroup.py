from flaskr.database.db import db
from datetime import datetime

class PasswordGroup(db.Model):
    password_group_id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    title = db.Column(db.String(256), unique=True, nullable=False)
    description = db.Column(db.Text)
    group_img = db.Column(db.String(256))
    FK_UserID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable=False)
    creator = db.Column(db.String(256))
    modified_by = db.Column(db.String(256))
    CreatedAt = db.Column(db.Datetime(), default=datetime.now, nullable=False)
    UpdatedAt = db.Column(db.Datetime(), default=datetime.now, onupdate=datetime.now, nullable=False)