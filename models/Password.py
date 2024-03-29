from flaskr.database.db import db
from datetime import datetime


class Password(db.Model):
    PasswordID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Title = db.Column(db.String(256)) 
    Username = db.Column(db.String(256))
    EncryptedPassword = db.Column(db.String(256))
    FK_UserID = db.Column(db.Integer, db.ForeignKey('user.UserID'))
    CreatedAt = db.Column(db.DateTime(), default=datetime.now)
    UpdatedAt = db.Column(db.DateTime(), default=datetime.now, onupdate=datetime.now)
