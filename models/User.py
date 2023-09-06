from flaskr.database.db import db
from datetime import datetime

class User(db.Model):
    UserID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Username = db.Column(db.String(256), unique=True, nullable=False)
    Email = db.Column(db.String(256), unique=True, nullable=False)
    Password = db.Column(db.String(256), nullable=False)
    CreatedAt = db.Column(db.DateTime(), default=datetime.now)
    UpdatedAt = db.Column(db.DateTime(), default=datetime.now, onupdate=datetime.now)
