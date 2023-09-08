from flaskr.database.db import db
from datetime import datetime
class User(db.Model):
    UserID = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    Username = db.Column(db.String(256), unique=True, nullable=False)
    Email = db.Column(db.String(256), unique=True, index=True, nullable=False)
    Password = db.Column(db.Text, nullable=False)
    roles = db.Column(db.String(256), default="User", nullable=False)
    is_active = db.Column(db.Boolean, default=True, server_default="true", nullable=False)
    CreatedAt = db.Column(db.DateTime(), default=datetime.now, nullable=False)
    UpdatedAt = db.Column(db.DateTime(), default=datetime.now, onupdate=datetime.now, nullable=False)

    @property
    def identity(self):
        return self.UserID
    @property
    def rolenames(self):
        try:
            return self.roles.split(",")
        except Exception:
            return []
    @property
    def password(self):
        return self.Password
    @classmethod
    def lookup(cls, username):
        return cls.query.filter_by(Username=username).one_or_none()
    @classmethod
    def identify(cls, id):
        return cls.query.get(id)
    
    def is_valid(self):
        return self.is_active
        