from flaskr.database.db import db

#A junction table to implement many-to-many relationship between groups and passwords
class PasswordGroupLink(db.Model):
    PasswordID = db.Column(db.Integer, db.ForeignKey("password.PasswordID"), primary_key=True)
    password_group_id = db.Column(db.Integer, db.ForeignKey("passwordGroup.password_group_id"), primary_key=True)
    FK_UserID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable=False)
