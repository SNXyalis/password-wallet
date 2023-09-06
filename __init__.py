import os

from flask import Flask

def create_app(test_config=None):
    
    app = Flask(__name__, instance_relative_config=True)
    
    #CONFIG
    app.config.from_mapping(
        SECRET_KEY='dev',
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(app.instance_path, "pw.sqlite")
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    #DB
    from flaskr.database.db import db
    db.init_app(app)

    with app.app_context():
        from flaskr.models.User import User
        from flaskr.models.Password import Password
        db.create_all()

    #Blueprints
    from flaskr.api import auth
    app.register_blueprint(auth.bp)

    #from flaskr.api import password
    #app.register_blueprint(password.bp)

    return app