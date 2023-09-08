import os

from flask import Flask
#from . import db
from flaskr.database.db import db
from flaskr.models import Password
from flaskr.models.User import User
from flaskr.utils.auth import guard, cors
from flaskr.utils.util import blacklist, mail

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    #CONFIG
    app.config.from_mapping(
        SECRET_KEY='dev',
        SQLALCHEMY_DATABASE_URI = "sqlite:///"+ os.path.join(app.instance_path, 'pw.sqlite')
    )
    app.config["JWT_ACCESS_LIFESPAN"] = {"hours": 24}
    app.config["JWT_REFRESH_LIFESPAN"] = {"days": 30}
    app.config["PRAETORIAN_CONFIRMATION_SENDER"] = "noreply@example.com"
    app.config["PRAETORIAN_CONFIRMATION_SUBJECT"] = "test"
    app.config["PRAETORIAN_CONFIRMATION_URI"] = "127.0.0.1:5000/register-confirm"
    app.config['MAIL_SERVER'] = 'localhost'  # MailHog runs locally
    app.config['MAIL_PORT'] = 1025  # Use port 1025 for SMTP
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = None
    app.config['MAIL_PASSWORD'] = None


    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    if app.config.get("MAIL_SERVER"):
        mail.init_app(app)

    #AUTH
    guard.init_app(app, user_class = User, is_blacklisted=blacklist.is_blacklisted)

    #DB
    db.init_app(app)
    
    #CORS
    cors.init_app(app)

    with app.app_context():
        db.create_all()

    #BP
    from flaskr.api import auth
    app.register_blueprint(auth.bp)
    from flaskr.api import password
    app.register_blueprint(password.bp)

    #from . import password
    #app.register_blueprint(password.bp)
    #app.add_url_rule('/', endpoint='index')


    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    return app