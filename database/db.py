from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, AttributeError

###Warning: In case of db migration, if you use oracledb be aware of the case sensitivity

db = SQLAlchemy()