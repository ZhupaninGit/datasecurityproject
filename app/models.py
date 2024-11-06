from app.extensions import db,login_manager
from flask_login import UserMixin
from datetime import datetime

from sqlalchemy.sql import expression

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(50),nullable=False,unique=True)
    password = db.Column(db.String(80),nullable=False)
    confirmed = db.Column(db.Boolean(),default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean(), default=False)
    is_two_factor_enabled = db.Column(db.Boolean(), nullable=False, default=False)
    secret_token = db.Column(db.String,nullable=True)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)


