from app.extensions import db,login_manager
from flask_login import UserMixin

from sqlalchemy.sql import expression

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(50),nullable=False,unique=True)
    password = db.Column(db.String(80),nullable=False)
    is_active = db.Column(db.Boolean,nullable=False,default=False)



