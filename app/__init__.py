from flask import Flask,render_template,url_for,flash,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_required,login_user,LoginManager,current_user,logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db,login_manager

app = Flask(__name__)

app.secret_key = 'secretTkey'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LcfeHMqAAAAAG0N9p3AeYn3WhrCI1nxDFMAyHzp'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LcfeHMqAAAAAIQFQJBH0eOycDxlkVtzptSKs6RV'
db.init_app(app=app)

login_manager.init_app(app=app)
login_manager.login_view = "login"
login_manager.login_message = "Щоб побачити цю сторінку необхідно авторизуватися!"

from app import views
