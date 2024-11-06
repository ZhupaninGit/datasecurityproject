from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,current_user
from functools import wraps
from flask import redirect, url_for, flash

db = SQLAlchemy()
login_manager = LoginManager()


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("У вас немає прав доступу до цієї сторінки.")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function
