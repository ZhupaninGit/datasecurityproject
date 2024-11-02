from flask import render_template, url_for, flash, redirect, request
from flask_login import login_required,login_user, current_user,logout_user
from werkzeug.security import generate_password_hash, check_password_hash

import random
import string

from app import app
from app.extensions import db
from app.models import User

captcha_value = ''.join(random.choices(string.ascii_letters + string.digits, k=6))

@app.route("/")
@login_required
def index():
    user = current_user
    return render_template("mainpage.html")

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/login', methods=['GET', 'POST'])
def login():
    from app.forms import LoginForm
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                flash('Успішний вхід')
                login_user(user=user)
                return redirect(url_for('index'))
            else:
                flash('Неправильна електронна адреса або пароль.')
        else:
            flash(f'Користувача {form.email.data} не існує. Зареєструйте новий аккаунт')
            return redirect(url_for('register'))
    return render_template('login.html', form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    from app.forms import RegistrationForm
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Реєстрація успішна.Тепер Ви можете зайти у свій аккаунт.')
        return redirect(url_for('login'))

    return render_template("register.html", form=form)
