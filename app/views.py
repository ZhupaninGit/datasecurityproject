from flask import render_template, url_for, flash, redirect, request
from flask_login import login_required,login_user, current_user,logout_user
from werkzeug.security import generate_password_hash, check_password_hash

import random
import string

from app import app, serializer,generate_confirmation_token,generate_password_hash,mail
from app.extensions import db,admin_required
from app.models import User,LoginAttempt

from flask_mail import Message


captcha_value = ''.join(random.choices(string.ascii_letters + string.digits, k=6))

@app.route("/")
@login_required
def index():
    return render_template("mainpage.html",user=current_user)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


from datetime import datetime, timedelta

MAX_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

@app.route('/login', methods=['GET', 'POST'])
def login():
    from app.forms import LoginForm
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()    
        login_attempt = LoginAttempt(email=form.email.data)
        
        if user:
            if user.locked_until and user.locked_until > datetime.utcnow():
                flash('Ваш аккаунт заблоковано. Спробуйте пізніше.')
                return redirect(url_for('login'))
            
            if check_password_hash(user.password, form.password.data):
                login_attempt.success = True  
                login_user(user)
                
                user.failed_attempts = 0
                user.locked_until = None
                db.session.commit()
                
                db.session.add(login_attempt)
                db.session.commit()
                
                flash('Успішний вхід')
                return redirect(url_for('index'))
            else:
                user.failed_attempts += 1
                db.session.add(login_attempt)

                if user.failed_attempts >= MAX_ATTEMPTS:
                    user.locked_until = datetime.now() + LOCKOUT_DURATION
                    flash(f'Ваш аккаунт заблоковано на {LOCKOUT_DURATION.total_seconds() / 60} хвилин.')
                else:
                    flash('Неправильна електронна адреса або пароль.')
                
                db.session.commit()
        else:
            flash(f'Користувача {form.email.data} не існує. Зареєструйте новий аккаунт')
            return redirect(url_for('register'))
        
        db.session.add(login_attempt)
        db.session.commit()

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

@login_required
@app.route('/send_confirmation/<email>')
def send_confirmation(email):
    if not current_user.confirmed:
        token = generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = f'Натисніть на посилання для активації аккаунту: <a href="{confirm_url}">Активуйте ваш аккаунт</a>'
        msg = Message('Активація аккаунту', recipients=[email], html=html)
        mail.send(msg)
        return render_template("confirmation.html")
    else:
        flash("Аккаунт вже активовано.")
        return redirect(url_for('index'))

@app.route('/confirm/<token>')
def confirm_email(token):
    if current_user.confirmed:
        flash("Аккаунт вже активовано.")
    try:
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=3600)  # 1 hour
    except:
        flash('Помилка при активації аккаунта.')

    current_user.confirmed = True
    db.session.commit()
    
    flash('Ваш аккаунт було активовано!')
    return redirect(url_for('index'))


@app.route('/admin/login_attempts')
@login_required
@admin_required
def login_attempts():
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()
    return render_template('login_attempts.html', attempts=attempts)
