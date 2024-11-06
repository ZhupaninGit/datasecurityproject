from flask import render_template, url_for, flash, redirect, request,session
from flask_login import login_required,login_user, current_user,logout_user
from werkzeug.security import generate_password_hash, check_password_hash

import random
import string
import pyotp,qrcode
from io import BytesIO
import base64

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
            # Check if the user is locked
            if user.locked_until and user.locked_until > datetime.utcnow():
                flash('Ваш аккаунт заблоковано. Спробуйте пізніше.')
                return redirect(url_for('login'))
            
            if check_password_hash(user.password, form.password.data):
                
                if user.is_two_factor_enabled:
                    session['2fa_user_id'] = user.id
                    return redirect(url_for('two_factor_auth'))
                
                login_attempt.success = True
                login_user(user)
                
                user.failed_attempts = 0
                user.locked_until = None
                db.session.commit()
                
                flash('Успішний вхід')
                return redirect(url_for('index'))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= MAX_ATTEMPTS:
                    user.locked_until = datetime.now() + LOCKOUT_DURATION
                    flash(f'Ваш аккаунт заблоковано на {LOCKOUT_DURATION.total_seconds() / 60} хвилин.')
                else:
                    flash('Неправильна електронна адреса або пароль.')
        else:
            flash(f'Користувача {form.email.data} не існує. Зареєструйте новий аккаунт')
            return redirect(url_for('register'))
        
        db.session.add(login_attempt)
        db.session.commit()

    return render_template('login.html', form=form)

@app.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    from app.forms import TwoFactorForm
    form = TwoFactorForm()
    
    user_id = session.get('2fa_user_id')
    if not user_id:
        flash("Щось пішло не так...")
        return redirect(url_for('login'))
    
    user = User.query.get(user_id)
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.secret_token)
        
        if totp.verify(form.code.data):
            login_user(user)
            session.pop('2fa_user_id', None)
            
            flash('Успішний вхід з 2FA!')
            return redirect(url_for('index'))
        else:
            flash('Неправильний 2FA код.')

    return render_template('two_factor_auth.html', form=form)



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


@app.route('/enable_2fa', methods=['POST', 'GET'])
@login_required
def enable_2fa():
    if current_user.is_two_factor_enabled:
        flash("Аутентифікацію 2FA вже ввімкнено.")
        return redirect(url_for("index"))
    
    current_user.secret_token = pyotp.random_base32()
    current_user.is_two_factor_enabled = True
    db.session.commit()
    
    totp = pyotp.TOTP(current_user.secret_token)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="flaskapplication")
    
    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return render_template('enable_2fa.html', qr_code_base64=qr_code_base64)

@app.route('/disable_2fa', methods=['POST', 'GET'])
@login_required
def disable_2fa():
    current_user.is_two_factor_enabled = False  
    current_user.secret_token = None 
    db.session.commit()
    flash("Аутентифікацію 2FA вимкнено.")
    return redirect(url_for('index'))
