from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import Email,DataRequired,Length,ValidationError,EqualTo
import re

class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired("Поле не може бути пустим"), Email("Некоректна електронна адреса")])
    password = PasswordField('Пароль', validators=[DataRequired("Поле не може бути пустим")])
    submit = SubmitField('Увійти')


class RegistrationForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired("Поле не може бути пустим"), Email("Некоректна електронна адреса")])
    password = PasswordField('Пароль', validators=[
        DataRequired("Поле не може бути пустим"),
        Length(min=8, message='Пароль має складатися з 8 і більше символів.')
    ])
    repeat_pass = PasswordField(validators=[DataRequired("Поле не може бути пустим"), EqualTo("password", message="Паролі не співпадають.")], label="Повторіть пароль")
    captcha = RecaptchaField()
    submit = SubmitField('Зареєструвати аккаунт')

    def validate_password(self, password):
        password_data = password.data

        if not re.search(r'[A-Z]', password_data):
            raise ValidationError("Пароль має містити щонайменше 1 велику літеру.")
        if not re.search(r'[a-z]', password_data):
            raise ValidationError("Пароль має містити щонайменше 1 малу літеру.")
        if not re.search(r'[0-9]', password_data):
            raise ValidationError("Пароль має містити щонайменше 1 цифру.")
        if not re.search(r'[!@#$%^&*(),.?]', password_data):
            raise ValidationError("Пароль має містити щонайменше 1 спеціальний символ (!@#$%^&*(),.?)")

    def validate_email(self, email):
        from app.models import User
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Користувач з таким e-mail вже існує.')
        

class TwoFactorForm(FlaskForm):
    code = StringField('2FA Код', validators=[DataRequired()])
    submit = SubmitField('Увійти')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    submit = SubmitField('Відновити пароль')

class PasswordResetForm(FlaskForm):
    password = PasswordField('Новий пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Повторіть новий пароль', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Змінити пароль')

    def validate_password(self, password):
        password_data = password.data

        if not re.search(r'[A-Z]', password_data):
            raise ValidationError("Пароль має містити щонайменше 1 велику літеру.")
        if not re.search(r'[a-z]', password_data):
            raise ValidationError("Пароль має містити щонайменше 1 малу літеру.")
        if not re.search(r'[0-9]', password_data):
            raise ValidationError("Пароль має містити щонайменше 1 цифру.")
        if not re.search(r'[!@#$%^&*(),.?]', password_data):
            raise ValidationError("Пароль має містити щонайменше 1 спеціальний символ (!@#$%^&*(),.?)")