# from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash
#
# import views
# from app.models import User

from app import app

# app = Flask(__name__)
#
# app.secret_key = 'secretTkey'
# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
# db.init_app(app=app)
#
# login_manager.init_app(app=app)
# login_manager.login_view = "login"
# login_manager.login_message = "Щоб побачити цю сторінку необхідно авторизуватися!"
#
# @app.route("/")
# @login_required
# def index():
#     user = current_user
#     return render_template("mainpage.html")
#
# @app.route("/logout")
# def logout():
#     logout_user()
#     return redirect(url_for("login"))
#
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     from forms import LoginForm
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if user:
#             if check_password_hash(user.password, form.password.data):
#                 flash('Успішний вхід')
#                 login_user(user=user)
#                 return redirect(url_for('index'))
#             else:
#                 flash('Неправильна електронна адреса або пароль.')
#         else:
#             flash(f'Користувача {form.email.data} не існує. Зареєструйте новий аккаунт')
#             return redirect(url_for('register'))
#     return render_template('login.html', form=form)
#
# @app.route("/register",methods=["GET","POST"])
# def register():
#     from forms import RegistrationForm
#     form = RegistrationForm()
#     if form.validate_on_submit():
#         hashed_password = generate_password_hash(form.password.data)
#         new_user = User(email=form.email.data, password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#         flash('Реєстрація успішна.Тепер Ви можете зайти у свій аккаунт.')
#         return redirect(url_for('login'))
#     return render_template('register.html', form=form)
#

if __name__ == "__main__":
    app.run(debug=True)