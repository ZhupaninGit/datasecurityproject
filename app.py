from flask import Flask,render_template,url_for,flash,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_required,login_user,LoginManager,current_user,logout_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = 'secretTkey'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"  

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app=app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(50),nullable=False,unique=True)
    password = db.Column(db.String(80),nullable=False)



@app.route("/")
@login_required
def index():
    user = current_user
    return f"hello,{current_user.email},logout  <a href='{url_for('logout')}'>Вийти</a>"

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/login', methods=['GET', 'POST'])
def login():
    from forms import LoginForm
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            print('Login successful!')
            login_user(user=user)
            return redirect(url_for('index'))
        else:
            print('Login dd!')
            flash('Invalid email or password.')
    return render_template('login.html', form=form)

@app.route("/register",methods=["GET","POST"])
def register():
    from forms import RegistrationForm
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)