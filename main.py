import flask
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, BooleanField, validators
from wtforms.validators import DataRequired, URL, Length, Email, ValidationError
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# CONNECT TO DATABASE
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CREATE TABLE
class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    maps_url = db.Column(db.String(250), unique=True, nullable=False)
    img_url = db.Column(db.String(250), unique=True, nullable=False)
    city = db.Column(db.String(250), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    accommodation = db.Column(db.String(250), nullable=False)
    sockets = db.Column(db.Boolean(250), nullable=False)
    restroom = db.Column(db.Boolean(250), nullable=False)
    wifi = db.Column(db.Boolean(250), nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(40), nullable=False)


db.create_all()

# WTForm
class AddCafeForm(FlaskForm):
    name = StringField("Cafe Name", validators=[DataRequired()])
    maps_url = StringField("Google Maps Url", validators=[DataRequired()])
    img_url = StringField("Image Url", validators=[DataRequired()])
    city = StringField("Cafe City", validators=[DataRequired()])
    price = StringField("Coffee Price", validators=[DataRequired()])
    accommodation = SelectField("How many people can the cafe accommodate?",
                                choices=["1-10", "10-20", "20-30", "30-40", "50+"], validators=[DataRequired()])
    sockets = BooleanField("Cafe has power sockets")
    restroom = BooleanField("Cafe has a restroom available")
    wifi = BooleanField("Cafe has wifi available")
    submit = SubmitField("Add Cafe")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=4, max=15)])
    password = StringField("Password", validators=([DataRequired(), Length(min=8, max=40)]))
    remember = BooleanField("Remember me")
    submit = SubmitField("Log In")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=4, max=15)])
    email = StringField("Email", validators=([DataRequired(), Email(message="Invalid email")]))
    password = StringField("Password", validators=([DataRequired(), Length(min=8, max=40)]))
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one."
            )


@app.route('/')
def home():
    return render_template("index.html")

@app.route('/cafes')
def get_all_cafes():
    cafes = db.session.query(Cafe).all()
    return render_template("cafes.html", all_cafes=cafes)


@app.route('/add-cafe', methods=["GET", "POST"])
@login_required
def add_new_cafe():
    form = AddCafeForm()
    if form.validate_on_submit():
        new_cafe = Cafe(
            name=form.name.data,
            maps_url=form.maps_url.data,
            img_url=form.img_url.data,
            city=form.city.data,
            price=form.price.data,
            accommodation=form.accommodation.data,
            sockets=form.sockets.data,
            restroom=form.restroom.data,
            wifi=form.wifi.data
        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for("get_all_cafes"))
    return render_template("add-cafe.html", form=form, name=current_user.username)


@app.route("/edit-post/<int:cafe_id>", methods=["GET", "POST"])
@login_required
def edit_cafe(cafe_id):
    cafe = Cafe.query.get(cafe_id)
    edit_form = AddCafeForm(
        name=cafe.name,
        maps_url=cafe.maps_url,
        img_url=cafe.img_url,
        city=cafe.city,
        price=cafe.price,
        accommodation=cafe.accommodation,
        sockets=cafe.sockets,
        restroom=cafe.restroom,
        wifi=cafe.wifi
    )
    if edit_form.validate_on_submit():
        cafe.name = edit_form.name.data
        cafe.maps_url = edit_form.maps_url.data
        cafe.img_url = edit_form.img_url.data
        cafe.city = edit_form.city.data
        cafe.price = edit_form.price.data
        cafe.accommodation = edit_form.accommodation.data
        cafe.sockets = edit_form.sockets.data
        cafe.restroom = edit_form.restroom.data
        cafe.wifi = edit_form.wifi.data
        db.session.commit()
        return redirect(url_for("get_all_cafes"))
    return render_template('add-cafe.html', form=edit_form, is_edit=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(username=login_form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, login_form.password.data):
                login_user(user)
                flask.flash('Logged in successfully')
                return redirect(url_for('add_new_cafe'))
            else:
                return flask.abort(400)
    return render_template('login.html', form=login_form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    signup_form = RegisterForm()
    if signup_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(signup_form.password.data)
        new_user = User(
            username=signup_form.username.data,
            email=signup_form.email.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
    return render_template('signup.html', form=signup_form)


@app.route('/delete/<int:cafe_id>')
@login_required
def delete_cafe(cafe_id):
    cafe_to_delete = Cafe.query.get(cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_cafes'))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)
