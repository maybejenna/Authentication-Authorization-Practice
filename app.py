from flask import Flask, render_template, redirect, session, flash, url_for
from models import connect_db, db, User, Feedback, bcrypt  # Make sure bcrypt is imported here
from flask_migrate import Migrate
from forms import RegistrationForm, LoginForm  # Corrected import for LoginForm
from wtforms import StringField, PasswordField, validators
from wtforms.validators import Email, DataRequired, Length


from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///auth_demo"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

bcrypt = Bcrypt(app)

migrate = Migrate(app, db)

connect_db(app)

@app.route('/')
def home_page():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pwd = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            username=form.username.data, 
            email=form.email.data,
            password=hashed_pwd, 
            first_name=form.first_name.data,  # Ensure this matches the form field
            last_name=form.last_name.data  # Ensure this matches the form field
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login_user'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            session['user_username'] = user.username  # Storing user identity in session
            flash(f"Welcome Back, {user.username}!", "primary")
            return redirect(url_for('show_user', username=user.username))
        else:
            flash('Invalid username/password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout_user():
    session.clear()  # Clears the entire session
    flash("You have been logged out.", "info")
    return redirect(url_for('home_page'))

@app.route('/users/<username>')
def show_user(username):
    if 'user_username' not in session or session['user_username'] != username:
        flash("You must be logged in to view this page.", "danger")
        return redirect(url_for('login_user'))
    user = User.query.filter_by(username=username).first_or_404()
    feedback = Feedback.query.filter_by(username=username).all()
    return render_template('user_profile.html', user=user, feedback=feedback)

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    if 'user_username' not in session or username != session['user_username']:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('login_user'))
    Feedback.query.filter_by(username=username).delete()
    User.query.filter_by(username=username).delete()
    db.session.commit()
    session.pop('user_username')
    flash("User and all associated feedback deleted.", "info")
    return redirect('/')

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    if 'user_username' not in session or username != session['user_username']:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('login_user'))
    form = FeedbackForm()
    if form.validate_on_submit():
        new_feedback = Feedback(title=form.title.data, content=form.content.data, username=username)
        db.session.add(new_feedback)
        db.session.commit()
        flash("Feedback added!", "success")
        return redirect(url_for('show_user', username=username))
    return render_template('add_feedback.html', form=form)