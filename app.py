from flask import Flask, render_template, redirect, session, flash, url_for
from models import connect_db, db, User, bcrypt  # Make sure bcrypt is imported here
from forms import RegistrationForm, LoginForm  # Corrected import for LoginForm
from wtforms import StringField, PasswordField, validators
from wtforms.validators import Email, DataRequired, Lengthr


from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///auth_demo"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

bcrypt = Bcrypt(app)

connect_db(app)

@app.route('/')
def home_page():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        print(form.data)  # Just print the form data for now
        flash('Form is valid!', 'success')
        return redirect(url_for('home_page'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()  # Updated to use LoginForm
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome Back, {user.username}!", "primary")
            session['user_id'] = user.id
            return redirect('/')  # Adjusted the redirect as needed
        else:
            form.username.errors = ['Invalid username/password.']

    return render_template('login.html', form=form)

@app.route('/logout')
def logout_user():
    session.clear()  # Clearing the entire session
    return redirect('/')

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    if 'username' not in session or username != session['username']:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('login_user'))
    User.query.filter_by(username=username).delete()
    Feedback.query.filter_by(username=username).delete()
    db.session.commit()
    session.pop('username')
    flash("User and all associated feedback deleted.", "info")
    return redirect('/')

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    if 'username' not in session or username != session['username']:
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

@app.route('/users/<username>')
def show_user(username):
    if 'username' not in session or username != session['username']:
        flash("You must be logged in to view this page.", "danger")
        return redirect(url_for('login_user'))
    user = User.query.filter_by(username=username).first_or_404()
    feedback = Feedback.query.filter_by(username=username).all()
    return render_template('user_profile.html', user=user, feedback=feedback)

@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' not in session or feedback.username != session['username']:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('login_user'))
    form = FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash("Feedback updated!", "success")
        return redirect(url_for('show_user', username=feedback.username))
    return render_template('edit_feedback.html', form=form, feedback_id=feedback_id)

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' not in session or feedback.username != session['username']:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('login_user'))
    db.session.delete(feedback)
    db.session.commit()
    flash("Feedback deleted!", "info")
    return redirect(url_for('show_user', username=feedback.username))