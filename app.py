from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os 
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16).hex()  # Generate a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fitzone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'auth'  # Redirect to auth page if not logged in

# User model with Flask-Login integration
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required  # Require login to access homepage
def index():
    return render_template('index.html', 
                         logged_in=current_user.is_authenticated, 
                         user_name=current_user.name if current_user.is_authenticated else '',
                         selected_plan=session.get('selected_plan', None))

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    form_type = request.args.get('form_type', 'login')
    plan = request.args.get('plan')
    
    if request.method == 'POST':
        form_type = request.form.get('form_type', 'login')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if form_type == 'signup':
            name = request.form.get('name')
            confirm_password = request.form.get('confirm_password')
            
            if password != confirm_password:
                flash('Passwords do not match!', 'error')
                return render_template('auth.html', form_type='signup', plan=plan, 
                                     logged_in=current_user.is_authenticated, 
                                     user_name=current_user.name if current_user.is_authenticated else '')
            
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered!', 'error')
                return render_template('auth.html', form_type='signup', plan=plan, 
                                     logged_in=current_user.is_authenticated, 
                                     user_name=current_user.name if current_user.is_authenticated else '')
            
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            
            user = User.query.filter_by(email=email).first()
            login_user(user)  # Log in the user after signup
            flash('Account created successfully!', 'success')
        else:
            user = User.query.filter_by(email=email).first()
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user)  # Log in the user
                flash('Login successful!', 'success')
            else:
                flash('Invalid email or password!', 'error')
                return render_template('auth.html', form_type='login', plan=plan, 
                                     logged_in=current_user.is_authenticated, 
                                     user_name=current_user.name if current_user.is_authenticated else '')
        
        if plan:
            session['selected_plan'] = plan
            return redirect(url_for('index'))
        
        return redirect(url_for('index'))
    
    return render_template('auth.html', form_type=form_type, plan=plan, 
                         logged_in=current_user.is_authenticated, 
                         user_name=current_user.name if current_user.is_authenticated else '')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()  # Use Flask-Login to log out
    session.pop('selected_plan', None)  # Clear selected plan
    flash('Successfully logged out!', 'success')
    return redirect(url_for('index'))

@app.route('/contact', methods=['POST'])
def contact():
    flash('Thank you for your message! We will get back to you soon.', 'success')
    return redirect(url_for('index') + '#contact')

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)