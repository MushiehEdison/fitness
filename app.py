from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os
import secrets
import urllib.parse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
# Use forward slashes for SQLite URI to ensure Windows compatibility
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///fitzone.db').replace('\\', '/')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'auth'

# WhatsApp contact number (without + sign, include country code)
WHATSAPP_NUMBER = "237652523818"  # Replace with your actual WhatsApp business number

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    logger.info("Accessing index route")
    return render_template('index.html', 
                         logged_in=current_user.is_authenticated, 
                         user_name=current_user.name if current_user.is_authenticated else '')

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    form_type = request.args.get('form_type', 'login')
    plan = request.args.get('plan', '')
    
    logger.info(f"Accessing auth route with form_type={form_type}, plan={plan}")
    
    if current_user.is_authenticated:
        logger.info(f"User {current_user.email} already authenticated, redirecting")
        if plan:
            return redirect(url_for('redirect_to_whatsapp', plan=plan))
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_type = request.form.get('form_type', 'login')
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            logger.warning("Missing email or password in form submission")
            flash('Please fill in all required fields.', 'error')
            return render_template('auth.html', form_type=form_type, plan=plan)
        
        if form_type == 'signup':
            name = request.form.get('name', '').strip()
            confirm_password = request.form.get('confirm_password', '')
            
            logger.info(f"Signup attempt for email: {email}")
            
            if not name:
                logger.warning("Missing name in signup form")
                flash('Please provide your full name.', 'error')
                return render_template('auth.html', form_type='signup', plan=plan)
            
            if len(password) < 6:
                logger.warning("Password too short")
                flash('Password must be at least 6 characters long.', 'error')
                return render_template('auth.html', form_type='signup', plan=plan)
            
            if password != confirm_password:
                logger.warning("Passwords do not match")
                flash('Passwords do not match!', 'error')
                return render_template('auth.html', form_type='signup', plan=plan)
            
            # Check if user already exists
            try:
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    logger.warning(f"Email {email} already exists")
                    flash('An account with this email already exists. Please log in instead.', 'error')
                    return render_template('auth.html', form_type='login', plan=plan)
                
                # Create new user
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = User(name=name, email=email, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                
                logger.info(f"New user created: {email}")
                
                # Log in the new user
                login_user(new_user)
                flash(f'Welcome to FitZone Pro, {name.split()[0]}!', 'success')
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error creating user: {str(e)}")
                flash('An error occurred while creating your account. Please try again.', 'error')
                return render_template('auth.html', form_type='signup', plan=plan)
                
        else:  # Login
            logger.info(f"Login attempt for email: {email}")
            user = User.query.filter_by(email=email).first()
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user)
                logger.info(f"Successful login for {email}")
                flash(f'Welcome back, {user.name.split()[0]}!', 'success')
            else:
                logger.warning(f"Invalid login attempt for {email}")
                flash('Invalid email or password.', 'error')
                return render_template('auth.html', form_type='login', plan=plan)
        
        # After successful login/signup, redirect to WhatsApp if plan was selected
        if plan:
            logger.info(f"Redirecting to WhatsApp for plan: {plan}")
            return redirect(url_for('redirect_to_whatsapp', plan=plan))
        
        return redirect(url_for('index'))
    
    return render_template('auth.html', form_type=form_type, plan=plan)

@app.route('/logout')
@login_required
def logout():
    user_name = current_user.name.split()[0] if current_user.is_authenticated else ''
    user_email = current_user.email
    logout_user()
    logger.info(f"User {user_email} logged out")
    flash(f'Goodbye, {user_name}! You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/contact', methods=['POST'])
def contact():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    phone = request.form.get('phone', '').strip()
    message = request.form.get('message', '').strip()
    
    logger.info(f"Contact form submission from {email}")
    
    if not name or not email or not message:
        logger.warning("Missing required fields in contact form")
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('index') + '#contact')
    
    try:
        new_message = ContactMessage(
            name=name,
            email=email,
            phone=phone,
            message=message
        )
        db.session.add(new_message)
        db.session.commit()
        
        logger.info(f"Contact message saved from {email}")
        flash(f'Thank you for your message, {name.split()[0]}! We will get back to you soon.', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving contact message: {str(e)}")
        flash('Failed to send your message. Please try again.', 'error')
    
    return redirect(url_for('index') + '#contact')

@app.route('/select-plan/<plan>')
@login_required
def redirect_to_whatsapp(plan):
    """Redirect logged-in users to WhatsApp for plan discussion"""
    logger.info(f"Redirecting user {current_user.email} to WhatsApp for plan: {plan}")
    
    # Plan details for WhatsApp message
    plan_details = {
        'Basic': {'price': '20,000 frs/month', 'features': 'Full gym access, Cardio equipment, Strength training area, Locker room access'},
        'Premium': {'price': '30,000 frs/month', 'features': 'Everything in Basic + All group classes + Recovery zone access + Nutrition consultation + Guest passes'},
        'Elite': {'price': '45,000 frs/month', 'features': 'Everything in Premium + Personal training sessions + Priority booking + Unlimited guest passes + Massage therapy + VIP locker'}
    }
    
    if plan not in plan_details:
        logger.warning(f"Invalid plan selected: {plan}")
        flash('Invalid plan selected.', 'error')
        return redirect(url_for('index'))
    
    # Create WhatsApp message
    user_name = current_user.name
    plan_info = plan_details[plan]
    
    message = f"""Hello! I'm {user_name} and I'm interested in the {plan} Plan.

Plan Details:
- Price: {plan_info['price']}
- Features: {plan_info['features']}

Could you please help me complete the membership registration and payment process?

Thank you!"""
    
    # URL encode the message
    encoded_message = urllib.parse.quote(message)
    whatsapp_url = f"https://wa.me/{WHATSAPP_NUMBER}?text={encoded_message}"
    
    logger.info(f"Redirecting to WhatsApp URL: {whatsapp_url}")
    return redirect(whatsapp_url)

# Initialize database
def init_database():
    with app.app_context():
        try:
            # Drop all tables and recreate them to ensure schema consistency
            db.drop_all()
            db.create_all()
            logger.info("Database initialized successfully with updated schema")
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            raise

if __name__ == '__main__':
    init_database()
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)