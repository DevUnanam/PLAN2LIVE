from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_cors import CORS, cross_origin
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
import pyotp
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import timedelta
from datetime import datetime, timezone
from api.states_api import api
from state_lga_data import get_all_states
from dotenv import load_dotenv



import os
import openai
import secrets
from PIL import Image
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Use a strong secret key
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:M3d3asin3@localhost/plan2live"
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'Riaahh20@gmail.com'
app.config['MAIL_PASSWORD'] = 'qzcd lzhc oizb tvbt'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_DURATION=timedelta(days=1)
)

app.register_blueprint(api)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # Serializer for generating secure tokens
CORS(app)  # Enable CORS for the Flask app
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Configure OAuth providers
google_bp = make_google_blueprint(client_id="YOUR_GOOGLE_CLIENT_ID", client_secret="YOUR_GOOGLE_CLIENT_SECRET", redirect_to='google_login')
facebook_bp = make_facebook_blueprint(client_id="YOUR_FACEBOOK_CLIENT_ID", client_secret="YOUR_FACEBOOK_CLIENT_SECRET", redirect_to='facebook_login')
app.register_blueprint(google_bp, url_prefix="/google_login")
app.register_blueprint(facebook_bp, url_prefix="/facebook_login")

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    phone_number = db.Column(db.String(20))
    is_verified = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(200))
    verification_token = db.Column(db.String(60), nullable=True)
    reset_token = db.Column(db.String(60), nullable=True)
    otp_secret = db.Column(db.String(16), nullable=True)
    bookings = db.relationship('Booking', backref='user', lazy=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    profile_picture_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
# Hospital Model
class Hospital(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    state = db.Column(db.String(60), nullable=False)
    local_government = db.Column(db.String(60), nullable=False)
    address = db.Column(db.String(255), nullable=False)

# Forms
class SignUpForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class SignInForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class ProfileUpdateForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=6)])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    profile_picture = FileField('Update Profile Picture')  # Allow profile picture upload
    submit = SubmitField('Update Profile')
    
class ReviewForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Leave a Review', validators=[DataRequired(), Length(max=400)])
    submit = SubmitField('Submit Review')
    
    
    

# Decorators for Role-Based Access Control
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('signin'))
            user = User.query.filter_by(email=session['user']).first()
            if user.role != role:
                return 'You do not have permission to access this page.', 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Function to save profile picture
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    # Resize the image to a standard size
    output_size = (150, 150)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def splash():
    return render_template('splash.html')

@app.route('/landing')
def landing():
    signin_form = SignInForm()
    signup_form = SignUpForm()
    review_form = ReviewForm()
    return render_template('landing.html', signin_form=signin_form, signup_form=signup_form, review_form=review_form)

@app.route('/signin', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signin():
    form = SignInForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if not user.is_verified:
                return 'Please verify your email before logging in.', 401
            if user.otp_secret:  # Check if 2FA is enabled
                session['user_email'] = user.email
                return redirect(url_for('verify_2fa'))
            session['user'] = user.email
            return redirect(url_for('dashboard'))
        return 'Invalid credentials', 401
    return redirect(url_for('landing'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if request.method == 'POST' and form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        verification_token = s.dumps(form.email.data, salt='email-confirm')
        new_user = User(email=form.email.data, password=hashed_password, verification_token=verification_token)
        db.session.add(new_user)
        db.session.commit()

        # Send email
        token_url = url_for('verify_email', token=verification_token, _external=True)
        msg = Message('Confirm Your Email', sender='noreply@demo.com', recipients=[form.email.data])
        msg.body = f'Please click the link to verify your email: {token_url}'
        mail.send(msg)

        return redirect(url_for('signin'))
    return redirect(url_for('landing'))

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        return 'The verification link is invalid or has expired.'
    
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_verified:
        return 'Account already verified. Please log in.'
    else:
        user.is_verified = True
        db.session.commit()
        return 'Your account has been verified!'

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            send_reset_email(user.email, reset_url)
            flash('A password reset link has been sent to your email.', 'success')
        else:
            flash('Invalid email address.', 'danger')
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except:
        return 'The reset link is invalid or has expired.'
    
    user = User.query.filter_by(email=email).first_or_404()
    form = ResetPasswordForm()
    if request.method == 'POST' and form.validate_on_submit():
        user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.reset_token = None  # Clear the reset token
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('signin'))
    
    return render_template('reset_password.html', form=form)

def send_reset_email(to_email, reset_url):
    msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[to_email])
    msg.body = f'To reset your password, visit the following link: {reset_url}'
    mail.send(msg)

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Welcome {current_user.email}'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileUpdateForm()
    if request.method == 'POST' and form.validate_on_submit():
        if form.profile_picture.data:
            file = form.profile_picture.data
            if allowed_file(file.filename):
                filename = save_picture(file)  # Use the function to save the picture
                current_user.profile_picture = filename
                # Optionally, you might want to commit changes to the database here
                db.session.commit()
                flash('Your profile picture has been updated!', 'success')
            else:
                flash('File type is not allowed. Please upload a valid image.', 'danger')
        else:
            flash('No file selected. Please choose an image to upload.', 'warning')
    
    # Render the profile update form
    return render_template('profile.html', form=form)
    


# Load user bookings to display
    bookings = current_user.bookings
    return render_template('profile.html', form=form, bookings=bookings, user=current_user)

# Booking Model (Example)
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'), nullable=False)
    hospital = db.relationship('Hospital', backref='bookings')

@app.route('/enable_2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if request.method == 'POST':
        totp = pyotp.TOTP(current_user.email)  # Use user's email to generate OTP
        current_user.otp_secret = totp.secret
        db.session.commit()
        flash('2FA has been enabled.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('enable_2fa.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user_email' not in session:
        return redirect(url_for('signin'))
    
    user = User.query.filter_by(email=session['user_email']).first_or_404()
    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp):
            session['user'] = session.pop('user_email')
            flash('2FA verified. You are now logged in.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify_2fa.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('signin'))

@app.route('/testdb')
def testdb():
    try:
        result = db.session.execute('SELECT 1')
        return "Database connection successful!"
    except Exception as e:
        return f"Database connection failed: {e}"

# New API Endpoints for Hospital Enlistment
@app.route('/hospitals', methods=['POST'])
@cross_origin()
def create_hospital():
    data = request.get_json()
    new_hospital = Hospital(
        name=data['name'],
        state=data['state'],
        local_government=data['local_government'],
        address=data['address']
    )
    db.session.add(new_hospital)
    db.session.commit()
    return jsonify({'message': 'Hospital added successfully!'}), 201

@app.route('/hospitals', methods=['GET'])
@cross_origin()
def get_hospitals():
    state = request.args.get('state')
    hospitals = Hospital.query.filter_by(state=state).all()
    hospital_list = [{'id': h.id, 'name': h.name, 'state': h.state, 'local_government': h.local_government, 'address': h.address} for h in hospitals]
    return jsonify(hospital_list), 200

@app.route('/hospitals/<int:id>', methods=['GET'])
@cross_origin()
def get_hospital_by_id(id):
    hospital = Hospital.query.get(id)
    if not hospital:
        return jsonify({'message': 'Hospital not found'}), 404
    hospital_data = {
        'id': hospital.id,
        'name': hospital.name,
        'state': hospital.state,
        'local_government': hospital.local_government,
        'address': hospital.address
    }
    return jsonify(hospital_data), 200

# API endpoint to fetch states and LGAs
@app.route('/api/get-states-lga', methods=['GET'])
def get_states_lga():
    states = get_all_states()
    if states:
        return jsonify(states), 200
    return jsonify({"error": "Unable to fetch states"}), 500

@app.route('/search', methods=['GET'])
def search():
    # Logic for handling search queries
    query = request.args.get('q')
    # Process the query and return results (dummy response for now)
    return f'Search results for: {query}'

@app.route('/submit_review', methods=['POST'])
@login_required
def submit_review():
    form = ReviewForm()

    if form.validate_on_submit():
        review = Review(
            user_id=current_user.id,
            name=current_user.username,  # Or fetch name from the user profile
            content=form.content.data,
            profile_picture_url=current_user.profile_picture_url  # Or any default URL
        )
        db.session.add(review)
        db.session.commit()
        flash('Your review has been submitted!', 'success')
        return redirect(url_for('landing'))  # Redirect to a relevant page

    flash('There was an error submitting your review.', 'danger')
    return redirect(url_for('landing'))

@app.route('/enlist', methods=['POST'])
def enlist_hospital():
    hospital_name = request.form.get('hospital_name')
    hospital_email = request.form.get('hospital_email')
    hospital_state = request.form.get('hospital_state')
    hospital_lga = request.form.get('hospital_lga')
    hospital_address = request.form.get('hospital_address')

    # Generate email verification token
    token = serializer.dumps(hospital_email, salt='email-confirm')

    # Send verification email
    verification_url = url_for('confirm_email', token=token, _external=True)
    html = f'<p>Thanks for registering your hospital. Please verify your email by clicking the link below:</p><a href="{verification_url}">Verify your email</a>'

    msg = Message('Confirm Your Email', recipients=[hospital_email], html=html)
    mail.send(msg)

    flash('An email has been sent to verify your email address.', 'success')
    return redirect(url_for('enlist_page'))

# Route to handle email verification
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)  # 1-hour limit
        # Mark email as verified in the database
        # Redirect to hospital profile setup page
        flash('Your email has been verified. You can now set up your hospital profile.', 'success')
        return redirect(url_for('setup_hospital_profile'))
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('enlist_page'))

def send_email_verification(email, link):
    msg = Message('Confirm your email', sender='youremail@example.com', recipients=[email])
    msg.body = f'Please verify your email by clicking this link: {link}'
    mail.send(msg)
    
@app.route('/setup-hospital-profile')
def setup_hospital_profile():
    # Render a form where users can upload pictures, enter description, features, etc.
    return render_template('setup_hospital_profile.html')

@app.route('/save-hospital-profile', methods=['POST'])
def save_hospital_profile():
    # Save uploaded files and form data to the database
    pictures = request.files.getlist('hospital_pictures')
    description = request.form.get('hospital_description')
    features = request.form.get('hospital_features')
    specialties = request.form.get('hospital_specialties')

    # Save the hospital profile information in the database

    flash('Hospital profile saved successfully!', 'success')
    return redirect(url_for('hospital_dashboard'))

# Load OpenAI API key from environment variable
openai.api_key = os.getenv("OPENAI_API_KEY")

@app.route('/chat', methods=['POST'])
def chatbot():
    try:
        # Get user message from the request
        data = request.get_json()
        user_input = data.get('message')

        if not user_input:
            return jsonify({'error': 'No input message provided.'}), 400

        # Send user message to OpenAI's GPT model
        response = openai.Completion.create(
            model="gpt-3.5-turbo",  # Choose model, or gpt-3.5-turbo for cost-effective responses
            prompt=user_input,
            max_tokens=150,  # Adjust response length
            temperature=0.7,  # Adjust the creativity of the responses
        )

        # Extract chatbot's response
        bot_reply = response.choices[0].text.strip()

        # Return chatbot's response as JSON
        return jsonify({'reply': bot_reply}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



if __name__ == '__main__':
    db.create_all()  # Create database tables based on models
    app.run(debug=True)
