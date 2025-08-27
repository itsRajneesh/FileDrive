# app.py
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, send_from_directory, abort
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from dotenv import load_dotenv
import os
import bcrypt
import datetime # Make sure datetime is imported
import time
import random
from pytz import timezone
from flask_uploads import UploadSet, configure_uploads, IMAGES
from werkzeug.utils import secure_filename
import uuid
from werkzeug.exceptions import RequestEntityTooLarge
from flask_mail import Mail, Message
import smtplib
from urllib.parse import quote_plus

# load .env
load_dotenv()

app = Flask(__name__)

# -------------------- Basic App Config --------------------
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey123')
app.config['DEBUG'] = True

# -------------------- MongoDB Setup --------------------
db = None
try:
    # Encode username & password
    username = quote_plus(os.getenv('DB_USER'))
    password = quote_plus(os.getenv('DB_PASS'))
    cluster = os.getenv('DB_CLUSTER')
    db_name = os.getenv('DB_NAME')

    mongo_uri = f"mongodb+srv://{username}:{password}@{cluster}/{db_name}?retryWrites=true&w=majority"
    
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    db = client[db_name]
    users = db['users']
    files = db['files']
    print("✅ Connected to MongoDB")
except ServerSelectionTimeoutError as e:
    print("❌ Database connection failed:", e)

# -------------------- Mail Config --------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')

mail = Mail(app)

# -------------------- Upload Config --------------------
UPLOAD_FOLDER = 'uploads'
app.config['UPLOADED_FILES_DEST'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB
ALLOWED_EXTENSIONS = IMAGES + ('pdf',)
fileset = UploadSet('files', ALLOWED_EXTENSIONS)
configure_uploads(app, fileset)

# ADDED: Context processor to inject 'now' into all templates
@app.context_processor
def inject_now():
    return {'now': datetime.datetime.now}

# -------------------- Forms --------------------
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    file = FileField('Upload File (PDF/Image)', validators=[DataRequired()])
    submit = SubmitField('Upload')

class SearchForm(FlaskForm):
    query = StringField('Search Files', validators=[DataRequired()])
    submit = SubmitField('Search')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')

class ResetPasswordForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')

# -------------------- Error Handlers --------------------
@app.errorhandler(ServerSelectionTimeoutError)
def handle_database_error(error):
    flash('Unable to connect to the database. Please check your network.', 'danger')
    return render_template('login.html', form=LoginForm()) # CHANGED: Render login page on db error

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    max_size = app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024)
    uploaded_size = request.content_length / (1024 * 1024) if request.content_length else 0
    flash(f"File size ({uploaded_size:.2f} MB) exceeds maximum allowed ({max_size:.2f} MB).", "danger")
    return redirect(url_for('upload'))

# -------------------- Routes --------------------
@app.route('/')
def home():
    if db is None:
        flash('Database unavailable.', 'danger')
        return render_template('login.html', form=LoginForm()) # CHANGED: Render login page on db error
        
    if 'username' in session:
        uploaded_files = list(files.find({'username': session['username']}).sort('upload_date', -1))
        return render_template('home.html', username=session['username'], files=uploaded_files)
    
    # CHANGED: More direct to redirect to login if not in session
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if db is None:
        flash('Database unavailable.', 'danger')
        return redirect(url_for('signup')) # CHANGED: Redirect to self to show flash
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.lower().strip()
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        if users.find_one({'username': username}):
            flash('Username already exists!', 'danger')
        elif users.find_one({'email': email}):
            flash('Email already registered!', 'danger')
        else:
            users.insert_one({'username': username, 'email': email, 'password': hashed_password})
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if db is None:
        flash('Database unavailable.', 'danger')
        return redirect(url_for('login')) # CHANGED: Redirect to self to show flash
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = users.find_one({'username': username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# -------------------- Upload --------------------
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    if db is None:
        flash('Database unavailable.', 'danger')
        return redirect(url_for('home'))
    form = UploadForm()
    if form.validate_on_submit():
        filedata = form.file.data
        orig_filename = secure_filename(filedata.filename)
        unique_filename = f"{uuid.uuid4().hex}_{orig_filename}"

        # File size (MB)
        filedata.seek(0, os.SEEK_END)
        file_size_mb = round(filedata.tell() / (1024 * 1024), 2)
        filedata.seek(0)

        file_ext = os.path.splitext(orig_filename)[1].lower()
        fileset.save(filedata, name=unique_filename)

        ist = timezone('Asia/Kolkata')
        upload_time_ist = datetime.datetime.now(ist)
        upload_time_utc = datetime.datetime.utcnow()
        upload_date_str = upload_time_ist.strftime('%Y-%m-%d %I:%M:%S %p IST')

        files.insert_one({
            'username': session['username'],
            'filename': unique_filename,
            'original_filename': orig_filename,
            'file_size': file_size_mb,
            'file_type': file_ext,
            'upload_date': upload_time_utc,
            'upload_date_str': upload_date_str,
            'download_count': 0
        })
        flash(f'File "{orig_filename}" uploaded successfully ({file_size_mb:.2f} MB)!', 'success')
        return redirect(url_for('home'))
    return render_template('upload.html', form=form)

# -------------------- Download --------------------
@app.route('/download/<filename>')
def download(filename):
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    if db is None:
        flash('Database unavailable.', 'danger')
        return redirect(url_for('home'))

    file_doc = files.find_one({'username': session['username'], 'filename': filename})
    if not file_doc:
        flash('File not found or unauthorized!', 'danger')
        return redirect(url_for('home'))

    # increment download count
    files.update_one({'_id': file_doc['_id']}, {'$inc': {'download_count': 1}})

    upload_dir = app.config.get('UPLOADED_FILES_DEST', 'uploads')
    file_path = os.path.join(upload_dir, filename)
    if not os.path.exists(file_path):
        flash('File missing on server!', 'danger')
        return redirect(url_for('home'))

    return send_from_directory(upload_dir, filename, as_attachment=True)

# -------------------- Delete --------------------
@app.route('/delete/<filename>')
def delete(filename):
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    if db is None:
        flash('Database unavailable.', 'danger')
        return redirect(url_for('home'))

    file_doc = files.find_one({'username': session['username'], 'filename': filename})
    if not file_doc:
        flash('File not found or unauthorized!', 'danger')
        return redirect(url_for('home'))

    files.delete_one({'_id': file_doc['_id']})
    upload_dir = app.config.get('UPLOADED_FILES_DEST', 'uploads')
    file_path = os.path.join(upload_dir, filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except OSError as e:
        print(f"Error removing file {file_path}: {e}")

    flash('File deleted successfully!', 'success')
    return redirect(url_for('home'))

# -------------------- Search --------------------
@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    form = SearchForm()
    uploaded_files = [] # Initialize as empty
    if form.validate_on_submit():
        query = form.query.data
        cursor = files.find({
            'username': session['username'],
            '$or': [
                {'original_filename': {'$regex': query, '$options': 'i'}},
                {'filename': {'$regex': query, '$options': 'i'}}
            ]
        }).sort('upload_date', -1)
        uploaded_files = list(cursor)
        if not uploaded_files:
            flash(f'No files found matching "{query}".', 'danger')
        else:
            flash(f'Found {len(uploaded_files)} files matching "{query}".', 'success')
    
    # CHANGED: Simplified logic - no need for an else block to fetch all files.
    return render_template('search.html', form=form, files=uploaded_files)

# -------------------- Forgot Password Route --------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = users.find_one({'email': email})
        if not user:
            flash('Email not found!', 'danger')
            return render_template('forgot_password.html', form=form)

        otp = f"{random.randint(100000, 999999)}"
        session['reset_otp'] = otp
        session['reset_user'] = email
        session['reset_otp_expires'] = time.time() + 5 * 60

        subject = "🔒 Password Reset OTP - File Upload & Management System"
        html_body = f"""
        <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 10px; overflow: hidden;">
            <div style="background-color: #4a76a8; padding: 20px; color: white; text-align: center;">
                <h2>File Upload & Management System</h2>
                <p>Password Reset Request</p>
            </div>
            <div style="padding: 20px;">
                <p>Hi <strong>{user['username']}</strong>,</p>
                <p>You requested to reset your password. Use the OTP below to reset it:</p>
                <h3 style="text-align:center; color: #4a76a8; font-size: 28px; letter-spacing: 4px;">{otp}</h3>
                <p style="text-align:center; color: #777;">This OTP will expire in 5 minutes.</p>
                <hr>
                <p style="font-size: 14px; color: #999;">If you did not request this, please ignore this email.</p>
            </div>
            <div style="background-color: #f7f7f7; padding: 15px; text-align: center; font-size: 12px; color: #555;">
                File Upload & Management System &copy; {datetime.datetime.now().year}
            </div>
        </div>
        """

        msg = Message(subject=subject,
                      sender=app.config.get('MAIL_DEFAULT_SENDER'),
                      recipients=[email],
                      html=html_body)

        try:
            mail.send(msg)
            flash('OTP sent to your registered email.', 'success')
            return redirect(url_for('reset_password'))
        except (smtplib.SMTPException, Exception) as e:
            print("Mail sending failed:", e)
            session.pop('reset_otp', None)
            session.pop('reset_user', None)
            session.pop('reset_otp_expires', None)
            flash('Failed to send OTP email. Please try again later.', 'danger')
            return render_template('forgot_password.html', form=form)

    return render_template('forgot_password.html', form=form)

# -------------------- Reset Password (verify & set) --------------------
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if 'reset_otp' not in session or 'reset_user' not in session or 'reset_otp_expires' not in session:
        flash('No active password reset request. Please request OTP first.', 'danger')
        return redirect(url_for('forgot_password'))

    if time.time() > session.get('reset_otp_expires', 0):
        session.pop('reset_otp', None)
        session.pop('reset_user', None)
        session.pop('reset_otp_expires', None)
        flash('OTP expired. Please request a new OTP.', 'danger')
        return redirect(url_for('forgot_password'))

    if form.validate_on_submit():
        entered_otp = form.otp.data.strip()
        if entered_otp != session.get('reset_otp'):
            flash('Invalid OTP!', 'danger')
            return render_template('reset_password.html', form=form)

        new_password = form.new_password.data
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        users.update_one({'email': session['reset_user']}, {'$set': {'password': hashed_password}})

        session.pop('reset_otp', None)
        session.pop('reset_user', None)
        session.pop('reset_otp_expires', None)

        flash('Password reset successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)

# -------------------- Run App --------------------
if __name__ == '__main__':
    app.run(debug=True)