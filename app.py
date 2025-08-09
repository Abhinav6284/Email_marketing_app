import os
import random
from datetime import datetime, date, timedelta, timezone
import csv
from io import StringIO
import secrets
from flask import (
    Flask, request, render_template, redirect,
    url_for, flash, session, make_response, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
import config

# Local imports from your files
from email_services import send_email_enhanced
from utils import encrypt_password, decrypt_password

# -----------------------------------------------------------------------------
# App & DB Setup
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
basedir = os.path.abspath(os.path.dirname(__file__))
# IMPORTANT: This uses MySQL. Ensure your MySQL server is running and the database 'markdb' exists.
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://markuser:StrongPass123@localhost:3306/markdb"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -----------------------------------------------------------------------------
# System SMTP (for built-in sending of OTPs etc.)
# -----------------------------------------------------------------------------
SMTP_SERVER = "server210.web-hosting.com"
SMTP_PORT = 465
SMTP_USER = "dev@corediva365.com"
SMTP_PASS = "akila@196f"
EMAIL_SIGNATURE = "\n--\nMark Team"


# -----------------------------------------------------------------------------
# Models (Corrected to match your markdb.sql schema and add profile pic)
# -----------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)

    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(100))
    is_2fa_enabled = db.Column(db.Boolean, default=True)
    login_otp = db.Column(db.String(6))
    login_otp_created = db.Column(db.DateTime)
    is_verified = db.Column(db.Boolean, default=False)
    smtp_email = db.Column(db.String(100))
    smtp_password = db.Column(db.String(500))
    smtp_server = db.Column(db.String(100))
    smtp_port = db.Column(db.Integer, default=465)
    smtp_sender_name = db.Column(db.String(100))
    use_custom_smtp = db.Column(db.Boolean, default=False)
    smtp_verified = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.LargeBinary(length=(2 ** 24)), nullable=True)
    profile_picture_mimetype = db.Column(db.String(100), nullable=True)
    reset_otp = db.Column(db.String(200))  # Hashed OTP
    reset_otp_expires = db.Column(db.DateTime)  # Expiry timestamp

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def generate_login_otp(self):
        otp = str(random.randint(100000, 999999))
        self.login_otp = otp
        self.login_otp_created = datetime.now(timezone.utc)
        return otp

    def verify_login_otp(self, code):
        if not self.login_otp or not self.login_otp_created: return False

        now_aware = datetime.now(timezone.utc)
        stored_time_aware = self.login_otp_created
        if stored_time_aware.tzinfo is None:
            stored_time_aware = stored_time_aware.replace(tzinfo=timezone.utc)

        if now_aware - stored_time_aware > timedelta(minutes=5): return False

        ok = self.login_otp == code
        if ok:
            self.login_otp = None
            self.login_otp_created = None
        return ok


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    contact = db.Column(db.String(100))
    email = db.Column(db.String(150), nullable=False)
    location = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    phone_number = db.Column(db.String(20))
    company_type = db.Column(db.String(100))
    file_data = db.Column(db.LargeBinary)
    file_name = db.Column(db.String(255))
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)


class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    recipient_count = db.Column(db.Integer, default=0)
    success_count = db.Column(db.Integer, default=0)
    failed_count = db.Column(db.Integer, default=0)
    attachments = db.Column(db.String(500))  # Add this line


# Helper Functions
def generate_otp(length=6):
    """Generate a secure OTP (e.g., '123456')."""
    return ''.join(secrets.choice('0123456789') for _ in range(length))

def hash_otp(otp):
    """Hash the OTP using Werkzeug's password hasher."""
    return generate_password_hash(otp)


def check_otp(user, otp_entered):
    """Check if the entered OTP matches the hashed OTP stored in the user."""
    if not user.reset_otp or not user.reset_otp_expires:
        return False

    # FIX: Make the database datetime "aware" of the UTC timezone before comparing
    if datetime.now(timezone.utc) > user.reset_otp_expires.replace(tzinfo=timezone.utc):
        flash("This OTP has expired.", "error")
        return False

    return check_password_hash(user.reset_otp, otp_entered)


def hash_password(password):
    """Hash password using Werkzeug."""
    return generate_password_hash(password)

# -----------------------------------------------------------------------------
# Login Manager & Mail Helpers
# -----------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def send_email(to_addr, subject, body, files=None, user=None):
    system_config = {
        'server': SMTP_SERVER,
        'port': SMTP_PORT,
        'user': SMTP_USER,
        'password': SMTP_PASS,
        'signature': EMAIL_SIGNATURE
    }
    # ADD THIS DEBUG CODE:
    print(f"🔧 SMTP Config: {SMTP_SERVER}:{SMTP_PORT}")
    print(f"🔧 Using Custom SMTP: {user.use_custom_smtp if user else False}")

    result = send_email_enhanced(to_addr, subject, body, files, user, system_config)

    success, message = result
    print(f"📧 Email Result: Success={success}, Message='{message}'")

    return result


def send_otp_email(user, otp, subject):
    body = f"Hello {user.first_name},\n\nYour verification code is: {otp}\n\nThis code expires in 5 minutes."
    # By removing `user=user`, we ensure the system email is always used for OTPs.
    return send_email(user.email, subject, body)


def _finish_login(user):
    login_user(user)
    session["user_name"] = user.get_full_name()
    session["user_email"] = user.email
    flash(f"Welcome back, {user.first_name}!", "success")
    return redirect(url_for("dashboard"))


def run_migrations():
    with app.app_context():
        try:
            inspector = db.inspect(db.engine)

            # Check user table columns
            user_columns = [c['name'].lower() for c in inspector.get_columns('user')]
            if 'reset_otp' not in user_columns:
                db.session.execute(text("ALTER TABLE user ADD COLUMN reset_otp VARCHAR(200)"))
                print("✅ Added column 'reset_otp' to 'user' table.")
            if 'reset_otp_expires' not in user_columns:
                db.session.execute(text("ALTER TABLE user ADD COLUMN reset_otp_expires DATETIME"))
                print("✅ Added column 'reset_otp_expires' to 'user' table.")

            # Check campaign table columns
            campaign_columns = [c['name'].lower() for c in inspector.get_columns('campaign')]
            if 'attachments' not in campaign_columns:
                db.session.execute(text("ALTER TABLE campaign ADD COLUMN attachments VARCHAR(500)"))
                print("✅ Added column 'attachments' to 'campaign' table.")

            db.session.commit()
            print("✅ Migration completed successfully.")

        except Exception as e:
            print(f"❌ Migration failed: {str(e)}")
            db.session.rollback()


# -----------------------------------------------------------------------------
# Main & Auth Routes
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    current_year = datetime.now().year
    return render_template("index.html", current_year=current_year)


# In app.py
# In app.py
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # --- Collect all data from the registration form ---
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        # username = request.form.get('username') # THIS LINE IS NOW REMOVED
        email = request.form.get('email')
        password = request.form.get('password')
        company = request.form.get('company')

        # --- CORRECTED validation check (no username) ---
        if not all([first_name, last_name, email, password]):
            print(">>> REASON: Validation failed. A required field is missing.")
            # CORRECTED the flash message
            flash('Please fill out all required fields: Name, Email, and Password.', 'error')
            return redirect(url_for('register'))

        # Check if user email already exists (this part is correct)
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            print(f">>> REASON: Email '{email}' already exists in the database.")
            flash('Email address already registered. Please log in.', 'error')
            return redirect(url_for('register'))

        print("--- All validation checks passed. Proceeding to OTP step. ---")

        # --- Generate OTP and store registration data in session (no username) ---
        otp = str(random.randint(100000, 999999))
        session['registration_data'] = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': password,
            'company': company,
            'otp': otp,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # This part for sending the email is correct as it doesn't use username
        class TempUser:
            def __init__(self, data):
                self.first_name = data.get('first_name')
                self.last_name = data.get('last_name', '')
                self.email = data.get('email')
                self.use_custom_smtp = False

            def get_full_name(self):
                return f"{self.first_name} {self.last_name}".strip()

        temp_user = TempUser(session['registration_data'])
        success, message = send_otp_email(temp_user, otp, "Your Mark Verification Code")

        if success:
            flash(f'A verification OTP has been sent to {email}.', 'info')
        else:
            flash(f"Error sending email: {message}", "error")
            flash(f"For testing, your OTP is: {otp}", "info")

        return redirect(url_for('verify_registration_otp'))

    return render_template('register.html')


@app.route("/verify-registration-otp", methods=["GET", "POST"])
def verify_registration_otp():
    """
    Handles the verification of the OTP sent during registration.
    It checks for session data, OTP expiry, and correctness.
    """
    # Redirect if there's no registration data in the session
    if 'registration_data' not in session:
        flash('Your registration session has expired. Please try again.', 'error')
        return redirect(url_for('register'))

    reg_data = session['registration_data']
    # **FIX**: Get the email from the session to display on the page
    email_for_display = reg_data.get('email')

    otp_timestamp = datetime.fromisoformat(reg_data['timestamp'])

    # Check if the OTP has expired (e.g., 5 minutes validity)
    if datetime.now(timezone.utc) > otp_timestamp + timedelta(minutes=5):
        session.pop('registration_data', None)  # Clear expired data
        flash('Your OTP has expired. Please register again.', 'error')
        return redirect(url_for('register'))

    if request.method == 'POST':
        submitted_otp = request.form.get('otp')
        # Check if the submitted OTP is correct (ensure both are strings or ints)
        if submitted_otp and int(submitted_otp) == int(reg_data['otp']):
            # OTP is correct, create the new user
            new_user = User(
                first_name=reg_data['first_name'],
                last_name=reg_data['last_name'],
                email=reg_data['email'],
                company=reg_data['company'],
                is_verified=True  # Mark user as verified
            )
            new_user.set_password(reg_data['password'])
            db.session.add(new_user)
            db.session.commit()

            # Clear the temporary registration data from the session
            session.pop('registration_data', None)

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'error')

    # **FIX**: Pass the email variable to the template
    return render_template('verify_registration_otp.html', email=email_for_display)


@app.route("/smtp-settings", methods=["GET", "POST"])
@login_required
def smtp_settings():
    if request.method == 'POST':
        action = request.form.get("action")
        if action == "save_smtp":
            send_method = request.form.get("send_method")

            if send_method == "custom":
                # STORE ACTUAL USER INPUT VALUES - NOT "CUSTOM"
                current_user.use_custom_smtp = True
                current_user.smtp_email = request.form.get("smtp_email")
                current_user.smtp_sender_name = request.form.get("smtp_sender_name")
                current_user.smtp_port = int(request.form.get("smtp_port", 587))

                # Handle server selection vs custom server input
                selected_server = request.form.get("smtp_server")
                if selected_server == "custom":
                    # User selected "Other/Custom" - get custom server value
                    current_user.smtp_server = request.form.get("custom_smtp_server")
                else:
                    # User selected a predefined server (Gmail, Outlook, Yahoo)
                    current_user.smtp_server = selected_server

                # Encrypt and store password
                password = request.form.get("smtp_password")
                if password:
                    current_user.smtp_password = encrypt_password(password)

                current_user.smtp_verified = False

            else:  # send_method == "builtin"
                # Use system SMTP settings
                current_user.use_custom_smtp = False
                current_user.smtp_server = "server210.web-hosting.com"  # Your system server
                current_user.smtp_port = 587
                current_user.smtp_email = "dev@corediva365.com"  # Your system email
                current_user.smtp_sender_name = current_user.get_full_name()
                current_user.smtp_verified = True

            db.session.commit()
            flash('SMTP settings saved successfully!', 'success')

        return redirect(url_for('smtp_settings'))

    # For GET request - display current decrypted password
    decrypted_pass = ""
    if current_user.smtp_password:
        try:
            decrypted_pass = decrypt_password(current_user.smtp_password)
        except Exception:
            decrypted_pass = ""

    return render_template("smtp_settings.html", decrypted_pass=decrypted_pass)


@app.route("/debug-smtp")
@login_required
def debug_smtp():
    return f"""
    <h2>SMTP Debug Info</h2>
    <p><strong>use_custom_smtp:</strong> {current_user.use_custom_smtp}</p>
    <p><strong>smtp_verified:</strong> {current_user.smtp_verified}</p>
    <p><strong>smtp_server:</strong> {current_user.smtp_server}</p>
    <p><strong>smtp_email:</strong> {current_user.smtp_email}</p>
    <p><strong>smtp_port:</strong> {current_user.smtp_port}</p>
    <p><strong>smtp_sender_name:</strong> {current_user.smtp_sender_name}</p>
    """

    print("=" * 50)
    print(f"User Custom SMTP: {current_user.use_custom_smtp}")
    print(f"Custom Server: {current_user.smtp_server}")
    print(f"Custom Port: {current_user.smtp_port}")
    print(f"System Server: {SMTP_SERVER}")
    print(f"System Port: {SMTP_PORT}")
    print("=" * 50)
    return f"Debug info printed to console. Check your terminal."


def send_login_otp_email(user, otp):
    subj = "Mark – Login Verification Code"
    body = (
        f"Hello {user.first_name},\n\n"
        f"Your Mark login code is: {otp}\n\n"
        "This code expires in 5 minutes.\n\n"
        "If you did not try to sign in, please ignore this e-mail."
    )
    # Use enhanced function that supports custom SMTP
    success, message = send_email_enhanced(user.email, subj, body, user=current_user)
    return success

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        # Check if the user exists and the password is correct
        if user and check_password_hash(user.password_hash, password):

            # --- NEW: 2-FACTOR AUTHENTICATION LOGIC ---
            # Check if 2FA is enabled for this user
            if user.is_2fa_enabled:
                # 1. Generate and save the OTP to the database
                otp = user.generate_login_otp()
                db.session.commit()

                # 2. Send the OTP to the user's email
                send_otp_email(user, otp, "Your Login Verification Code")
                flash("A verification code has been sent to your email.", "info")

                # 3. Store the user's ID to verify on the next screen and redirect
                session['pending_uid'] = user.id
                return redirect(url_for('login_otp'))
            else:
                # If 2FA is not enabled, log them in directly
                return _finish_login(user)
            # --- END OF NEW LOGIC ---

        flash("Invalid email or password.", "error")

    return render_template('login.html')


@app.route("/login-otp", methods=["GET", "POST"])
def login_otp():
    uid = session.get("pending_uid")
    if not uid: return redirect(url_for("login"))
    user = db.session.get(User, uid)
    if not user: return redirect(url_for("login"))
    if request.method == "POST":
        if user.verify_login_otp(request.form.get("otp", "")):
            db.session.commit()
            session.pop("pending_uid", None)
            return _finish_login(user)
        else:
            flash("Invalid or expired code.", "error")
    return render_template("login_otp.html", user=user)


@app.route('/resend-login-otp')
def resend_login_otp():
    uid = session.get('pending_uid')
    if not uid: return redirect(url_for('login'))
    user = db.session.get(User, uid)
    if not user: return redirect(url_for('login'))
    otp = user.generate_login_otp()
    db.session.commit()
    success, message = send_otp_email(user, otp, "Your New Mark Login Code")
    if success:
        flash("A new verification code has been sent.", "success")
    else:
        flash(f"Failed to send code. Reason: {message}", "error")
    return redirect(url_for('login_otp'))


@app.route('/fix-smtp')
@login_required
def fix_smtp():
    current_user.use_custom_smtp = False
    current_user.smtp_verified = False
    db.session.commit()
    return f"✅ Fixed! Custom SMTP disabled. use_custom_smtp: {current_user.use_custom_smtp}"

# In app.py

@app.route('/resend-registration-otp')
def resend_registration_otp():
    """
    Resends the OTP for registration if the session is still valid.
    """
    if 'registration_data' not in session:
        flash('Your registration session has expired. Please try again.', 'error')
        return redirect(url_for('register'))

    reg_data = session['registration_data']

    # Generate a new OTP and update the timestamp
    new_otp = str(random.randint(100000, 999999))
    reg_data['otp'] = new_otp
    reg_data['timestamp'] = datetime.now(timezone.utc).isoformat()
    session['registration_data'] = reg_data

    # --- FIX: Create a TempUser class that mimics the real User object ---
    class TempUser:
        def __init__(self, data):
            self.first_name = data.get('first_name')
            self.last_name = data.get('last_name', '')
            self.email = data.get('email')
            self.use_custom_smtp = False

        def get_full_name(self):
            return f"{self.first_name} {self.last_name}".strip()
    # --- END FIX ---

    temp_user = TempUser(reg_data)

    success, message = send_otp_email(temp_user, new_otp, "Your New Mark Verification Code")

    if success:
        flash("A new verification code has been sent to your email.", "success")
    else:
        flash(f"Failed to send the code. Reason: {message}", "error")
        flash(f"For testing, your new OTP is: {new_otp}", "info")

    return redirect(url_for('verify_registration_otp'))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


# -----------------------------------------------------------------------------
# User Profile & Settings Routes
# -----------------------------------------------------------------------------
@app.route('/user-avatar')
@login_required
def user_avatar():
    if not current_user.profile_picture:
        return redirect(url_for('static', filename='images/default_avatar.png'))
    response = make_response(current_user.profile_picture)
    response.headers.set('Content-Type', current_user.profile_picture_mimetype or 'image/jpeg')
    return response


@app.route('/profile-settings', methods=['GET', 'POST'])
@login_required
def profile_settings():
    if request.method == 'POST':
        new_first_name = request.form.get('first_name', '').strip()
        new_last_name = request.form.get('last_name', '').strip()

        # Only update name if new, non-empty values are provided
        if new_first_name and new_last_name:
            current_user.first_name = new_first_name
            current_user.last_name = new_last_name
            session['user_name'] = current_user.get_full_name()

        picture = request.files.get('profile_picture')
        if picture and picture.filename != '':
            # FIX: File size limit has been removed.
            image_data = picture.read()
            current_user.profile_picture = image_data
            current_user.profile_picture_mimetype = picture.mimetype

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile_settings'))

    return render_template('profile_settings.html')



@app.route('/chart-data')
@login_required
def chart_data():
    """Provides data for the customizable date range chart."""
    start_date_str = request.args.get('start')
    end_date_str = request.args.get('end')

    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        # Default to the last 7 days if dates are invalid
        today = datetime.now(timezone.utc).date()
        start_date = today - timedelta(days=6)
        end_date = today

    # Generate all dates in the range for the labels
    delta = end_date - start_date
    date_range = [start_date + timedelta(days=i) for i in range(delta.days + 1)]

    # Create a dictionary to hold daily counts, initialized to zero
    daily_counts = {date.strftime('%a, %b %d'): 0 for date in date_range}

    # Query the database for campaigns within the date range
    campaigns_in_range = Campaign.query.filter(
        Campaign.user_id == current_user.id,
        db.func.date(Campaign.sent_at) >= start_date,
        db.func.date(Campaign.sent_at) <= end_date
    ).all()

    # Populate the dictionary with actual data
    for campaign in campaigns_in_range:
        day_key = campaign.sent_at.strftime('%a, %b %d')
        if day_key in daily_counts:
            daily_counts[day_key] += campaign.success_count or 0

    chart_labels = list(daily_counts.keys())
    chart_data = list(daily_counts.values())

    return jsonify(labels=chart_labels, data=chart_data)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        otp_entered = request.form.get('otp')
        user = User.query.filter_by(email=email).first()
        # Validate OTP
        if user and check_otp(user, otp_entered) and user.reset_otp_expires > datetime.utcnow():
            # User is valid, render new password form
            return render_template('set_new_password.html', email=email, otp=otp_entered)
        error = "Invalid or expired OTP."
        return render_template('reset_password.html', error=error)
    return render_template('reset_password.html')


# In app.py

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            otp = generate_otp()
            user.reset_otp = hash_otp(otp)
            user.reset_otp_expires = datetime.now(timezone.utc) + timedelta(minutes=10)  # 10-minute validity
            db.session.commit()

            # Send the email
            success, message = send_email(
                user.email,
                "Password Reset Code",
                f"Your password reset code is: {otp}. It will expire in 10 minutes."
            )

            if success:
                success, message = send_email(  # This overwrites the previous result!
                    user.email,
                    "Password Reset OTP",
                    f"Your password reset OTP is: {otp}. This code expires in 15 minutes.",
                    user=user
                )


            else:
                # Show a user-friendly error without revealing the OTP
                flash("We had a problem sending your reset code. Please try again.", "error")

            # --- FIX: Store email in session and redirect to the OTP entry page ---
            session['reset_email'] = email
            return redirect(url_for('verify_otp'))

        # If user does not exist, show a generic message to prevent user enumeration
        flash("If an account with that email exists, a reset code has been sent.", "info")
        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


# In app.py

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # Get the email from the session
    email = session.get('reset_email')
    if not email:
        flash("Your session has expired. Please start over.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        otp_entered = request.form.get('otp')
        user = User.query.filter_by(email=email).first()

        # Use the check_otp helper which also checks expiry
        if user and check_otp(user, otp_entered):
            # OTP is correct. Store it in the session to re-verify on the final step
            # and redirect to the new password form.
            session['verified_otp'] = otp_entered
            flash("Verification successful. Please set your new password.", "success")
            return redirect(url_for('set_new_password'))

        flash("The code you entered is invalid or has expired.", "error")
        return redirect(url_for('verify_otp'))

    # For a GET request, just show the page
    return render_template('enter_otp.html', email=email)
# In app.py

@app.route('/set-new-password', methods=['GET', 'POST'])
def set_new_password():
    email = session.get('reset_email')
    otp = session.get('verified_otp')

    # Security check: ensure user has completed previous steps
    if not email or not otp:
        flash("Invalid request. Please start the password reset process again.", "error")
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for('set_new_password'))

        # Final check of the OTP before changing password
        if user and check_otp(user, otp):
            user.password_hash = hash_password(new_password)
            user.reset_otp = None  # Invalidate the OTP
            user.reset_otp_expires = None
            db.session.commit()

            # Clean up the session
            session.pop('reset_email', None)
            session.pop('verified_otp', None)

            flash("Your password has been updated successfully. Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Your password reset request was invalid or has expired. Please try again.", "error")
            return redirect(url_for('forgot_password'))

    # For a GET request, show the form
    return render_template('set_new_password.html', email=email)


@app.route("/test-smtp", methods=["POST"])
@login_required
def test_smtp():
    """Test custom SMTP settings and mark as verified if successful"""
    if not current_user.use_custom_smtp:
        return jsonify({"success": False, "message": "Custom SMTP not enabled"})

    try:
        test_subject = "SMTP Test - Mark Email Marketing"
        test_body = f"Hello {current_user.first_name},\n\nThis is a test email to verify your SMTP settings.\n\nIf you receive this, your custom SMTP is working!"

        # Force use of custom SMTP for testing (bypass verification)
        success, message = send_email_enhanced(
            current_user.email,
            test_subject,
            test_body,
            user=current_user,
            force_custom=True  # This is the key!
        )

        if success:
            # Mark SMTP as verified
            current_user.smtp_verified = True
            db.session.commit()
            return jsonify({"success": True, "message": "SMTP test successful! Custom SMTP is now active."})
        else:
            return jsonify({"success": False, "message": f"SMTP test failed: {message}"})

    except Exception as e:
        return jsonify({"success": False, "message": f"SMTP test error: {str(e)}"})



# -----------------------------------------------------------------------------
# Dashboard & Core App Routes
# -----------------------------------------------------------------------------
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    uid = current_user.id
    if request.method == "POST":
        f = request.form

        # --- Handle Add Contact ---
        if "add_contact" in f:
            ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
            uploaded_file = request.files.get('file_data')
            file_data = None
            file_name = None
            file_type = None
            file_size = None

            if uploaded_file and uploaded_file.filename != '':
                # Check if the file type is allowed
                file_extension = uploaded_file.filename.rsplit('.', 1)[1].lower()
                if file_extension not in ALLOWED_EXTENSIONS:
                    flash(f"Invalid file type. Please upload a PNG or JPG file.", "error")
                    return redirect(url_for("dashboard"))

                file_data = uploaded_file.read()
                file_name = uploaded_file.filename
                file_type = uploaded_file.mimetype
                file_size = len(file_data)

            new_c = Contact(
                date=date.today(),
                company_name=f.get("company_name"),
                email=f.get("email"),
                contact=f.get("contact"),
                phone_number=f.get("phone_number"),
                company_type=f.get("company_type"),
                location=f.get("location"),
                user_id=uid
            )
            db.session.add(new_c)
            db.session.commit()
            flash("Contact added!", "success")
            return redirect(url_for("dashboard"))

        # --- Handle Delete Contact ---
        if "delete_contact" in f:
            contact_to_delete = db.session.get(Contact, int(f.get("contact_id")))
            if contact_to_delete and contact_to_delete.user_id == uid:
                db.session.delete(contact_to_delete)
                db.session.commit()
                flash("Contact deleted.", "success")
            return redirect(url_for("dashboard"))

        if "send_email" in f:
            send_option = f.get('send_to_option')
            contacts_to_send = []

            if send_option == 'all':
                # Option 1: User chose to send to all contacts
                contacts_to_send = Contact.query.filter_by(user_id=uid).all()

            elif send_option == 'selected':
                # Option 2: User chose to send to selected contacts
                selected_ids = request.form.getlist('selected_contacts')
                if not selected_ids:
                    flash(
                        "You selected 'Selected Contacts' but did not choose any. Please select at least one contact.",
                        "error")
                    return redirect(url_for('dashboard'))

                # Securely query for the selected contacts belonging to the current user
                contacts_to_send = Contact.query.filter(
                    Contact.id.in_(selected_ids),
                    Contact.user_id == uid
                ).all()

            if not contacts_to_send:
                flash("No contacts to send campaign to.", "warning")
                return redirect(url_for('dashboard'))

            subject = f.get('subject')
            message = f.get('message')

            attachment_file = request.files.get('attachments')
            attachment_data = None
            attachment_filename = None
            attachment_mimetype = None

            if attachment_file and attachment_file.filename != '':
                attachment_data = attachment_file.read()
                attachment_filename = attachment_file.filename
                attachment_mimetype = attachment_file.mimetype

            camp = Campaign(
                user_id=uid,
                subject=subject,
                message=message,
                recipient_count=len(contacts_to_send)
            )
            db.session.add(camp)
            db.session.flush()

            sent = failed = 0
            for c in contacts_to_send:
                success, error_msg = send_email(
                    c.email,
                    subject,
                    message,
                    files=[(attachment_data, attachment_filename, attachment_mimetype)] if attachment_data else None,
                    user=current_user
                )
                if success:
                    sent += 1
                else:
                    failed += 1

            camp.success_count = sent
            camp.failed_count = failed
            db.session.commit()
            flash(f"Campaign finished: {sent} sent, {failed} failed.", "success")
            return redirect(url_for('dashboard'))

    # --- GET REQUEST LOGIC (runs when the page is loaded) ---
    Contact.query.filter_by(user_id=uid).order_by(Contact.id.desc()).all()
    total_campaigns = Campaign.query.filter_by(user_id=uid).count()
    total_emails_sent = db.session.query(db.func.sum(Campaign.success_count)).filter_by(user_id=uid).scalar() or 0

    # FIXED: Fetch campaigns for display in Campaign History
    campaigns = Campaign.query.filter_by(user_id=uid).order_by(Campaign.sent_at.desc()).all()

    successful_campaigns = Campaign.query.filter(Campaign.user_id == uid, Campaign.success_count > 0).count()
    failed_campaigns = Campaign.query.filter(Campaign.user_id == uid, Campaign.failed_count > 0).count()
    contacts_added_today = Contact.query.filter(Contact.user_id == uid, Contact.date == date.today()).count()

    # Chart data logic (existing code)...
    today = datetime.now(timezone.utc).date()
    seven_days_ago = today - timedelta(days=6)
    daily_counts = {(seven_days_ago + timedelta(days=i)).strftime('%a, %b %d'): 0 for i in range(7)}
    campaigns_in_last_week = Campaign.query.filter(Campaign.user_id == uid, Campaign.sent_at >= seven_days_ago).all()

    for campaign in campaigns_in_last_week:
        campaign_date = campaign.sent_at.date() if isinstance(campaign.sent_at, datetime) else campaign.sent_at
        day_key = campaign_date.strftime('%a, %b %d')
        if day_key in daily_counts:
            daily_counts[day_key] += campaign.success_count or 0

    chart_labels = list(daily_counts.keys())
    chart_data = list(daily_counts.values())
    contacts = Contact.query.filter_by(user_id=uid).order_by(Contact.id.desc()).all()

    # FIXED: Add campaigns to the return statement
    return render_template(
        "dashboard.html",
        contacts=contacts,
        total_contacts=len(contacts),
        total_campaigns=total_campaigns,
        total_emails_sent=total_emails_sent,
        campaigns=campaigns,  # <-- ADD THIS LINE!
        successful_campaigns=successful_campaigns,
        failed_campaigns=failed_campaigns,
        contacts_added_today=contacts_added_today,
        chart_labels=chart_labels,
        chart_data=chart_data
    )
@app.route("/export-contacts")
@login_required
def export_contacts():
    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Company Name', 'Contact Person', 'Email', 'Phone', 'Type', 'Location'])
    for contact in contacts:
        writer.writerow([
            contact.company_name, contact.contact, contact.email,
            contact.phone_number, contact.company_type, contact.location
        ])
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=contacts.csv'
    response.headers['Content-type'] = 'text/csv'
    return response


# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        run_migrations()
    print("🚀 Mark Email Marketing Application Started!")
    app.run(debug=True, host="0.0.0.0", port=5000)