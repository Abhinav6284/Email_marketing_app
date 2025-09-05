from datetime import date, timedelta, datetime, timezone
import os
import random
from datetime import datetime, date, timedelta, timezone
import csv
import io
from io import StringIO
import secrets
from flask import (
    Blueprint, request, render_template, redirect,
    url_for, flash, session, make_response, jsonify
)
from mark_app.whatsapp_routes import whatsapp_bp    
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from . import config
import pandas as pd
from .email_services import send_email_enhanced
from .utils import encrypt_password, decrypt_password
from . import db
from .models import User, Contact, Campaign, EmailReply
from flask import Blueprint, jsonify
from flask import Blueprint, redirect, url_for, flash
from mark_app.reply_email import fetch_replies
from mark_app.models import db

main_bp = Blueprint('main', __name__)



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


# 1. Added reply_to_addr here
def send_email(to_addr, subject, body, files=None, user=None, reply_to_addr=None):
    system_config = {
        'server': SMTP_SERVER,
        'port': SMTP_PORT,
        'user': SMTP_USER,
        'password': SMTP_PASS,
        'signature': EMAIL_SIGNATURE
    }
    print(f"🔧 SMTP Config: {SMTP_SERVER}:{SMTP_PORT}")
    print(f"🔧 Using Custom SMTP: {user.use_custom_smtp if user else False}")

    # 2. Pass reply_to_addr to the enhanced function
    result = send_email_enhanced(
        to_addr, subject, body, files, user, system_config, reply_to_addr)

    success, message = result
    print(f"📧 Email Result: Success={success}, Message='{message}'")

    return result


def send_otp_email(user, otp, subject):
    body = f"Hello {user.first_name},\n\nYour verification code is: {otp}\n\nThis code expires in 5 minutes."
    # By removing `user=user`, we ensure the system email is always used for OTPs.
    return send_email(user.email, subject, body)


def _finish_login(user, remember=False):
    login_user(user, remember=remember)
    session["user_name"] = user.get_full_name()
    session["user_email"] = user.email
    flash(f"Welcome back, {user.first_name}!", "success")
    return redirect(url_for("main.dashboard"))

# -----------------------------------------------------------------------------
# Main & Auth Routes
# -----------------------------------------------------------------------------
@main_bp.route("/get_replies", methods=["GET"])
def get_replies():
    sender_email = request.args.get("sender_email")

    query = EmailReply.query.filter_by(user_id=current_user.id)

    if sender_email:
        query = query.filter_by(sender_email=sender_email)

    replies = query.order_by(EmailReply.received_at.desc()).all()

    return jsonify([
        {
            "id": r.id,
            "sender_name": r.sender_name,
            "sender_email": r.sender_email,
            "subject": r.subject,
            "body": r.body,
            "received_at": r.received_at.strftime("%Y-%m-%d %H:%M")
        } for r in replies
    ])
    
@main_bp.route("/fetch-replies")
@login_required
def fetch_replies_route():
    try:
        # Pass the current user's ID to fetch_replies
        result = fetch_replies(user_id=current_user.id)
        flash(result, "success")  # fetch_replies now returns a string message
    except Exception as e:
        flash(f"Error fetching replies: {str(e)}", "danger")
    return redirect(url_for("main.dashboard"))

@main_bp.route("/")
def index():
    current_year = datetime.now().year
    return render_template("index.html", current_year=current_year)



@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        # --- Collect all data from the registration form ---
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        # username = request.form.get('username') # THIS LINE IS NOW REMOVED
        email = request.form.get('email')
        password = request.form.get('password')
        company = request.form.get('company')
        mobile_number = request.form.get('mobile_number')
        company_address = request.form.get('company_address')
        how_did_you_hear = request.form.get('how_did_you_hear')

        # --- CORRECTED validation check (no username) ---
        if not all([first_name, last_name, email, password, company, mobile_number, company_address, how_did_you_hear]):
            print(">>> REASON: Validation failed. A required field is missing.")
            # CORRECTED the flash message
            flash(
                'Please fill out all required fields.', 'error')
            return redirect(url_for('main.register'))

        # Check if user email already exists (this part is correct)
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            print(
                f">>> REASON: Email '{email}' already exists in the database.")
            flash('Email address already registered. Please log in.', 'error')
            return redirect(url_for('main.register'))

        print("--- All validation checks passed. Proceeding to OTP step. ---")

        # --- Generate OTP and store registration data in session (no username) ---
        otp = str(random.randint(100000, 999999))
        session['registration_data'] = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': password,
            'company': company,
            'mobile_number': mobile_number,
            'company_address': company_address,
            'how_did_you_hear': how_did_you_hear,
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
        success, message = send_otp_email(
            temp_user, otp, "Your Mark Verification Code")

        if success:
            flash(f'A verification OTP has been sent to {email}.', 'info')
        else:
            flash(f"Error sending email: {message}", "error")
            flash(f"For testing, your OTP is: {otp}", "info")

        return redirect(url_for('main.verify_registration_otp'))

    return render_template('register.html')


@main_bp.route("/verify-registration-otp", methods=["GET", "POST"])
def verify_registration_otp():
    """
    Handles the verification of the OTP sent during registration.
    It checks for session data, OTP expiry, and correctness.
    """
    # Redirect if there's no registration data in the session
    if 'registration_data' not in session:
        flash('Your registration session has expired. Please try again.', 'error')
        return redirect(url_for('main.register'))

    reg_data = session['registration_data']
    # **FIX**: Get the email from the session to display on the page
    email_for_display = reg_data.get('email')

    otp_timestamp = datetime.fromisoformat(reg_data['timestamp'])

    # Check if the OTP has expired (e.g., 5 minutes validity)
    if datetime.now(timezone.utc) > otp_timestamp + timedelta(minutes=5):
        session.pop('registration_data', None)  # Clear expired data
        flash('Your OTP has expired. Please register again.', 'error')
        return redirect(url_for('main.register'))

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
                mobile_number=reg_data['mobile_number'],
                company_address=reg_data['company_address'],
                how_did_you_hear=reg_data['how_did_you_hear'],
                is_verified=True  # Mark user as verified
            )
            new_user.set_password(reg_data['password'])
            db.session.add(new_user)
            db.session.commit()

            # Clear the temporary registration data from the session
            session.pop('registration_data', None)

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('main.login'))
        else:
            flash('Invalid OTP. Please try again.', 'error')

    # **FIX**: Pass the email variable to the template
    return render_template('verify_registration_otp.html', email=email_for_display)


@main_bp.route("/download-template")
@login_required
def download_template():
    """Generates and serves a CSV template file for contact import."""

    # 1. Use StringIO to create an in-memory text buffer
    output = io.StringIO()

    # 2. Use the csv library to write to the buffer
    writer = csv.writer(output)

    # 3. Write the header row. These are the EXACT columns the user needs to fill.
    header = [
        'Company Name', 'Email', 'Contact Person',
        'Phone Number', 'Company Type', 'Location'
    ]
    writer.writerow(header)

    # 4. Create a Flask response
    response = make_response(output.getvalue())

    # 5. Set the headers to trigger a browser download
    response.headers["Content-Disposition"] = "attachment; filename=contacts_template.csv"
    response.headers["Content-type"] = "text/csv"

    return response


@main_bp.route("/smtp-settings", methods=["GET", "POST"])
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
                current_user.smtp_sender_name = request.form.get(
                    "smtp_sender_name")
                current_user.smtp_port = int(
                    request.form.get("smtp_port", 587))

                # Handle server selection vs custom server input
                selected_server = request.form.get("smtp_server")
                if selected_server == "custom":
                    # User selected "Other/Custom" - get custom server value
                    current_user.smtp_server = request.form.get(
                        "custom_smtp_server")
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

        return redirect(url_for('main.smtp_settings'))

    # For GET request - display current decrypted password
    decrypted_pass = ""
    if current_user.smtp_password:
        try:
            decrypted_pass = decrypt_password(current_user.smtp_password)
        except Exception:
            decrypted_pass = ""

    return render_template("smtp_settings.html", decrypted_pass=decrypted_pass)


@main_bp.route("/debug-smtp")
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
    success, message = send_email_enhanced(
        user.email, subj, body, user=current_user)
    return success


@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember')  # Get remember me checkbox
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

                # 3. Store the user's ID and remember preference to verify on the next screen and redirect
                session['pending_uid'] = user.id
                session['remember_user'] = bool(remember)  # Store remember preference
                return redirect(url_for('main.login_otp'))
            else:
                # If 2FA is not enabled, log them in directly
                return _finish_login(user, remember=bool(remember))
            # --- END OF NEW LOGIC ---

        flash("Invalid email or password.", "error")

    return render_template('login.html')


@main_bp.route("/login-otp", methods=["GET", "POST"])
def login_otp():
    uid = session.get("pending_uid")
    if not uid:
        return redirect(url_for("main.login"))
    user = db.session.get(User, uid)
    if not user:
        return redirect(url_for("main.login"))
    if request.method == "POST":
        if user.verify_login_otp(request.form.get("otp", "")):
            db.session.commit()
            remember = session.pop("remember_user", False)  # Get and remove remember preference
            session.pop("pending_uid", None)
            return _finish_login(user, remember=remember)
        else:
            flash("Invalid or expired code.", "error")
    return render_template("login_otp.html", user=user)


@main_bp.route('/resend-login-otp')
def resend_login_otp():
    uid = session.get('pending_uid')
    if not uid:
        return redirect(url_for('main.login'))
    user = db.session.get(User, uid)
    if not user:
        return redirect(url_for('main.login'))
    otp = user.generate_login_otp()
    db.session.commit()
    success, message = send_otp_email(user, otp, "Your New Mark Login Code")
    if success:
        flash("A new verification code has been sent.", "success")
    else:
        flash(f"Failed to send code. Reason: {message}", "error")
    return redirect(url_for('main.login_otp'))


@main_bp.route('/fix-smtp')
@login_required
def fix_smtp():
    current_user.use_custom_smtp = False
    current_user.smtp_verified = False
    db.session.commit()
    return f"✅ Fixed! Custom SMTP disabled. use_custom_smtp: {current_user.use_custom_smtp}"


# In app.py

@main_bp.route('/resend-registration-otp')
def resend_registration_otp():
    """
    Resends the OTP for registration if the session is still valid.
    """
    if 'registration_data' not in session:
        flash('Your registration session has expired. Please try again.', 'error')
        return redirect(url_for('main.register'))

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

    success, message = send_otp_email(
        temp_user, new_otp, "Your New Mark Verification Code")

    if success:
        flash("A new verification code has been sent to your email.", "success")
    else:
        flash(f"Failed to send the code. Reason: {message}", "error")
        flash(f"For testing, your new OTP is: {new_otp}", "info")

    return redirect(url_for('main.verify_registration_otp'))


@main_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("main.index"))


# -----------------------------------------------------------------------------
# User Profile & Settings Routes
# -----------------------------------------------------------------------------
@main_bp.route('/user-avatar')
@login_required
def user_avatar():
    if not current_user.profile_picture:
        return redirect(url_for('main.static', filename='images/default_avatar.png'))
    response = make_response(current_user.profile_picture)
    response.headers.set(
        'Content-Type', current_user.profile_picture_mimetype or 'image/jpeg')
    return response


@main_bp.route('/profile-settings', methods=['GET', 'POST'])
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

        # Update new profile fields
        current_user.company = request.form.get('company', '').strip()
        current_user.mobile_number = request.form.get('mobile_number', '').strip()
        current_user.company_address = request.form.get('company_address', '').strip()
        current_user.how_did_you_hear = request.form.get('how_did_you_hear', '').strip()

        picture = request.files.get('profile_picture')
        if picture and picture.filename != '':
            # FIX: File size limit has been removed.
            image_data = picture.read()
            current_user.profile_picture = image_data
            current_user.profile_picture_mimetype = picture.mimetype

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('main.profile_settings'))

    return render_template('profile_settings.html')


@main_bp.route('/chart-data')
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
    date_range = [start_date + timedelta(days=i)
                  for i in range(delta.days + 1)]

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


@main_bp.route('/reset-password', methods=['GET', 'POST'])
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

@main_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            otp = generate_otp()
            user.reset_otp = hash_otp(otp)
            user.reset_otp_expires = datetime.now(
                timezone.utc) + timedelta(minutes=10)  # 10-minute validity
            db.session.commit()

            # Send the email
            success, message = send_email(
                user.email,
                "Password Reset Code",
                f"Your password reset code is: {otp}. It will expire in 10 minutes."
            )

            if success:
                flash("If an account with that email exists, a reset code has been sent.", "info")
            else:
                # Show a user-friendly error without revealing the OTP
                flash(
                    "We had a problem sending your reset code. Please try again.", "error")

            # --- FIX: Store email in session and redirect to the OTP entry page ---
            session['reset_email'] = email
            return redirect(url_for('main.verify_otp'))

        # If user does not exist, show a generic message to prevent user enumeration
        flash("If an account with that email exists, a reset code has been sent.", "info")
        return redirect(url_for('main.forgot_password'))

    return render_template('forgot_password.html')


# In app.py

@main_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # Get the email from the session
    email = session.get('reset_email')
    if not email:
        flash("Your session has expired. Please start over.", "error")
        return redirect(url_for('main.forgot_password'))

    if request.method == 'POST':
        otp_entered = request.form.get('otp')
        user = User.query.filter_by(email=email).first()

        # Use the check_otp helper which also checks expiry
        if user and check_otp(user, otp_entered):
            # OTP is correct. Store it in the session to re-verify on the final step
            # and redirect to the new password form.
            session['verified_otp'] = otp_entered
            flash("Verification successful. Please set your new password.", "success")
            return redirect(url_for('main.set_new_password'))

        flash("The code you entered is invalid or has expired.", "error")
        return redirect(url_for('main.verify_otp'))

    # For a GET request, just show the page
    return render_template('enter_otp.html', email=email)


# In app.py

@main_bp.route('/set-new-password', methods=['GET', 'POST'])
def set_new_password():
    email = session.get('reset_email')
    otp = session.get('verified_otp')

    # Security check: ensure user has completed previous steps
    if not email or not otp:
        flash("Invalid request. Please start the password reset process again.", "error")
        return redirect(url_for('main.forgot_password'))

    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for('main.set_new_password'))

        # Final check of the OTP before changing password
        if user and check_otp(user, otp):
            user.password_hash = hash_password(new_password)
            user.reset_otp = None  # Invalidate the OTP
            user.reset_otp_expires = None
            db.session.commit()

            # Clean up the session
            session.pop('reset_email', None)
            session.pop('verified_otp', None)

            flash(
                "Your password has been updated successfully. Please log in.", "success")
            return redirect(url_for('main.login'))
        else:
            flash(
                "Your password reset request was invalid or has expired. Please try again.", "error")
            return redirect(url_for('main.forgot_password'))

    # For a GET request, show the form
    return render_template('set_new_password.html', email=email)


@main_bp.route("/test-smtp", methods=["POST"])
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


# In app.py, replace your old dashboard function with this one
# Make sure you have these imports at the top of app.py


# ... (rest of your imports) ...

@main_bp.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    uid = current_user.id

    # =========================================================================
    #  HANDLE ALL FORM SUBMISSIONS (POST REQUESTS)
    # =========================================================================
    if request.method == "POST":
        form_data = request.form

        # --- Handle Add Single Contact ---
        if "add_contact" in form_data:
            new_contact = Contact(
                date=date.today(),
                company_name=form_data.get("company_name"),
                email=form_data.get("email"),
                contact=form_data.get("contact"),
                phone_number=form_data.get("phone_number"),
                company_type=form_data.get("company_type"),
                location=form_data.get("location"),
                user_id=uid
            )
            db.session.add(new_contact)
            db.session.commit()
            flash("Contact added successfully!", "success")
            return redirect(url_for("main.dashboard"))

        # --- Handle Edit Contact ---
        if "edit_contact" in form_data:
            contact_id = form_data.get("contact_id")
            contact = Contact.query.filter_by(id=contact_id, user_id=uid).first()
            
            if contact:
                contact.company_name = form_data.get("company_name")
                contact.contact = form_data.get("contact")
                contact.email = form_data.get("email")
                contact.phone_number = form_data.get("phone_number")
                contact.company_type = form_data.get("company_type")
                contact.location = form_data.get("location")
                
                db.session.commit()
                flash("Contact updated successfully!", "success")
            else:
                flash("Contact not found or access denied.", "error")
            return redirect(url_for("main.dashboard"))

        if "import_contacts" in form_data:
            uploaded_file = request.files.get('file')

            if not uploaded_file or uploaded_file.filename == '':
                flash("No file was selected for import.", "error")
                return redirect(url_for("dashboard"))

            filename = uploaded_file.filename
            try:
                if filename.endswith('.csv'):
                    df = pd.read_csv(uploaded_file.stream, dtype=str)
                elif filename.endswith('.xlsx'):
                    df = pd.read_excel(uploaded_file.stream, dtype=str)
                else:
                    flash(
                        "Invalid file type. Please upload the CSV or XLSX template.", "error")
                    return redirect(url_for("dashboard"))

                df = df.fillna('')
                print("DEBUG: The columns in your file are:", df.columns.tolist())

                # --- ADJUST THE KEY HERE ('Phone Number') TO MATCH YOUR FILE'S ACTUAL HEADER ---
                df = df.rename(columns={
                    'Company Name': 'company_name',
                    'Contact Person': 'contact',
                    'Email': 'email',
                    # For example, if your file uses 'Phone', change this to: 'Phone': 'phone_number',
                    'Phone': 'phone_number',
                    'Company Type': 'company_type',
                    'Location': 'location'
                })

                if 'email' not in df.columns:
                    flash(
                        "Import failed. The 'Email' column is missing from your file.", "error")
                    return redirect(url_for("dashboard"))

                new_contacts_count = 0
                for index, row in df.iterrows():
                    if row.get('email'):
                        # Check if 'phone_number' column exists after rename before accessing
                        phone = row.get('phone_number', '')

                        contact = Contact(
                            date=date.today(), user_id=uid,
                            company_name=row.get('company_name', ''), email=row.get('email'),
                            contact=row.get('contact', ''), phone_number=phone,
                            company_type=row.get('company_type', ''), location=row.get('location', '')
                        )
                        db.session.add(contact)
                        new_contacts_count += 1

                db.session.commit()
                flash(
                    f"✅ Successfully imported {new_contacts_count} new contacts!", "success")

            except Exception as e:
                db.session.rollback()
                flash(f"❌ An error occurred during import: {e}", "error")

            return redirect(url_for("main.dashboard"))

        # --- Handle Delete Contact ---
        if "delete_contact" in form_data:
            contact_to_delete = db.session.get(
                Contact, int(form_data.get("contact_id")))
            if contact_to_delete and contact_to_delete.user_id == uid:
                db.session.delete(contact_to_delete)
                db.session.commit()
                flash("Contact deleted.", "success")
            return redirect(url_for("main.dashboard"))

        # --- Handle Delete Selected Campaigns ---
        if "delete_selected_campaigns" in form_data:
            campaign_ids = request.form.getlist('campaign_ids')
            if campaign_ids:
                campaigns_to_delete = Campaign.query.filter(
                    Campaign.id.in_(campaign_ids), 
                    Campaign.user_id == uid
                ).all()
                
                for campaign in campaigns_to_delete:
                    db.session.delete(campaign)
                
                db.session.commit()
                flash(f"{len(campaigns_to_delete)} campaign(s) deleted successfully.", "success")
            else:
                flash("No campaigns selected for deletion.", "error")
            return redirect(url_for("main.dashboard"))

        # --- Handle Clear All Campaigns ---
        if "clear_all_campaigns" in form_data:
            campaigns_to_clear = Campaign.query.filter_by(user_id=uid).all()
            campaign_count = len(campaigns_to_clear)
            
            for campaign in campaigns_to_clear:
                db.session.delete(campaign)
            
            db.session.commit()
            flash(f"All {campaign_count} campaign(s) cleared successfully.", "success")
            return redirect(url_for("main.dashboard"))

        # --- Handle Send Email Campaign ---
        if "send_email" in form_data:
            send_option = form_data.get('send_to_option')
            contacts_to_send = []

            if send_option == 'all':
                contacts_to_send = Contact.query.filter_by(user_id=uid).all()
            elif send_option == 'selected':
                selected_ids = request.form.getlist('selected_contacts')
                if not selected_ids:
                    flash(
                        "You chose 'Selected Contacts' but did not select any.", "error")
                    return redirect(url_for('main.dashboard'))
                contacts_to_send = Contact.query.filter(
                    Contact.id.in_(selected_ids), Contact.user_id == uid).all()

            if not contacts_to_send:
                flash("No contacts found to send the campaign to.", "warning")
                return redirect(url_for('main.dashboard'))

            subject = form_data.get('subject')
            message = form_data.get('message')

            # Handle file attachments
            attachment_files = []
            attachment_names = []
            uploaded_file = request.files.get('attachments')
            
            if uploaded_file and uploaded_file.filename != '':
                # Read file data
                file_data = uploaded_file.read()
                file_name = uploaded_file.filename
                file_type = uploaded_file.content_type or 'application/octet-stream'
                
                # Prepare for email service (expects list of tuples)
                attachment_files = [(file_data, file_name, file_type)]
                attachment_names.append(file_name)

            # This logic sets the Reply-To address correctly
            reply_address = None
            if current_user.use_custom_smtp and current_user.smtp_email:
                reply_address = current_user.smtp_email

            campaign = Campaign(
                user_id=uid, 
                subject=subject, 
                message=message, 
                recipient_count=len(contacts_to_send),
                attachments=', '.join(attachment_names) if attachment_names else None
            )
            db.session.add(campaign)

            sent, failed = 0, 0
            for contact in contacts_to_send:
                # Include attachments in email sending
                success, error_msg = send_email(
                    contact.email, 
                    subject, 
                    message, 
                    files=attachment_files if attachment_files else None,
                    user=current_user,
                    reply_to_addr=reply_address
                )
                if success:
                    sent += 1
                else:
                    failed += 1
                    print(f"Failed to send email to {contact.email}: {error_msg}")

            campaign.success_count = sent
            campaign.failed_count = failed
            db.session.commit()

            flash(
                f"Campaign finished: {sent} sent, {failed} failed.", "success")
            return redirect(url_for('main.dashboard'))

    # =========================================================================
    #  FETCH DATA FOR DISPLAY (GET REQUEST)
    # =========================================================================
    contacts = Contact.query.filter_by(
        user_id=uid).order_by(Contact.id.desc()).all()
    campaigns = Campaign.query.filter_by(
        user_id=uid).order_by(Campaign.sent_at.desc()).all()
    all_replies = EmailReply.query.filter_by(
        user_id=uid).order_by(EmailReply.received_at.desc()).all()

    # Dashboard stats
    total_contacts = len(contacts)
    total_campaigns = len(campaigns)
    total_emails_sent = db.session.query(db.func.sum(
        Campaign.success_count)).filter_by(user_id=uid).scalar() or 0
    successful_campaigns = Campaign.query.filter(
        Campaign.user_id == uid, Campaign.success_count > 0).count()
    failed_campaigns = Campaign.query.filter(
        Campaign.user_id == uid, Campaign.failed_count > 0).count()
    contacts_added_today = Contact.query.filter(
        Contact.user_id == uid, Contact.date == date.today()).count()

    # Default chart data (last 7 days)
    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=6)
    date_range = [start_date + timedelta(days=i) for i in range(7)]
    daily_counts = {date.strftime('%a, %b %d'): 0 for date in date_range}

    campaigns_in_range = Campaign.query.filter(
        Campaign.user_id == uid,
        db.func.date(Campaign.sent_at) >= start_date,
        db.func.date(Campaign.sent_at) <= today
    ).all()

    for campaign in campaigns_in_range:
        day_key = campaign.sent_at.strftime('%a, %b %d')
        if day_key in daily_counts:
            daily_counts[day_key] += campaign.success_count or 0

    chart_labels = list(daily_counts.keys())
    chart_data = list(daily_counts.values())

    return render_template(
        "dashboard.html",
        contacts=contacts,
        total_contacts=total_contacts,
        total_campaigns=total_campaigns,
        total_emails_sent=total_emails_sent,
        campaigns=campaigns,
        successful_campaigns=successful_campaigns,
        failed_campaigns=failed_campaigns,
        contacts_added_today=contacts_added_today,
        chart_labels=chart_labels,
        chart_data=chart_data,
        replies=all_replies
    )


@main_bp.route("/export-contacts")
@login_required
def export_contacts():
    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Company Name', 'Contact Person',
                    'Email', 'Phone', 'Type', 'Location'])
    for contact in contacts:
        writer.writerow([
            contact.company_name, contact.contact, contact.email,
            contact.phone_number, contact.company_type, contact.location
        ])
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=contacts.csv'
    response.headers['Content-type'] = 'text/csv'
    return response


@main_bp.route('/my-id')
@login_required
def show_my_id():
    return f"<h1>Your current User ID is: {current_user.id}</h1>"
