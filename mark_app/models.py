from flask_login import UserMixin
from . import db  # Imports the central db object
from datetime import date, timedelta, datetime, timezone
import random
from werkzeug.security import generate_password_hash, check_password_hash


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
    profile_picture = db.Column(
        db.LargeBinary(length=(2 ** 24)), nullable=True)
    profile_picture_mimetype = db.Column(db.String(100), nullable=True)
    reset_otp = db.Column(db.String(200))
    reset_otp_expires = db.Column(db.DateTime)
    whatsapp_sid = db.Column(db.String(100), nullable=True)
    whatsapp_auth_token = db.Column(db.String(500), nullable=True)
    whatsapp_number = db.Column(db.String(50), nullable=True)
    whatsapp_verified = db.Column(db.Boolean, default=False)
    
    # WhatsApp Integration Types
    whatsapp_integration_type = db.Column(db.String(50), default='personal')  # personal, twilio, business
    whatsapp_business_token = db.Column(db.String(500), nullable=True)
    whatsapp_business_phone_id = db.Column(db.String(100), nullable=True)
    whatsapp_business_app_id = db.Column(db.String(100), nullable=True)
    
    # Additional signup fields as requested
    mobile_number = db.Column(db.String(20), nullable=True)
    company_address = db.Column(db.Text, nullable=True)
    how_did_you_hear = db.Column(db.String(100), nullable=True)

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
        if not self.login_otp or not self.login_otp_created:
            return False

        now_aware = datetime.now(timezone.utc)
        stored_time_aware = self.login_otp_created
        if stored_time_aware.tzinfo is None:
            stored_time_aware = stored_time_aware.replace(tzinfo=timezone.utc)

        if now_aware - stored_time_aware > timedelta(minutes=5):
            return False

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
    attachments = db.Column(db.String(500))
    message_id = db.Column(db.String(255), unique=True)   # ✅ NEW

class EmailReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    sender_name = db.Column(db.String(150))
    sender_email = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(255))
    body = db.Column(db.Text)
    received_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc))
    
class MessageHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text)
    attachment = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
