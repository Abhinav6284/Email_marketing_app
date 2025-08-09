# email_services.py
import ssl
import smtplib
from email.message import EmailMessage
from utils import decrypt_password

import smtplib
import ssl
from email.message import EmailMessage


def send_email_enhanced(to_addr, subject, body, files=None, user=None, force_custom=False):
    """
    Enhanced email sending with proper default vs custom SMTP separation
    """
    try:
        # Determine SMTP settings
        if user and user.use_custom_smtp and (user.smtp_verified or force_custom):

            smtp_server = user.smtp_server
            smtp_port = user.smtp_port
            smtp_user = user.smtp_email
            smtp_pass = user.smtp_password
            sender_name = user.smtp_sender_name or user.get_full_name()
            from_address = f"{sender_name} <{smtp_user}>"

            print(f"✅ Using CUSTOM SMTP: {smtp_server}:{smtp_port} with {smtp_user}")

        else:
            # Use DEFAULT SMTP (from your attached image)
            smtp_server = "server210.web-hosting.com"
            smtp_port = 465
            smtp_user = "dev@corediva365.com"
            smtp_pass = "akila@196f"

            if user:
                sender_name = user.get_full_name()
                from_address = f"{sender_name} via Mark <{smtp_user}>"
            else:
                from_address = f"Mark Team <{smtp_user}>"

            print(f"🏢 Using DEFAULT SMTP: {smtp_server}:{smtp_port} with {smtp_user}")

        # Create email message
        msg = EmailMessage()
        msg["From"] = from_address
        msg["To"] = to_addr
        msg["Subject"] = subject

        # Add signature based on SMTP type
        if user and user.use_custom_smtp and (user.smtp_verified or force_custom):
            signature = f"\n\nBest regards,\n{user.smtp_sender_name or user.get_full_name()}"
        else:
            signature = "\n--\nRegards,\nMark Team"

        msg.set_content(f"{body}{signature}")

        # Add attachments if provided
        if files:
            for fname, data, mime in files:
                maintype, subtype = (
                    mime.split("/", 1) if "/" in mime else ("application", "octet-stream")
                )
                msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)

        # Create SSL context and send
        context = ssl._create_unverified_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        print(f"✅ Email sent successfully from {from_address}")
        return True, "Email sent successfully"

    except Exception as e:
        error_message = str(e)
        print(f"✉️ Email error: {error_message}")
        return False, error_message
