import smtplib
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from .utils import decrypt_password


def send_email_enhanced(to_addr, subject, body, files=None, user=None, system_config=None,
                        reply_to_addr=None, force_custom=False, campaign_id=None):
    """
    Sends an email with forced Reply-To to replies@corediva365.com,
    CCs the sender, and adds a unique X-Campaign-ID header
    for accurate reply tracking.
    """

    # Determine which SMTP settings to use
    use_custom = user and user.use_custom_smtp and user.smtp_verified
    if force_custom:
        use_custom = True

    if use_custom:
        smtp_server = user.smtp_server
        smtp_port = user.smtp_port
        smtp_user = user.smtp_email
        try:
            smtp_pass = decrypt_password(user.smtp_password)
        except Exception:
            return False, "Failed to decrypt SMTP password."
        from_name = user.smtp_sender_name or user.get_full_name()
        from_addr = user.smtp_email
        signature = ""
    else:
        smtp_server = system_config['server']
        smtp_port = system_config['port']
        smtp_user = system_config['user']
        smtp_pass = system_config['password']
        from_name = user.get_full_name() if user else "Mark Team"
        from_addr = system_config['user']
        signature = system_config.get('signature', '')

    # --- Build the Email Message ---
    msg = MIMEMultipart()
    msg['From'] = f"{from_name} <{from_addr}>"
    msg['To'] = to_addr
    msg['Subject'] = subject

    # Force Reply-To
    msg['Reply-To'] = "replies@corediva365.com"

    # CC the sender
    msg['Cc'] = from_addr

    # Unique campaign tracking header
    if campaign_id:
        msg['X-Campaign-ID'] = str(campaign_id)
    else:
        msg['X-Campaign-ID'] = str(uuid.uuid4())  # fallback unique id

    full_body = body + signature
    msg.attach(MIMEText(full_body, 'plain'))

    # Attach files if any
    if files:
        for file_data, file_name, file_type in files:
            if file_data and file_name:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(file_data)
                encoders.encode_base64(part)
                part.add_header('Content-Disposition',
                                f'attachment; filename="{file_name}"')
                msg.attach(part)

    # --- Send the Email ---
    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True, "Email sent successfully."
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP Authentication Error. Check email/password."
    except Exception as e:
        return False, str(e)
