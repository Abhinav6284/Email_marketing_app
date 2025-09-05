import imaplib
import email
from email.header import decode_header
from datetime import datetime, timezone
from . import db
from .models import EmailReply


IMAP_SERVER = "server210.web-hosting.com"
IMAP_USER = "replies@corediva365.com"
IMAP_PASS = "r-pli@s#365"  # ⚠️ Use App Password if provider requires


def fetch_replies(user_id=None):
    """
    Fetch unread replies from IMAP inbox and save them into EmailReply table.
    If user_id is passed, link replies to that user.
    """
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(IMAP_USER, IMAP_PASS)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")  # only unread emails
        if status != "OK":
            return "No new messages"

        for num in messages[0].split():
            status, data = mail.fetch(num, "(RFC822)")
            if status != "OK":
                continue

            msg = email.message_from_bytes(data[0][1])

            # --- Decode Subject ---
            subject, encoding = decode_header(msg.get("Subject"))[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or "utf-8", errors="ignore")

            # --- Extract Sender ---
            from_email = msg.get("From", "")
            if "<" in from_email:
                sender_name = from_email.split("<")[0].strip().replace('"', '')
                sender_email = from_email.split("<")[-1].replace(">", "").strip()
            else:
                sender_name = from_email
                sender_email = from_email

            # --- Extract Body ---
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                        body = part.get_payload(decode=True).decode(errors="ignore")
                        break
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")

            # --- Save to DB ---
            reply = EmailReply(
                user_id=user_id,  # now always linked to the logged-in user
                sender_name=sender_name,
                sender_email=sender_email,
                subject=subject,
                body=body,
                received_at=datetime.now(timezone.utc)
            )

            db.session.add(reply)

        db.session.commit()
        mail.logout()
        return "Replies fetched successfully"

    except Exception as e:
        return f"Error: {e}"
