import imaplib
import email
from email.utils import parseaddr

# Known providers
COMMON_PROVIDERS = {
    "gmail.com": {"host": "imap.gmail.com", "port": 993},
    "outlook.com": {"host": "outlook.office365.com", "port": 993},
    "hotmail.com": {"host": "outlook.office365.com", "port": 993},
    "yahoo.com": {"host": "imap.mail.yahoo.com", "port": 993},
    "zoho.com": {"host": "imap.zoho.com", "port": 993},
    "corediva365.com": {"host": "server210.web-hosting.com", "port": 993},  # ✅ added custom domain
}

def detect_imap_server(email_address):
    domain = email_address.split("@")[-1].lower()
    if domain in COMMON_PROVIDERS:
        return COMMON_PROVIDERS[domain]["host"], COMMON_PROVIDERS[domain]["port"]
    return f"imap.{domain}", 993  # fallback guess

def test_email_login(email_address, password):
    host, port = detect_imap_server(email_address)
    print(f"[INFO] Trying IMAP login → {host}:{port} for {email_address}")

    try:
        mail = imaplib.IMAP4_SSL(host, port)
        mail.login(email_address, password)
        print("[SUCCESS] Logged in successfully!")

        mail.select("INBOX")
        status, messages = mail.search(None, "ALL")
        if status != "OK":
            print("❌ Failed to search mailbox")
            return

        msg_ids = messages[0].split()
        print(f"[INFO] Found {len(msg_ids)} messages.")

        for msg_id in msg_ids[-5:]:
            status, msg_data = mail.fetch(msg_id, "(RFC822)")
            if status != "OK":
                continue
            raw_msg = msg_data[0][1]
            msg = email.message_from_bytes(raw_msg)

            from_name, from_addr = parseaddr(msg.get("From"))
            subject = msg.get("Subject", "(No subject)")
            print(f"📩 {from_addr} | {subject}")

        mail.logout()

    except Exception as e:
        print(f"❌ Login failed or error occurred: {e}")

if __name__ == "__main__":
    EMAIL = input("Enter your email: ")
    PASSWORD = input("Enter your password: ")
    test_email_login(EMAIL, PASSWORD)
