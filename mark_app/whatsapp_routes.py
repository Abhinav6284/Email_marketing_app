from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, send_from_directory
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
import urllib.parse

from . import db
from .models import Contact, MessageHistory

whatsapp_bp = Blueprint(
    "whatsapp", __name__, url_prefix="/whatsapp", template_folder="templates"
)

# WhatsApp Settings & Contacts
@whatsapp_bp.route("/settings", methods=["GET", "POST"])
@login_required
def whatsapp_settings():
    if request.method == "POST":
        whatsapp_number = request.form.get("whatsapp_number", "").strip()
        current_user.whatsapp_number = whatsapp_number
        db.session.commit()
        flash("WhatsApp settings saved", "success")
        return redirect(url_for("whatsapp.whatsapp_settings"))

    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    # Include messages for history
    for c in contacts:
        c.messages = MessageHistory.query.filter_by(contact_id=c.id, user_id=current_user.id).order_by(MessageHistory.date.desc()).all()

    return render_template(
        "whatsapp_settings.html",
        whatsapp_number=getattr(current_user, "whatsapp_number", ""),
        contacts=contacts
    )

# Send WhatsApp message
@whatsapp_bp.route("/send/<int:contact_id>", methods=["POST"])
@login_required
def send_message(contact_id):
    contact = Contact.query.filter_by(id=contact_id, user_id=current_user.id).first()
    if not contact:
        flash("Contact not found", "error")
        return redirect(url_for("main.dashboard") + "#whatsapp")

    message_txt = request.form.get("message", "").strip()
    attachment = request.files.get("attachment")

    attachment_url = None
    if attachment and attachment.filename:
        filename = secure_filename(attachment.filename)
        upload_folder = current_app.config.get("UPLOAD_FOLDER", "uploads")
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, filename)
        attachment.save(filepath)
        attachment_url = url_for("whatsapp.uploaded_file", filename=filename, _external=True)

    # Append attachment URL to message
    if attachment_url:
        message_txt += f"\n\nAttachment: {attachment_url}"

    # Save to DB
    history = MessageHistory(
        contact_id=contact.id,
        user_id=current_user.id,
        message=message_txt,
        attachment=attachment_url
    )
    db.session.add(history)
    db.session.commit()

    if not contact.phone_number:
        flash("Contact has no phone number", "error")
        return redirect(url_for("main.dashboard") + "#whatsapp")

    phone = contact.phone_number.strip().replace("+", "")
    encoded_msg = urllib.parse.quote(message_txt)
    whatsapp_url = f"https://wa.me/{phone}?text={encoded_msg}"

    return redirect(whatsapp_url)

# Serve uploaded files
@whatsapp_bp.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(current_app.config.get("UPLOAD_FOLDER", "uploads"), filename)
