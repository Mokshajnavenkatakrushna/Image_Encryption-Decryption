import os
import secrets
import mimetypes
import logging
from flask import Flask, request, render_template, flash, send_file, redirect, url_for
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Set SECRET_KEY for session management
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", secrets.token_hex(16))

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Define folders for uploads
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
DECRYPTED_FOLDER = "decrypted"
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Email Configuration
app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    ENCRYPTED_FOLDER=ENCRYPTED_FOLDER,
    DECRYPTED_FOLDER=DECRYPTED_FOLDER,
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_USERNAME")
)

mail = Mail(app)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Encryption function
def encrypt_image(image_path, password):
    try:
        salt = secrets.token_bytes(16)
        key = PBKDF2(password.encode(), salt, dkLen=32, count=200000)
        nonce = secrets.token_bytes(12)

        with open(image_path, "rb") as f:
            data = f.read()
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        encrypted_filename = secure_filename(os.path.basename(image_path)) + ".aes"
        encrypted_image_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
        
        with open(encrypted_image_path, "wb") as f:
            f.write(salt + nonce + tag + ciphertext)
        
        return encrypted_image_path
    except Exception as e:
        logging.error(f"Encryption failed: {str(e)}")
        return None

# Decryption function
def decrypt_image(encrypted_path, password):
    try:
        with open(encrypted_path, "rb") as f:
            file_data = f.read()

        salt, nonce, tag = file_data[:16], file_data[16:28], file_data[28:44]
        ciphertext = file_data[44:]

        key = PBKDF2(password.encode(), salt, dkLen=32, count=200000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        # Extract the original filename without ".aes"
        original_filename = os.path.basename(encrypted_path).replace(".aes", "")

        # Ensure the correct file extension is used
        if "." not in original_filename:
            original_filename += ".png"  # Default to PNG if extension is missing

        decrypted_path = os.path.join(DECRYPTED_FOLDER, original_filename)
        
        with open(decrypted_path, "wb") as f:
            f.write(decrypted_data)
        
        return original_filename, decrypted_path
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        return None, None


@app.route("/")
def dashboard():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    recipient = request.form.get("email")
    password = request.form.get("password")
    image = request.files.get("image")

    if not recipient or not password or not image or not allowed_file(image.filename):
        flash("Invalid input!", "error")
        return redirect(url_for("dashboard"))

    image_path = os.path.join(UPLOAD_FOLDER, secure_filename(image.filename))
    image.save(image_path)

    encrypted_path = encrypt_image(image_path, password)
    if not encrypted_path:
        flash("Encryption failed!", "error")
        return redirect(url_for("dashboard"))

    msg = Message("Your Encrypted Image and Password", recipients=[recipient], body=f"Your encryption password is: {password}")
    try:
        with open(encrypted_path, "rb") as f:
            msg.attach("encrypted_image.aes", "application/octet-stream", f.read())
        mail.send(msg)
        flash("Email sent successfully!", "success")
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        flash("Failed to send email!", "error")
    return redirect(url_for("dashboard"))

@app.route("/decrypt", methods=["POST"])
def decrypt():
    encrypted_image = request.files.get("encrypted_image")
    password = request.form.get("password")

    if not encrypted_image or not password:
        flash("Invalid input!", "error")
        return redirect(url_for("dashboard"))

    encrypted_filename = secure_filename(encrypted_image.filename)
    encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
    encrypted_image.save(encrypted_path)

    logging.info(f"Saved encrypted image at: {encrypted_path}")

    decrypted_filename, decrypted_path = decrypt_image(encrypted_path, password)

    if decrypted_path:
        if not os.path.exists(decrypted_path):
            logging.error(f"Decryption failed: {decrypted_path} does not exist!")
            flash("Decryption failed! File not found.", "error")
            return redirect(url_for("dashboard"))

        mimetype = mimetypes.guess_type(decrypted_path)[0] or "image/jpeg"
        logging.info(f"Decryption successful: {decrypted_path}")
        
        os.chmod(decrypted_path, 0o644)

        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name=decrypted_filename,
            mimetype=mimetype
        )

    logging.error("Decryption failed: Incorrect password or file corrupted!")
    flash("Decryption failed! Incorrect password or corrupted file.", "error")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True)
