from datetime import datetime
from flask import Flask, render_template, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import sqlite3
import os
import boto3
import io

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

DB_NAME = "vault.db"
UPLOAD_FOLDER = "temp"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {
    "txt",
    "pdf",
    "png",
    "jpg",
    "jpeg",
    "docx"
}

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

AWS_REGION = os.environ.get("AWS_REGION")
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")

s3 = boto3.client(
    "s3",
    region_name=AWS_REGION,
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY")
)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            original_name TEXT,
            s3_key TEXT,
            encryption_key TEXT,
            file_size TEXT,
            upload_time TEXT
        )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        action TEXT,
        timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()
def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        try:
            conn = sqlite3.connect(DB_NAME)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, password)
            )
            conn.commit()
            conn.close()
            return redirect("/login")
        except:
            return "Email already registered."

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session["user"] = email
            return redirect("/dashboard")
        else:
            return "Invalid login details."

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute(
        "SELECT id, original_name, file_size, upload_time FROM files WHERE user_email = ?",
        (session["user"],)
    )

    files = cur.fetchall()
    total_files = len(files)

    conn.close()

    return render_template(
        "dashboard.html",
        files=files,
        total_files=total_files
    )
@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect("/login")

    file = request.files["file"]

    if file.filename == "":
        return "No file selected."
    
    if not allowed_file(file.filename):
        return "Invalid file type."

    original_data = file.read()
    file_size_kb = round(len(original_data) / 1024, 2)

    if file_size_kb > 1024:
        file_size = f"{round(file_size_kb / 1024, 2)} MB"
    else:
        file_size = f"{file_size_kb} KB"

    upload_time = datetime.now().strftime("%d %b %Y %I:%M %p")

    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(original_data)

    s3_key = session["user"] + "/" + file.filename + ".encrypted"

    s3.upload_fileobj(
        io.BytesIO(encrypted_data),
        S3_BUCKET_NAME,
        s3_key
    )

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute(
    """
    INSERT INTO files (
        user_email,
        original_name,
        s3_key,
        encryption_key,
        file_size,
        upload_time
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """,
        (
        session["user"],
        file.filename,
        s3_key,
        key.decode(),
        file_size,
        upload_time
        )
    )
    conn.commit()
    conn.close()

    return redirect("/dashboard")

@app.route("/download/<int:file_id>")
def download(file_id):
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute(
        "SELECT original_name, s3_key, encryption_key FROM files WHERE id = ? AND user_email = ?",
        (file_id, session["user"])
    )
    file_record = cur.fetchone()
    conn.close()

    if not file_record:
        return "File not found."

    original_name, s3_key, encryption_key = file_record

    encrypted_obj = s3.get_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
    encrypted_data = encrypted_obj["Body"].read()

    cipher = Fernet(encryption_key.encode())
    decrypted_data = cipher.decrypt(encrypted_data)

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=original_name
    )
@app.route("/delete/<int:file_id>")
def delete_file(file_id):
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute(
        "SELECT s3_key FROM files WHERE id = ? AND user_email = ?",
        (file_id, session["user"])
    )
    file_record = cur.fetchone()

    if not file_record:
        conn.close()
        return "File not found."

    s3_key = file_record[0]

    # Delete file from AWS S3
    s3.delete_object(
        Bucket=S3_BUCKET_NAME,
        Key=s3_key
    )

    # Delete file record from database
    cur.execute(
        "DELETE FROM files WHERE id = ? AND user_email = ?",
        (file_id, session["user"])
    )

    conn.commit()
    conn.close()

    return redirect("/dashboard")
    
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.errorhandler(413)
def too_large(e):
    return "File is too large. Maximum allowed size is 10 MB."
    
if __name__ == "__main__":
    app.run(debug=True)
