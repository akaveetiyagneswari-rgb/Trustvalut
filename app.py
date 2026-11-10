
from flask import (
    Flask, render_template, request, redirect,
    session, flash, send_file, abort
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

import sqlite3
import os
import uuid

# -------------------------------
# 1. FLASK CONFIGURATION
# -------------------------------

app = Flask(
    __name__,
    template_folder="templates"
)
app.secret_key = os.environ.get("SECRET_KEY", "trustvalut-local-dev-key")
csrf = CSRFProtect(app)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

DB = "trustvalut.db"
UPLOAD_FOLDER = "uploads"

ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"
}

# -------------------------------
# 2. DATABASE CONNECTION
# -------------------------------

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# -------------------------------
# 3. INITIALIZE DATABASE
# -------------------------------

def initialize_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# -------------------------------
# 4. AUDIT LOG FUNCTION
# -------------------------------

def log_action(user_id, action, details=""):
    conn = get_db()

    conn.execute(
        """
        INSERT INTO audit_logs (user_id, action, details)
        VALUES (?, ?, ?)
        """,
        (user_id, action, details)
    )

    conn.commit()
    conn.close()


# -------------------------------
# 5. HOME PAGE
# -------------------------------

@app.route("/")
def home():

    if "user_id" not in session:
        return redirect("/login")

    return render_template("dashboard.html")


# -------------------------------
# 6. USER REGISTRATION
# -------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or len(password) < 8:
            flash("Username and password (8+ characters) required.")
            return redirect("/register")

        conn = get_db()

        try:
            conn.execute(
                """
                INSERT INTO users (username, password)
                VALUES (?, ?)
                """,
                (username, generate_password_hash(password))
            )

            conn.commit()
            flash("Registration successful. Please login.")
            return redirect("/login")

        except sqlite3.IntegrityError:
            flash("Username already exists.")

        finally:
            conn.close()

    return render_template("register.html")


# -------------------------------
# 7. USER LOGIN
# -------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            log_action(user["id"], "LOGIN")

            return redirect("/")

        flash("Invalid username or password.")

    return render_template("login.html")


# -------------------------------
# 8. USER LOGOUT
# -------------------------------

@app.route("/logout")
def logout():

    if "user_id" in session:
        log_action(session["user_id"], "LOGOUT")

    session.clear()

    return redirect("/login")


# -------------------------------
# 9. DOCUMENT UPLOAD
# -------------------------------

@app.route("/upload", methods=["GET", "POST"])
def upload():

    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":

        file = request.files.get("document")

        if not file or not file.filename:
            flash("Please select a document.")
            return redirect("/upload")

        original_name = secure_filename(file.filename)

        if "." not in original_name:
            flash("Invalid file.")
            return redirect("/upload")

        extension = original_name.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            flash("File type not allowed.")
            return redirect("/upload")

        stored_name = uuid.uuid4().hex + "." + extension

        file.save(
            os.path.join(UPLOAD_FOLDER, stored_name)
        )

        conn = get_db()

        conn.execute(
            """
            INSERT INTO documents
            (filename, stored_name, owner_id)
            VALUES (?, ?, ?)
            """,
            (original_name, stored_name, session["user_id"])
        )

        conn.commit()
        conn.close()

        log_action(
            session["user_id"],
            "UPLOAD",
            original_name
        )

        flash("Document uploaded successfully!")

        return redirect("/documents")

    return render_template("upload.html")


# -------------------------------
# 10. VIEW MY DOCUMENTS
# -------------------------------

@app.route("/documents")
def documents():

    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()

    docs = conn.execute(
        """
        SELECT * FROM documents
        WHERE owner_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    conn.close()

    return render_template(
        "documents.html",
        documents=docs
    )


# -------------------------------
# 11. SECURE DOCUMENT DOWNLOAD
# -------------------------------

@app.route("/download/<int:doc_id>")
def download(doc_id):

    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()

    doc = conn.execute(
        """
        SELECT * FROM documents
        WHERE id = ? AND owner_id = ?
        """,
        (doc_id, session["user_id"])
    ).fetchone()

    conn.close()

    if not doc:
        abort(404)

    path = os.path.join(
        UPLOAD_FOLDER,
        doc["stored_name"]
    )

    if not os.path.isfile(path):
        abort(404)

    log_action(
        session["user_id"],
        "DOWNLOAD",
        doc["filename"]
    )

    return send_file(
        path,
        as_attachment=True,
        download_name=doc["filename"]
    )


# -------------------------------
# 12. ADMIN AUDIT HISTORY
# -------------------------------

@app.route("/audit")
def audit():

    if "user_id" not in session:
        return redirect("/login")

    if session.get("role") != "admin":
        abort(403)

    conn = get_db()

    logs = conn.execute(
        """
        SELECT audit_logs.*, users.username
        FROM audit_logs
        LEFT JOIN users
        ON audit_logs.user_id = users.id
        ORDER BY audit_logs.id DESC
        """
    ).fetchall()

    conn.close()

    return render_template(
        "audit.html",
        logs=logs
    )


# -------------------------------
# 13. ERROR HANDLING
# -------------------------------

@app.errorhandler(404)
def not_found(error):
    return "Page or document not found.", 404


@app.errorhandler(403)
def forbidden(error):
    return "Access denied. You do not have permission.", 403


@app.errorhandler(413)
def file_too_large(error):
    return "File too large. Maximum size is 10 MB.", 413


# -------------------------------
# 14. START APPLICATION
# MUST BE AT THE VERY BOTTOM
# -------------------------------

if __name__ == "__main__":

    initialize_db()

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    app.run(debug=True)

