import base64
import io
import os
import sqlite3
from functools import wraps

import bcrypt
import pyotp
import qrcode
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "change-this-secret-key")
DATABASE = os.path.join(app.root_path, "mfa_app.db")
ISSUER_NAME = "CS504 MFA Demo"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                mfa_secret TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def get_user_by_username(username):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def get_user_by_id(user_id):
    with get_db_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def generate_qr_code_data_uri(provisioning_uri):
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id") or not session.get("mfa_verified"):
            flash("Please log in and complete MFA verification first.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


@app.route("/")
def index():
    if session.get("user_id") and session.get("mfa_verified"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if get_user_by_username(username):
            flash("That username is already registered.", "error")
            return render_template("register.html")

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        mfa_secret = pyotp.random_base32()

        with get_db_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, mfa_secret) VALUES (?, ?, ?)",
                (username, password_hash.decode("utf-8"), mfa_secret),
            )
            conn.commit()

        session.clear()
        session["setup_user_id"] = cursor.lastrowid
        flash("Account created. Scan the QR code to finish MFA setup.", "success")
        return redirect(url_for("setup_mfa"))

    return render_template("register.html")


@app.route("/setup-mfa")
def setup_mfa():
    setup_user_id = session.get("setup_user_id")
    if not setup_user_id:
        flash("Please register before setting up MFA.", "warning")
        return redirect(url_for("register"))

    user = get_user_by_id(setup_user_id)
    if not user:
        session.clear()
        flash("Account setup session expired. Please register again.", "error")
        return redirect(url_for("register"))

    totp = pyotp.TOTP(user["mfa_secret"])
    provisioning_uri = totp.provisioning_uri(
        name=user["username"],
        issuer_name=ISSUER_NAME,
    )
    qr_code = generate_qr_code_data_uri(provisioning_uri)

    return render_template(
        "setup_mfa.html",
        username=user["username"],
        mfa_secret=user["mfa_secret"],
        qr_code=qr_code,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user_by_username(username)

        if not user or not bcrypt.checkpw(
            password.encode("utf-8"), user["password_hash"].encode("utf-8")
        ):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session.clear()
        session["pending_user_id"] = user["id"]
        session["pending_username"] = user["username"]
        flash("Password accepted. Enter your authenticator code.", "success")
        return redirect(url_for("verify"))

    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    pending_user_id = session.get("pending_user_id")
    if not pending_user_id:
        flash("Please enter your username and password first.", "warning")
        return redirect(url_for("login"))

    user = get_user_by_id(pending_user_id)
    if not user:
        session.clear()
        flash("Login session expired. Please try again.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip().replace(" ", "")
        totp = pyotp.TOTP(user["mfa_secret"])

        if totp.verify(otp_code, valid_window=1):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["mfa_verified"] = True
            flash("MFA verified. Welcome!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid or expired authentication code.", "error")

    return render_template("verify.html", username=user["username"])


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


init_db()


if __name__ == "__main__":
    app.run(debug=True)
