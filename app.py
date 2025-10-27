import os
import io
import qrcode
import pyotp
import base64
import secrets
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text
from sqlalchemy.orm import sessionmaker, declarative_base
from email_validator import validate_email, EmailNotValidError

# ---------- Config ----------
DB_URL = "sqlite:///mfa.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
ISSUER_NAME = "MeuSiteFlaskMFA"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=6)
)

login_manager = LoginManager(app)
login_manager.login_view = "login"

Base = declarative_base()
engine = create_engine(DB_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

# ---------- Models ----------
class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    pw_hash = Column(String(255), nullable=False)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(64), nullable=True)  # base32 secret
    recovery_codes = Column(Text, nullable=True)    # newline-separated hashed codes

    def get_id(self):
        return str(self.id)

Base.metadata.create_all(engine)

@login_manager.user_loader
def load_user(user_id):
    return db.get(User, int(user_id))

# ---------- Helpers ----------
def hash_code(code: str) -> str:
    # simple peppered hash (dev-only); use a stronger KDF (argon2/bcrypt) in prod
    import hashlib
    pepper = os.environ.get("RECOVERY_PEPPER", "dev-pepper")
    return hashlib.sha256((pepper + code).encode()).hexdigest()

def generate_recovery_codes(n=10):
    # human-friendly blocks like "K7PX-9W3T-AB12"
    codes = []
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(n):
        raw = "".join(secrets.choice(alphabet) for _ in range(12))
        code = f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"
        codes.append(code)
    return codes

# ---------- Routes ----------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        try:
            validate_email(email)
        except EmailNotValidError as e:
            flash(f"Email inválido: {e}", "danger")
            return render_template("register.html")
        if db.query(User).filter_by(email=email).first():
            flash("Email já cadastrado.", "warning")
            return render_template("register.html")
        if len(password) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "warning")
            return render_template("register.html")
        u = User(email=email, pw_hash=generate_password_hash(password))
        db.add(u)
        db.commit()
        flash("Cadastro realizado! Faça login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        u = db.query(User).filter_by(email=email).first()
        if not u or not check_password_hash(u.pw_hash, password):
            flash("Credenciais inválidas.", "danger")
            return render_template("login.html")
        login_user(u)
        session.permanent = True
        # Se MFA habilitado, exigir verificação
        if u.mfa_enabled:
            session["mfa_pending"] = True
            return redirect(url_for("mfa_verify"))
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Sessão encerrada.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("mfa_pending"):
        return redirect(url_for("mfa_verify"))
    return render_template("dashboard.html")

# ---------- MFA: Enrollment ----------
@app.route("/mfa/enroll", methods=["GET", "POST"])
@login_required
def mfa_enroll():
    if request.method == "POST":
        # 1) gerar secret e QR
        secret = pyotp.random_base32()
        # guardar secret temporário na sessão até confirmar com um token válido
        session["temp_mfa_secret"] = secret
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=current_user.email, issuer_name=ISSUER_NAME)
        # gerar QR como data URI
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        data_uri = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
        return render_template("mfa_enroll.html", data_uri=data_uri, secret=secret, uri=uri)
    return render_template("mfa_enroll.html")

@app.route("/mfa/enroll/confirm", methods=["POST"])
@login_required
def mfa_enroll_confirm():
    token = request.form.get("token", "").strip()
    secret = session.get("temp_mfa_secret")
    if not secret:
        flash("Fluxo de matrícula inválido. Refaça o processo.", "danger")
        return redirect(url_for("mfa_enroll"))
    totp = pyotp.TOTP(secret)
    if not totp.verify(token, valid_window=1):
        flash("Código TOTP inválido. Tente novamente.", "danger")
        return redirect(url_for("mfa_enroll"))
    # Ativar MFA no usuário
    u = db.query(User).get(current_user.id)
    u.mfa_secret = secret
    u.mfa_enabled = True
    # Gerar códigos de recuperação
    raw_codes = generate_recovery_codes(10)
    hashed = [hash_code(c) for c in raw_codes]
    u.recovery_codes = "\n".join(hashed)
    db.commit()
    session.pop("temp_mfa_secret", None)
    flash("MFA habilitado com sucesso! Salve seus códigos de recuperação.", "success")
    return render_template("recovery_codes.html", codes=raw_codes)

# ---------- MFA: Verify on login ----------
@app.route("/mfa/verify", methods=["GET", "POST"])
@login_required
def mfa_verify():
    if not current_user.mfa_enabled:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        recovery = request.form.get("recovery", "").strip()

        # Caminho 1: TOTP
        if token:
            totp = pyotp.TOTP(current_user.mfa_secret)
            if totp.verify(token, valid_window=1):
                session.pop("mfa_pending", None)
                flash("MFA verificado. Bem-vindo!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Código TOTP inválido.", "danger")

        # Caminho 2: Recovery code
        elif recovery:
            stored = (current_user.recovery_codes or "").split("\n") if current_user.recovery_codes else []
            hashed = hash_code(recovery)
            if hashed in stored:
                # invalidar código usado
                stored[stored.index(hashed)] = ""
                current_user.recovery_codes = "\n".join(stored)
                db.commit()
                session.pop("mfa_pending", None)
                flash("Login com código de recuperação.", "warning")
                return redirect(url_for("dashboard"))
            else:
                flash("Código de recuperação inválido.", "danger")

    return render_template("mfa_verify.html")

# ---------- Rotate recovery codes ----------
@app.route("/mfa/recovery/rotate", methods=["POST"])
@login_required
def rotate_recovery():
    if not current_user.mfa_enabled:
        flash("Ative o MFA primeiro.", "warning")
        return redirect(url_for("dashboard"))
    raw_codes = generate_recovery_codes(10)
    hashed = [hash_code(c) for c in raw_codes]
    u = db.query(User).get(current_user.id)
    u.recovery_codes = "\n".join(hashed)
    db.commit()
    flash("Novos códigos gerados.", "info")
    return render_template("recovery_codes.html", codes=raw_codes)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
