import os, json, time, secrets, hashlib, hmac, smtplib, threading
from email.message import EmailMessage
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory, abort

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
os.makedirs(DATA, exist_ok=True)

app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("CHATLY_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("Bitte zuerst CHATLY_SECRET_KEY als Umgebungsvariable setzen.")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7
)

lock = threading.RLock()
FILES = {
    "users": "users.json",
    "whitelist": "whitelist.json",
    "messages": "messages.json",
    "verification": "verification.json"
}
DEFAULTS = {
    "users": {"users": []},
    "whitelist": {"allowed_users": []},
    "messages": {"messages": []},
    "verification": {"codes": []}
}

def read_db(name):
    path = os.path.join(DATA, FILES[name])
    with lock:
        if not os.path.exists(path):
            write_db(name, DEFAULTS[name])
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

def write_db(name, data):
    path = os.path.join(DATA, FILES[name])
    temp = path + ".tmp"
    with lock:
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(temp, path)

def now():
    return int(time.time())

def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return salt.hex() + ":" + digest.hex()

def password_ok(password, stored):
    try:
        salt_hex, digest_hex = stored.split(":")
        test = password_hash(password, bytes.fromhex(salt_hex)).split(":")[1]
        return hmac.compare_digest(test, digest_hex)
    except Exception:
        return False

def current_user():
    username = session.get("username")
    if not username:
        return None
    db = read_db("users")
    return next((u for u in db["users"] if u["username"].lower() == username.lower()
                 and u.get("approved") and u.get("verified")), None)

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify(error="Bitte anmelden."), 401
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or not user.get("admin"):
            return jsonify(error="Nur für Admins."), 403
        return fn(*args, **kwargs)
    return wrapped

def send_verification_email(address, code):
    host = os.environ.get("SMTP_HOST")
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM", user or "")
    port = int(os.environ.get("SMTP_PORT", "587"))
    if not all([host, user, password, sender]):
        raise RuntimeError("SMTP ist noch nicht eingerichtet. Bitte die E-Mail-Einstellungen in .env setzen.")
    msg = EmailMessage()
    msg["Subject"] = "Dein Chatly-Verifizierungscode"
    msg["From"] = sender
    msg["To"] = address
    msg.set_content(f"Dein Chatly-Verifizierungscode lautet: {code}\n\nDer Code ist 10 Minuten gültig. Teile ihn mit niemandem.")
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.starttls()
        server.login(user, password)
        server.send_message(msg)

@app.before_request
def csrf_check():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.path == "/api/register" or request.path == "/api/verify":
            return
        token = session.get("csrf")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not token or not hmac.compare_digest(token, supplied):
            return jsonify(error="Sicherheitsprüfung fehlgeschlagen. Seite neu laden."), 403

@app.get("/")
def index():
    return send_from_directory("static", "index.html")

@app.get("/api/config")
def config():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return jsonify(csrf=session["csrf"], logged_in=bool(current_user()),
                   username=(current_user() or {}).get("username"))

@app.post("/api/register")
def register():
    data = request.get_json(force=True)
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not (3 <= len(username) <= 20) or not username.replace("_", "").isalnum():
        return jsonify(error="Benutzername: 3–20 Zeichen, nur Buchstaben, Zahlen und _. "), 400
    if len(password) < 10:
        return jsonify(error="Das Passwort muss mindestens 10 Zeichen haben."), 400
    if len(password) > 200 or "@" not in email or len(email) > 254:
        return jsonify(error="Bitte gültige E-Mail und ein gültiges Passwort eingeben."), 400

    allowed = read_db("whitelist")["allowed_users"]
    if username.lower() not in [x.lower() for x in allowed]:
        return jsonify(error="Dieser Benutzername steht nicht auf der Whitelist. Bitte einen Admin fragen."), 403

    users = read_db("users")
    if any(u["username"].lower() == username.lower() or u["email"].lower() == email for u in users["users"]):
        return jsonify(error="Benutzername oder E-Mail wird bereits verwendet."), 409

    code = f"{secrets.randbelow(1000000):06d}"
    try:
        send_verification_email(email, code)
    except Exception as e:
        app.logger.exception("E-Mail-Versand fehlgeschlagen")
        return jsonify(error="E-Mail konnte nicht versendet werden. Server-E-Mail-Einstellungen prüfen."), 503

    users["users"].append({
        "username": username, "email": email, "password_hash": password_hash(password),
        "verified": False, "approved": False, "admin": False, "created_at": now()
    })
    write_db("users", users)
    codes = read_db("verification")
    codes["codes"] = [c for c in codes["codes"] if c["username"].lower() != username.lower()]
    codes["codes"].append({"username": username, "code_hash": hashlib.sha256(code.encode()).hexdigest(),
                           "expires": now() + 600, "attempts": 0})
    write_db("verification", codes)
    return jsonify(message="Code wurde per E-Mail verschickt. Bitte E-Mail bestätigen.")

@app.post("/api/verify")
def verify():
    data = request.get_json(force=True)
    username = str(data.get("username", "")).strip()
    code = str(data.get("code", "")).strip()
    codes = read_db("verification")
    item = next((c for c in codes["codes"] if c["username"].lower() == username.lower()), None)
    if not item or item["expires"] < now() or item["attempts"] >= 5:
        return jsonify(error="Code ungültig oder abgelaufen. Bitte neu registrieren bzw. Admin fragen."), 400
    item["attempts"] += 1
    if not hmac.compare_digest(item["code_hash"], hashlib.sha256(code.encode()).hexdigest()):
        write_db("verification", codes)
        return jsonify(error="Falscher Verifizierungscode."), 400
    users = read_db("users")
    user = next((u for u in users["users"] if u["username"].lower() == username.lower()), None)
    if not user:
        return jsonify(error="Account nicht gefunden."), 404
    user["verified"] = True
    write_db("users", users)
    codes["codes"] = [c for c in codes["codes"] if c["username"].lower() != username.lower()]
    write_db("verification", codes)
    return jsonify(message="E-Mail bestätigt. Ein Admin muss deinen Account noch freischalten.")

@app.post("/api/login")
def login():
    data = request.get_json(force=True)
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    users = read_db("users")["users"]
    user = next((u for u in users if u["username"].lower() == username.lower()), None)
    if not user or not password_ok(password, user["password_hash"]):
        return jsonify(error="Benutzername oder Passwort falsch."), 401
    if not user.get("verified"):
        return jsonify(error="Bitte zuerst deine E-Mail verifizieren."), 403
    if not user.get("approved"):
        return jsonify(error="Dein Account wartet noch auf die Freischaltung durch einen Admin."), 403
    session.clear()
    session["username"] = user["username"]
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True
    return jsonify(message="Angemeldet.", username=user["username"], csrf=session["csrf"])

@app.post("/api/logout")
@login_required
def logout():
    session.clear()
    return jsonify(message="Abgemeldet.")

@app.get("/api/users")
@login_required
def list_users():
    me = current_user()
    users = [u["username"] for u in read_db("users")["users"]
             if u.get("approved") and u.get("verified") and u["username"] != me["username"]]
    return jsonify(users=users)

@app.get("/api/messages/<username>")
@login_required
def get_messages(username):
    me = current_user()
    users = read_db("users")["users"]
    other = next((u for u in users if u["username"].lower() == username.lower()
                  and u.get("approved") and u.get("verified")), None)
    if not other:
        return jsonify(error="Nutzer nicht gefunden."), 404
    msgs = read_db("messages")["messages"]
    result = [m for m in msgs if {m["from"], m["to"]} == {me["username"], other["username"]}]
    return jsonify(messages=result[-200:])

@app.post("/api/messages")
@login_required
def send_message():
    me = current_user()
    data = request.get_json(force=True)
    to = str(data.get("to", "")).strip()
    body = str(data.get("text", "")).strip()
    if not body or len(body) > 2000:
        return jsonify(error="Nachricht muss zwischen 1 und 2000 Zeichen haben."), 400
    users = read_db("users")["users"]
    other = next((u for u in users if u["username"].lower() == to.lower()
                  and u.get("approved") and u.get("verified")), None)
    if not other or other["username"] == me["username"]:
        return jsonify(error="Empfänger nicht gefunden."), 404
    db = read_db("messages")
    db["messages"].append({"id": secrets.token_hex(8), "from": me["username"],
                           "to": other["username"], "text": body, "created_at": now()})
    write_db("messages", db)
    return jsonify(message="Gesendet.")

@app.get("/api/admin/pending")
@admin_required
def pending_users():
    users = [ {"username":u["username"], "email":u["email"], "verified":u["verified"]}
              for u in read_db("users")["users"] if not u.get("approved") ]
    return jsonify(users=users)

@app.post("/api/admin/approve")
@admin_required
def approve_user():
    username = str(request.get_json(force=True).get("username", ""))
    db = read_db("users")
    user = next((u for u in db["users"] if u["username"].lower() == username.lower()), None)
    if not user or not user.get("verified"):
        return jsonify(error="Nutzer nicht gefunden oder E-Mail noch nicht bestätigt."), 400
    user["approved"] = True
    write_db("users", db)
    return jsonify(message="Account freigeschaltet.")

@app.post("/api/admin/whitelist")
@admin_required
def add_whitelist():
    username = str(request.get_json(force=True).get("username", "")).strip()
    if not (3 <= len(username) <= 20) or not username.replace("_", "").isalnum():
        return jsonify(error="Ungültiger Benutzername."), 400
    db = read_db("whitelist")
    if username.lower() not in [x.lower() for x in db["allowed_users"]]:
        db["allowed_users"].append(username)
        write_db("whitelist", db)
    return jsonify(message="Name zur Whitelist hinzugefügt.")

def bootstrap_admin():
    username = os.environ.get("CHATLY_ADMIN_USER")
    password = os.environ.get("CHATLY_ADMIN_PASSWORD")
    if not username or not password:
        return
    db = read_db("users")
    if not any(u["username"].lower() == username.lower() for u in db["users"]):
        db["users"].append({"username": username, "email": os.environ.get("CHATLY_ADMIN_EMAIL", ""),
                            "password_hash": password_hash(password), "verified": True,
                            "approved": True, "admin": True, "created_at": now()})
        write_db("users", db)
    wl = read_db("whitelist")
    if username.lower() not in [x.lower() for x in wl["allowed_users"]]:
        wl["allowed_users"].append(username)
        write_db("whitelist", wl)

if __name__ == "__main__":
    for name in FILES:
        read_db(name)
    bootstrap_admin()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
