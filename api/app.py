from flask import Flask, request
import sqlite3
import subprocess
import bcrypt
import os
from pathlib import Path

app = Flask(__name__)

DATABASE = "users.db"
SAFE_FILES_DIR = Path("safe_files")   # dossier autorisé
SAFE_FILES_DIR.mkdir(exist_ok=True)

# =========================================
# 🔐 Connexion DB
# =========================================
def get_db():
    return sqlite3.connect(DATABASE)

# =========================================
# 🔐 LOGIN sécurisé (anti-SQL injection)
# =========================================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return {"status": "error", "message": "missing credentials"}, 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return {"status": "error", "message": "user not found"}, 401

    stored_hash = row[0].encode()

    if bcrypt.checkpw(password.encode(), stored_hash):
        return {"status": "success", "user": username}

    return {"status": "error", "message": "invalid password"}, 401


# =========================================
# 🛡️ Ping sécurisé (pas de shell, host validé)
# =========================================
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}

@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    if host not in ALLOWED_HOSTS:
        return {"error": "host not allowed"}, 400

    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True
    )

    return {"output": result.stdout}


# =========================================
# 🧮 Compute → remplacement de eval()
# =========================================
@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "")

    allowed = {"+", "-", "*", "/", "(", ")", ".", "0","1","2","3","4","5","6","7","8","9"}

    if not all(c in allowed for c in expression):
        return {"error": "invalid expression"}, 400

    try:
        result = eval(expression, {"__builtins__": {}}, {})
    except Exception:
        return {"error": "calculation error"}, 400

    return {"result": result}


# =========================================
# 🔐 Hash sécurisé (bcrypt)
# =========================================
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "")

    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())

    return {"bcrypt": hashed.decode()}


# =========================================
# 📂 Lecture fichier sécurisée (sandbox)
# =========================================
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "")

    file_path = (SAFE_FILES_DIR / filename).resolve()

    if SAFE_FILES_DIR not in file_path.parents:
        return {"error": "access denied"}, 403

    if not file_path.exists():
        return {"error": "file not found"}, 404

    with open(file_path, "r") as f:
        return {"content": f.read()}


# =========================================
# 🚫 Suppression endpoint debug sensible
# =========================================
@app.route("/debug", methods=["GET"])
def debug_blocked():
    return {"message": "Debug mode disabled"}, 403


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Secure DevSecOps API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
