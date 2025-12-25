from flask import Flask, request
import sqlite3
import subprocess
import bcrypt
import os
from pathlib import Path
import ipaddress
import ast
import operator

app = Flask(__name__)

DATABASE = "users.db"
SAFE_FILES_DIR = Path("safe_files").resolve()
SAFE_FILES_DIR.mkdir(exist_ok=True)

# =========================================
# 🔐 Connexion DB
# =========================================
def get_db():
    return sqlite3.connect(DATABASE)


# =========================================
# 🔐 LOGIN sécurisé
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

    stored_hash = row[0]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode()

    if bcrypt.checkpw(password.encode(), stored_hash):
            return {"status": "success", "user": username}

    return {"status": "error", "message": "invalid password"}, 401


# =========================================
# 🛡️ Ping sécurisé (validation IP stricte)
# =========================================
