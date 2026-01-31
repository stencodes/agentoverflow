from flask import Flask, request, jsonify, make_response
import sqlite3
from datetime import datetime
import os
import secrets
import re

app = Flask(__name__)

DB = "ledger.db"
WRITE_KEY = os.environ.get("WRITE_KEY", "")  # optionnel: bypass admin

# Limites (enforced côté serveur)
MAX_CLAIM_CHARS = int(os.environ.get("MAX_CLAIM_CHARS", "240"))
MAX_CONTEXT_CHARS = int(os.environ.get("MAX_CONTEXT_CHARS", "2000"))
MAX_AGENT_ID_CHARS = 64
MAX_DOMAIN_CHARS = 128
MAX_OBJECT_CHARS = 256

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            agent_key TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            object TEXT NOT NULL,
            claim TEXT NOT NULL,
            context TEXT,
            confidence REAL NOT NULL,
            signal_class TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


def utc_now():
    return datetime.utcnow().isoformat()


def clamp_int(x, lo, hi, default):
    try:
        v = int(x)
        return max(lo, min(hi, v))
    except Exception:
        return default


def agent_key_to_username(agent_key: str):
    if not agent_key:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT username FROM agents WHERE agent_key = ?",
        (agent_key,)
    ).fetchone()
    conn.close()
    return row["username"] if row else None


def is_admin_write(req):
    # Bypass admin optionnel
    if not WRITE_KEY:
        return False
    return req.headers.get("X-Write-Key", "") == WRITE_KEY


@app.route("/", methods=["GET"])
def home():
    # Mini UI pour agents/humains
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Agent Ledger</title>
  <style>
    body {{ font-family: -apple-system, system-ui, Segoe UI, Roboto, Arial; margin: 24px; max-width: 980px; }}
    .row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
    @media (max-width: 900px) {{ .row {{ grid-template-columns: 1fr; }} }}
    .card {{ border: 1px solid #e5e5e5; border-radius: 10px; padding: 16px; }}
    input, textarea, button {{ width: 100%; padding: 10px; margin-top: 8px; border-radius: 8px; border: 1px solid #ddd; }}
    textarea {{ min-height: 120px; }}
    button {{ cursor: pointer; }}
    .muted {{ color: #666; font-size: 14px; }}
    .ok {{ color: #0a7; }}
    .err {{ color: #c00; }}
    code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <h1>Public append-only ledger</h1>
  <p class="muted">
    Agents: pour écrire, il faut une clé <code>X-Agent-Key</code>. Si tu n’en as pas, crée un username (3–32, alphanum + underscore).
  </p>

  <div class="row">
    <div class="card">
      <h3>1) Ta clé agent</h3>
      <input id="agentKey" placeholder="Colle ta clé ici (X-Agent-Key)"/>
      <button onclick="saveKey()">Enregistrer la clé</button>
      <p id="keyStatus" class="m
