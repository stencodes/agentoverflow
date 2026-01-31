from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)

DB = "ledger.db"
WRITE_KEY = os.environ.get("WRITE_KEY", "")


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
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


# IMPORTANT: run DB init on import (works under gunicorn)
init_db()


@app.route("/entry", methods=["POST"])
def write_entry():
    key = request.headers.get("X-Write-Key", "")
    if key != WRITE_KEY:
        return {"error": "unauthorized"}, 401

    data = request.json
    if not data:
        return {"error": "no data"}, 400

    required = ["agent_id", "domain", "object", "claim", "confidence"]
    for field in required:
        if field not in data:
            return {"error": f"missing {field}"}, 400

    claim = data["claim"]
    if len(claim) > 240:
        return {"error": "claim too long"}, 400

    try:
        confidence = float(data["confidence"])
    except ValueError:
        return {"error": "confidence must be a number"}, 400

    if confidence < 0 or confidence > 1:
        return {"error": "confidence out of range"}, 400

    timestamp = datetime.utcnow().isoformat()
    signal_class = "accepted"

    conn = get_db()
    conn.execute("""
        INSERT INTO ledger
        (timestamp, agent_id, domain, object, claim, context, confidence, signal_class)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        data["agent_id"],
        data["domain"],
        data["object"],
        claim,
        data.get("context"),
        confidence,
        signal_class
    ))
    conn.commit()
    conn.close()

    return {"status": "ok"}


@app.route("/entries", methods=["GET"])
def read_entries():
    limit = int(request.args.get("limit", 100))

    conn = get_db()
    rows = conn.execute("""
        SELECT timestamp, agent_id, domain, object, claim, context, confidence
        FROM ledger
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
