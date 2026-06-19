from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import sqlite3
import hashlib
import secrets
import os
from typing import Optional

app = FastAPI(title="Goldmine License Server", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "licenses.db"
ADMIN_KEY = os.getenv("ADMIN_KEY", "change-this-in-production-12345")

# ==================== DATABASE ====================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            plan_type TEXT NOT NULL DEFAULT 'solo',
            max_devices INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            is_revoked INTEGER NOT NULL DEFAULT 0,
            customer_email TEXT,
            customer_name TEXT,
            notes TEXT,
            total_activations INTEGER DEFAULT 0
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            hardware_id TEXT NOT NULL,
            device_name TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (token) REFERENCES licenses(token),
            UNIQUE(token, hardware_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            hardware_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ip_address TEXT
        )
    ''')

    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ==================== MODELS ====================
class TokenCreate(BaseModel):
    plan_type: str = "solo"
    duration_days: int = 30
    customer_email: Optional[str] = None
    customer_name: Optional[str] = None
    notes: Optional[str] = None

class TokenValidate(BaseModel):
    token: str
    hardware_id: str
    device_name: Optional[str] = None

class HeartbeatRequest(BaseModel):
    token: str
    hardware_id: str

class RevokeRequest(BaseModel):
    token: str
    reason: Optional[str] = None

# ==================== HELPERS ====================
def generate_token():
    parts = [secrets.token_uppercase(4) for _ in range(3)]
    return f"GM-PRO-{parts[0]}-{parts[1]}-{parts[2]}"

def hash_hardware_id(hw_id: str) -> str:
    return hashlib.sha256(hw_id.encode()).hexdigest()[:16]

# ==================== ADMIN ENDPOINTS ====================
@app.post("/admin/generate-token")
def generate_license_token(data: TokenCreate, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")

    token = generate_token()
    max_devices = 3 if data.plan_type == "family" else 1
    created_at = datetime.utcnow().isoformat()
    expires_at = (datetime.utcnow() + timedelta(days=data.duration_days)).isoformat() if data.duration_days > 0 else None

    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO licenses (token, plan_type, max_devices, created_at, expires_at, 
                                customer_email, customer_name, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (token, data.plan_type, max_devices, created_at, expires_at,
              data.customer_email, data.customer_name, data.notes))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=500, detail="Token collision, try again")
    finally:
        conn.close()

    return {
        "success": True,
        "token": token,
        "plan_type": data.plan_type,
        "max_devices": max_devices,
        "expires_at": expires_at,
        "created_at": created_at
    }

@app.get("/admin/list-tokens")
def list_tokens(x_admin_key: str = Header(...), active_only: bool = False):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")

    conn = get_db()
    c = conn.cursor()

    if active_only:
        c.execute('''
            SELECT l.*, COUNT(d.id) as active_devices 
            FROM licenses l 
            LEFT JOIN devices d ON l.token = d.token AND d.is_active = 1
            WHERE l.is_active = 1 AND l.is_revoked = 0
            GROUP BY l.token
            ORDER BY l.created_at DESC
        ''')
    else:
        c.execute('''
            SELECT l.*, COUNT(d.id) as active_devices 
            FROM licenses l 
            LEFT JOIN devices d ON l.token = d.token AND d.is_active = 1
            GROUP BY l.token
            ORDER BY l.created_at DESC
        ''')

    rows = c.fetchall()
    conn.close()

    tokens = []
    for row in rows:
        tokens.append({
            "token": row["token"],
            "plan_type": row["plan_type"],
            "max_devices": row["max_devices"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "is_active": bool(row["is_active"]),
            "is_revoked": bool(row["is_revoked"]),
            "customer_email": row["customer_email"],
            "customer_name": row["customer_name"],
            "notes": row["notes"],
            "active_devices": row["active_devices"],
            "total_activations": row["total_activations"]
        })

    return {"success": True, "tokens": tokens, "count": len(tokens)}

@app.post("/admin/revoke-token")
def revoke_token(data: RevokeRequest, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")

    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE licenses SET is_revoked = 1, notes = COALESCE(notes, "") || " | REVOKED: " || ? WHERE token = ?',
              (data.reason or "No reason", data.token))
    if c.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Token not found")
    conn.commit()
    conn.close()

    return {"success": True, "message": f"Token {data.token} revoked"}

@app.post("/admin/extend-token")
def extend_token(token: str, additional_days: int, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT expires_at FROM licenses WHERE token = ?', (token,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Token not found")

    current_expires = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else datetime.utcnow()
    new_expires = current_expires + timedelta(days=additional_days)

    c.execute('UPDATE licenses SET expires_at = ? WHERE token = ?', (new_expires.isoformat(), token))
    conn.commit()
    conn.close()

    return {"success": True, "new_expires_at": new_expires.isoformat()}

@app.get("/admin/token-details/{token}")
def token_details(token: str, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")

    conn = get_db()
    c = conn.cursor()

    c.execute('SELECT * FROM licenses WHERE token = ?', (token,))
    license_row = c.fetchone()
    if not license_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Token not found")

    c.execute('SELECT * FROM devices WHERE token = ? ORDER BY first_seen DESC', (token,))
    devices = [dict(row) for row in c.fetchall()]

    c.execute('SELECT * FROM heartbeats WHERE token = ? ORDER BY timestamp DESC LIMIT 50', (token,))
    heartbeats = [dict(row) for row in c.fetchall()]

    conn.close()

    return {
        "success": True,
        "license": dict(license_row),
        "devices": devices,
        "recent_heartbeats": heartbeats
    }

# ==================== BOT ENDPOINTS ====================
@app.post("/bot/validate")
def validate_token(data: TokenValidate):
    conn = get_db()
    c = conn.cursor()

    c.execute('SELECT * FROM licenses WHERE token = ?', (data.token,))
    license_row = c.fetchone()

    if not license_row:
        conn.close()
        return {"valid": False, "error": "INVALID_TOKEN", "message": "Token not found"}

    if not license_row["is_active"]:
        conn.close()
        return {"valid": False, "error": "INACTIVE", "message": "Token is inactive"}

    if license_row["is_revoked"]:
        conn.close()
        return {"valid": False, "error": "REVOKED", "message": "Token has been revoked"}

    if license_row["expires_at"]:
        expires = datetime.fromisoformat(license_row["expires_at"])
        if datetime.utcnow() > expires:
            conn.close()
            return {"valid": False, "error": "EXPIRED", "message": "Token expired"}

    hw_hash = hash_hardware_id(data.hardware_id)
    c.execute('SELECT * FROM devices WHERE token = ? AND hardware_id = ?', (data.token, hw_hash))
    existing_device = c.fetchone()

    if existing_device:
        c.execute('UPDATE devices SET last_seen = ?, is_active = 1 WHERE id = ?',
                  (datetime.utcnow().isoformat(), existing_device["id"]))
        conn.commit()
        conn.close()
        return {
            "valid": True,
            "plan_type": license_row["plan_type"],
            "max_devices": license_row["max_devices"],
            "expires_at": license_row["expires_at"],
            "message": "Welcome back!"
        }

    c.execute('SELECT COUNT(*) as count FROM devices WHERE token = ? AND is_active = 1', (data.token,))
    active_count = c.fetchone()["count"]

    if active_count >= license_row["max_devices"]:
        conn.close()
        return {
            "valid": False,
            "error": "DEVICE_LIMIT",
            "message": f"Device limit reached ({license_row['max_devices']} devices max). Contact support."
        }

    now = datetime.utcnow().isoformat()
    c.execute('''
        INSERT INTO devices (token, hardware_id, device_name, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?)
    ''', (data.token, hw_hash, data.device_name or "Unknown", now, now))

    c.execute('UPDATE licenses SET total_activations = total_activations + 1 WHERE token = ?', (data.token,))
    conn.commit()
    conn.close()

    return {
        "valid": True,
        "plan_type": license_row["plan_type"],
        "max_devices": license_row["max_devices"],
        "expires_at": license_row["expires_at"],
        "message": "Activation successful!"
    }

@app.post("/bot/heartbeat")
def bot_heartbeat(data: HeartbeatRequest):
    conn = get_db()
    c = conn.cursor()

    c.execute('SELECT * FROM licenses WHERE token = ?', (data.token,))
    license_row = c.fetchone()

    if not license_row:
        conn.close()
        return {"valid": False, "error": "INVALID_TOKEN"}

    if license_row["is_revoked"]:
        conn.close()
        return {"valid": False, "error": "REVOKED"}

    if license_row["expires_at"]:
        expires = datetime.fromisoformat(license_row["expires_at"])
        if datetime.utcnow() > expires:
            conn.close()
            return {"valid": False, "error": "EXPIRED"}

    hw_hash = hash_hardware_id(data.hardware_id)
    c.execute('SELECT * FROM devices WHERE token = ? AND hardware_id = ?', (data.token, hw_hash))
    device = c.fetchone()

    if not device:
        conn.close()
        return {"valid": False, "error": "DEVICE_NOT_REGISTERED"}

    now = datetime.utcnow().isoformat()
    c.execute('UPDATE devices SET last_seen = ? WHERE id = ?', (now, device["id"]))
    c.execute('''
        INSERT INTO heartbeats (token, hardware_id, timestamp, ip_address)
        VALUES (?, ?, ?, ?)
    ''', (data.token, hw_hash, now, "0.0.0.0"))
    conn.commit()
    conn.close()

    return {"valid": True, "message": "Heartbeat OK"}

@app.get("/bot/check-revoked/{token}")
def check_revoked(token: str, hardware_id: str):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT is_revoked FROM licenses WHERE token = ?', (token,))
    row = c.fetchone()
    conn.close()

    if not row:
        return {"revoked": True, "error": "TOKEN_NOT_FOUND"}

    return {"revoked": bool(row["is_revoked"])}

# ==================== HEALTH CHECK ====================
@app.get("/")
def root():
    return {
        "service": "Goldmine License Server",
        "version": "1.0",
        "status": "running"
    }

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ==================== RUN ====================
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
