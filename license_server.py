from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import hashlib
import secrets
import os
import psycopg2
from typing import Optional

app = FastAPI(title='Goldmine License Server', version='1.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

DATABASE_URL = os.getenv('DATABASE_URL')
ADMIN_KEY = os.getenv('ADMIN_KEY', 'change-this-in-production-12345')

def get_db_connection():
    if not DATABASE_URL:
        raise Exception('DATABASE_URL not set')
    return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS licenses (id SERIAL PRIMARY KEY, token VARCHAR(32) UNIQUE NOT NULL, plan_type VARCHAR(10) NOT NULL DEFAULT 'solo', max_devices INTEGER NOT NULL DEFAULT 1, created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP, is_active BOOLEAN NOT NULL DEFAULT TRUE, is_revoked BOOLEAN NOT NULL DEFAULT FALSE, customer_email VARCHAR(255), customer_name VARCHAR(255), notes TEXT, total_activations INTEGER DEFAULT 0)")
    c.execute("CREATE TABLE IF NOT EXISTS devices (id SERIAL PRIMARY KEY, token VARCHAR(32) NOT NULL, hardware_id VARCHAR(32) NOT NULL, device_name VARCHAR(255), first_seen TIMESTAMP NOT NULL, last_seen TIMESTAMP NOT NULL, is_active BOOLEAN NOT NULL DEFAULT TRUE, UNIQUE(token, hardware_id))")
    c.execute("CREATE TABLE IF NOT EXISTS heartbeats (id SERIAL PRIMARY KEY, token VARCHAR(32) NOT NULL, hardware_id VARCHAR(32) NOT NULL, timestamp TIMESTAMP NOT NULL, ip_address VARCHAR(50))")
    conn.commit()
    c.close()
    conn.close()

try:
    init_db()
except Exception as e:
    print(f'DB init warning: {e}')

class TokenCreate(BaseModel):
    plan_type: str = 'solo'
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

def generate_token():
    parts = [secrets.token_uppercase(4) for _ in range(3)]
    return f'GM-PRO-{parts[0]}-{parts[1]}-{parts[2]}'

def hash_hardware_id(hw_id: str) -> str:
    return hashlib.sha256(hw_id.encode()).hexdigest()[:16]

@app.post('/admin/generate-token')
def generate_license_token(data: TokenCreate, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')
    token = generate_token()
    max_devices = 3 if data.plan_type == 'family' else 1
    created_at = datetime.utcnow()
    expires_at = (datetime.utcnow() + timedelta(days=data.duration_days)) if data.duration_days > 0 else None
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO licenses (token, plan_type, max_devices, created_at, expires_at, customer_email, customer_name, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)', (token, data.plan_type, max_devices, created_at, expires_at, data.customer_email, data.customer_name, data.notes))
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=f'Token generation failed: {str(e)}')
    finally:
        c.close()
        conn.close()
    return {'success': True, 'token': token, 'plan_type': data.plan_type, 'max_devices': max_devices, 'expires_at': expires_at.isoformat() if expires_at else None, 'created_at': created_at.isoformat()}

@app.get('/admin/list-tokens')
def list_tokens(x_admin_key: str = Header(...), active_only: bool = False):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')
    conn = get_db_connection()
    c = conn.cursor()
    if active_only:
        c.execute('SELECT l.*, COUNT(d.id) as active_devices FROM licenses l LEFT JOIN devices d ON l.token = d.token AND d.is_active = TRUE WHERE l.is_active = TRUE AND l.is_revoked = FALSE GROUP BY l.id, l.token ORDER BY l.created_at DESC')
    else:
        c.execute('SELECT l.*, COUNT(d.id) as active_devices FROM licenses l LEFT JOIN devices d ON l.token = d.token AND d.is_active = TRUE GROUP BY l.id, l.token ORDER BY l.created_at DESC')
    rows = c.fetchall()
    columns = [desc[0] for desc in c.description]
    c.close()
    conn.close()
    tokens = []
    for row in rows:
        d = dict(zip(columns, row))
        tokens.append({'token': d['token'], 'plan_type': d['plan_type'], 'max_devices': d['max_devices'], 'created_at': d['created_at'].isoformat() if d['created_at'] else None, 'expires_at': d['expires_at'].isoformat() if d['expires_at'] else None, 'is_active': d['is_active'], 'is_revoked': d['is_revoked'], 'customer_email': d['customer_email'], 'customer_name': d['customer_name'], 'notes': d['notes'], 'active_devices': d['active_devices'], 'total_activations': d['total_activations']})
    return {'success': True, 'tokens': tokens, 'count': len(tokens)}

@app.post('/admin/revoke-token')
def revoke_token(data: RevokeRequest, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('UPDATE licenses SET is_revoked = TRUE, notes = COALESCE(notes, '') || ' | REVOKED: ' || %s WHERE token = %s', (data.reason or 'No reason', data.token))
    if c.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail='Token not found')
    conn.commit()
    c.close()
    conn.close()
    return {'success': True, 'message': f'Token {data.token} revoked'}

@app.post('/admin/extend-token')
def extend_token(token: str, additional_days: int, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT expires_at FROM licenses WHERE token = %s', (token,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail='Token not found')
    current_expires = row[0] if row[0] else datetime.utcnow()
    new_expires = current_expires + timedelta(days=additional_days)
    c.execute('UPDATE licenses SET expires_at = %s WHERE token = %s', (new_expires, token))
    conn.commit()
    c.close()
    conn.close()
    return {'success': True, 'new_expires_at': new_expires.isoformat()}

@app.get('/admin/token-details/{token}')
def token_details(token: str, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM licenses WHERE token = %s', (token,))
    license_row = c.fetchone()
    if not license_row:
        c.close()
        conn.close()
        raise HTTPException(status_code=404, detail='Token not found')
    columns = [desc[0] for desc in c.description]
    license_dict = dict(zip(columns, license_row))
    c.execute('SELECT * FROM devices WHERE token = %s ORDER BY first_seen DESC', (token,))
    devices = [dict(zip([desc[0] for desc in c.description], row)) for row in c.fetchall()]
    c.execute('SELECT * FROM heartbeats WHERE token = %s ORDER BY timestamp DESC LIMIT 50', (token,))
    heartbeats = [dict(zip([desc[0] for desc in c.description], row)) for row in c.fetchall()]
    c.close()
    conn.close()
    return {'success': True, 'license': license_dict, 'devices': devices, 'recent_heartbeats': heartbeats}

@app.post('/bot/validate')
def validate_token(data: TokenValidate):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM licenses WHERE token = %s', (data.token,))
    license_row = c.fetchone()
    if not license_row:
        c.close(); conn.close()
        return {'valid': False, 'error': 'INVALID_TOKEN', 'message': 'Token not found'}
    columns = [desc[0] for desc in c.description]
    lic = dict(zip(columns, license_row))
    if not lic['is_active']:
        c.close(); conn.close()
        return {'valid': False, 'error': 'INACTIVE', 'message': 'Token is inactive'}
    if lic['is_revoked']:
        c.close(); conn.close()
        return {'valid': False, 'error': 'REVOKED', 'message': 'Token has been revoked'}
    if lic['expires_at']:
        if datetime.utcnow() > lic['expires_at']:
            c.close(); conn.close()
            return {'valid': False, 'error': 'EXPIRED', 'message': 'Token expired'}
    hw_hash = hash_hardware_id(data.hardware_id)
    c.execute('SELECT * FROM devices WHERE token = %s AND hardware_id = %s', (data.token, hw_hash))
    existing_device = c.fetchone()
    if existing_device:
        c.execute('UPDATE devices SET last_seen = %s, is_active = TRUE WHERE id = %s', (datetime.utcnow(), existing_device[0]))
        conn.commit(); c.close(); conn.close()
        return {'valid': True, 'plan_type': lic['plan_type'], 'max_devices': lic['max_devices'], 'expires_at': lic['expires_at'].isoformat() if lic['expires_at'] else None, 'message': 'Welcome back!'}
    c.execute('SELECT COUNT(*) FROM devices WHERE token = %s AND is_active = TRUE', (data.token,))
    active_count = c.fetchone()[0]
    if active_count >= lic['max_devices']:
        c.close(); conn.close()
        return {'valid': False, 'error': 'DEVICE_LIMIT', 'message': f'Device limit reached ({lic[chr(39)+chr(39)]max_devices{chr(39)+chr(39)]} devices max). Contact support.'}
    now = datetime.utcnow()
    c.execute('INSERT INTO devices (token, hardware_id, device_name, first_seen, last_seen) VALUES (%s, %s, %s, %s, %s)', (data.token, hw_hash, data.device_name or 'Unknown', now, now))
    c.execute('UPDATE licenses SET total_activations = total_activations + 1 WHERE token = %s', (data.token,))
    conn.commit(); c.close(); conn.close()
    return {'valid': True, 'plan_type': lic['plan_type'], 'max_devices': lic['max_devices'], 'expires_at': lic['expires_at'].isoformat() if lic['expires_at'] else None, 'message': 'Activation successful!'}

@app.post('/bot/heartbeat')
def bot_heartbeat(data: HeartbeatRequest):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM licenses WHERE token = %s', (data.token,))
    license_row = c.fetchone()
    if not license_row:
        c.close(); conn.close()
        return {'valid': False, 'error': 'INVALID_TOKEN'}
    columns = [desc[0] for desc in c.description]
    lic = dict(zip(columns, license_row))
    if lic['is_revoked']:
        c.close(); conn.close()
        return {'valid': False, 'error': 'REVOKED'}
    if lic['expires_at']:
        if datetime.utcnow() > lic['expires_at']:
            c.close(); conn.close()
            return {'valid': False, 'error': 'EXPIRED'}
    hw_hash = hash_hardware_id(data.hardware_id)
    c.execute('SELECT * FROM devices WHERE token = %s AND hardware_id = %s', (data.token, hw_hash))
    device = c.fetchone()
    if not device:
        c.close(); conn.close()
        return {'valid': False, 'error': 'DEVICE_NOT_REGISTERED'}
    now = datetime.utcnow()
    c.execute('UPDATE devices SET last_seen = %s WHERE id = %s', (now, device[0]))
    c.execute('INSERT INTO heartbeats (token, hardware_id, timestamp, ip_address) VALUES (%s, %s, %s, %s)', (data.token, hw_hash, now, '0.0.0.0'))
    conn.commit(); c.close(); conn.close()
    return {'valid': True, 'message': 'Heartbeat OK'}

@app.get('/bot/check-revoked/{token}')
def check_revoked(token: str, hardware_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT is_revoked FROM licenses WHERE token = %s', (token,))
    row = c.fetchone()
    c.close(); conn.close()
    if not row:
        return {'revoked': True, 'error': 'TOKEN_NOT_FOUND'}
    return {'revoked': row[0]}

@app.get('/')
def root():
    return {'service': 'Goldmine License Server', 'version': '1.0', 'status': 'running'}

@app.get('/health')
def health():
    return {'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}

if __name__ == '__main__':
    import uvicorn
    port = int(os.getenv('PORT', 8000))
    uvicorn.run(app, host='0.0.0.0', port=port)
