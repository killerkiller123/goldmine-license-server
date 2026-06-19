from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import hashlib
import secrets
import os
from typing import Optional

app = FastAPI(title='Goldmine License Server', version='1.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

ADMIN_KEY = os.getenv('ADMIN_KEY', 'change-this-in-production-12345')

# Pure in-memory storage
licenses_db = {}
devices_db = {}
heartbeats_db = {}

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
    created_at = datetime.utcnow().isoformat()
    expires_at = (datetime.utcnow() + timedelta(days=data.duration_days)).isoformat() if data.duration_days > 0 else None

    licenses_db[token] = {
        'token': token,
        'plan_type': data.plan_type,
        'max_devices': max_devices,
        'created_at': created_at,
        'expires_at': expires_at,
        'is_active': True,
        'is_revoked': False,
        'customer_email': data.customer_email,
        'customer_name': data.customer_name,
        'notes': data.notes,
        'total_activations': 0
    }
    devices_db[token] = []
    heartbeats_db[token] = []

    return {
        'success': True,
        'token': token,
        'plan_type': data.plan_type,
        'max_devices': max_devices,
        'expires_at': expires_at,
        'created_at': created_at
    }

@app.get('/admin/list-tokens')
def list_tokens(x_admin_key: str = Header(...), active_only: bool = False):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')

    tokens = []
    for token, lic in licenses_db.items():
        if active_only and (not lic['is_active'] or lic['is_revoked']):
            continue
        active_devices = sum(1 for d in devices_db.get(token, []) if d.get('is_active', True))
        tokens.append({
            'token': lic['token'],
            'plan_type': lic['plan_type'],
            'max_devices': lic['max_devices'],
            'created_at': lic['created_at'],
            'expires_at': lic['expires_at'],
            'is_active': lic['is_active'],
            'is_revoked': lic['is_revoked'],
            'customer_email': lic['customer_email'],
            'customer_name': lic['customer_name'],
            'notes': lic['notes'],
            'active_devices': active_devices,
            'total_activations': lic['total_activations']
        })

    return {'success': True, 'tokens': tokens, 'count': len(tokens)}

@app.post('/admin/revoke-token')
def revoke_token(data: RevokeRequest, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')

    if data.token not in licenses_db:
        raise HTTPException(status_code=404, detail='Token not found')

    licenses_db[data.token]['is_revoked'] = True
    licenses_db[data.token]['notes'] = (licenses_db[data.token]['notes'] or '') + ' | REVOKED: ' + (data.reason or 'No reason')

    return {'success': True, 'message': f'Token {data.token} revoked'}

@app.post('/admin/extend-token')
def extend_token(token: str, additional_days: int, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')

    if token not in licenses_db:
        raise HTTPException(status_code=404, detail='Token not found')

    current_expires = datetime.fromisoformat(licenses_db[token]['expires_at']) if licenses_db[token]['expires_at'] else datetime.utcnow()
    new_expires = current_expires + timedelta(days=additional_days)
    licenses_db[token]['expires_at'] = new_expires.isoformat()

    return {'success': True, 'new_expires_at': new_expires.isoformat()}

@app.get('/admin/token-details/{token}')
def token_details(token: str, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')

    if token not in licenses_db:
        raise HTTPException(status_code=404, detail='Token not found')

    return {
        'success': True,
        'license': licenses_db[token],
        'devices': devices_db.get(token, []),
        'recent_heartbeats': heartbeats_db.get(token, [])[-50:]
    }

@app.post('/bot/validate')
def validate_token(data: TokenValidate):
    if data.token not in licenses_db:
        return {'valid': False, 'error': 'INVALID_TOKEN', 'message': 'Token not found'}

    lic = licenses_db[data.token]

    if not lic['is_active']:
        return {'valid': False, 'error': 'INACTIVE', 'message': 'Token is inactive'}

    if lic['is_revoked']:
        return {'valid': False, 'error': 'REVOKED', 'message': 'Token has been revoked'}

    if lic['expires_at']:
        if datetime.utcnow() > datetime.fromisoformat(lic['expires_at']):
            return {'valid': False, 'error': 'EXPIRED', 'message': 'Token expired'}

    hw_hash = hash_hardware_id(data.hardware_id)
    devices = devices_db.get(data.token, [])

    for device in devices:
        if device['hardware_id'] == hw_hash:
            device['last_seen'] = datetime.utcnow().isoformat()
            device['is_active'] = True
            return {
                'valid': True,
                'plan_type': lic['plan_type'],
                'max_devices': lic['max_devices'],
                'expires_at': lic['expires_at'],
                'message': 'Welcome back!'
            }

    active_count = sum(1 for d in devices if d.get('is_active', True))

    if active_count >= lic['max_devices']:
        return {
            'valid': False,
            'error': 'DEVICE_LIMIT',
            'message': f"Device limit reached ({lic['max_devices']} devices max). Contact support."
        }

    now = datetime.utcnow().isoformat()
    devices.append({
        'hardware_id': hw_hash,
        'device_name': data.device_name or 'Unknown',
        'first_seen': now,
        'last_seen': now,
        'is_active': True
    })

    licenses_db[data.token]['total_activations'] += 1

    return {
        'valid': True,
        'plan_type': lic['plan_type'],
        'max_devices': lic['max_devices'],
        'expires_at': lic['expires_at'],
        'message': 'Activation successful!'
    }

@app.post('/bot/heartbeat')
def bot_heartbeat(data: HeartbeatRequest):
    if data.token not in licenses_db:
        return {'valid': False, 'error': 'INVALID_TOKEN'}

    lic = licenses_db[data.token]

    if lic['is_revoked']:
        return {'valid': False, 'error': 'REVOKED'}

    if lic['expires_at']:
        if datetime.utcnow() > datetime.fromisoformat(lic['expires_at']):
            return {'valid': False, 'error': 'EXPIRED'}

    hw_hash = hash_hardware_id(data.hardware_id)
    devices = devices_db.get(data.token, [])

    found = False
    for device in devices:
        if device['hardware_id'] == hw_hash:
            device['last_seen'] = datetime.utcnow().isoformat()
            found = True
            break

    if not found:
        return {'valid': False, 'error': 'DEVICE_NOT_REGISTERED'}

    heartbeats = heartbeats_db.get(data.token, [])
    heartbeats.append({
        'hardware_id': hw_hash,
        'timestamp': datetime.utcnow().isoformat(),
        'ip_address': '0.0.0.0'
    })
    heartbeats_db[data.token] = heartbeats[-100:]

    return {'valid': True, 'message': 'Heartbeat OK'}

@app.get('/bot/check-revoked/{token}')
def check_revoked(token: str, hardware_id: str):
    if token not in licenses_db:
        return {'revoked': True, 'error': 'TOKEN_NOT_FOUND'}
    return {'revoked': licenses_db[token]['is_revoked']}

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
