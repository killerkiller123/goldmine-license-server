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

# In-memory storage
licenses = {}
devices = {}

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

def hash_hardware_id(hw_id):
    return hashlib.sha256(hw_id.encode()).hexdigest()[:16]

@app.post('/admin/generate-token')
def generate_token_endpoint(data: TokenCreate, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')

    token = generate_token()
    max_devices = 3 if data.plan_type == 'family' else 1
    created_at = datetime.utcnow().isoformat()
    expires_at = None
    if data.duration_days > 0:
        expires_at = (datetime.utcnow() + timedelta(days=data.duration_days)).isoformat()

    licenses[token] = {
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
    devices[token] = []

    return {
        'success': True,
        'token': token,
        'plan_type': data.plan_type,
        'max_devices': max_devices,
        'expires_at': expires_at,
        'created_at': created_at
    }

@app.get('/admin/list-tokens')
def list_tokens(x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')

    tokens = []
    for token, lic in licenses.items():
        active_devices = sum(1 for d in devices.get(token, []) if d.get('is_active', True))
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

    if data.token not in licenses:
        raise HTTPException(status_code=404, detail='Token not found')

    licenses[data.token]['is_revoked'] = True
    licenses[data.token]['notes'] = (licenses[data.token]['notes'] or '') + ' | REVOKED'

    return {'success': True, 'message': f'Token {data.token} revoked'}

@app.get('/admin/token-details/{token}')
def token_details(token: str, x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail='Invalid admin key')

    if token not in licenses:
        raise HTTPException(status_code=404, detail='Token not found')

    return {
        'success': True,
        'license': licenses[token],
        'devices': devices.get(token, [])
    }

@app.post('/bot/validate')
def validate_token(data: TokenValidate):
    if data.token not in licenses:
        return {'valid': False, 'error': 'INVALID_TOKEN', 'message': 'Token not found'}

    lic = licenses[data.token]

    if not lic['is_active']:
        return {'valid': False, 'error': 'INACTIVE', 'message': 'Token is inactive'}

    if lic['is_revoked']:
        return {'valid': False, 'error': 'REVOKED', 'message': 'Token has been revoked'}

    if lic['expires_at']:
        if datetime.utcnow() > datetime.fromisoformat(lic['expires_at']):
            return {'valid': False, 'error': 'EXPIRED', 'message': 'Token expired'}

    hw_hash = hash_hardware_id(data.hardware_id)
    token_devices = devices.get(data.token, [])

    for device in token_devices:
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

    active_count = sum(1 for d in token_devices if d.get('is_active', True))

    if active_count >= lic['max_devices']:
        return {
            'valid': False,
            'error': 'DEVICE_LIMIT',
            'message': f"Device limit reached ({lic['max_devices']} devices max). Contact support."
        }

    now = datetime.utcnow().isoformat()
    token_devices.append({
        'hardware_id': hw_hash,
        'device_name': data.device_name or 'Unknown',
        'first_seen': now,
        'last_seen': now,
        'is_active': True
    })

    licenses[data.token]['total_activations'] += 1

    return {
        'valid': True,
        'plan_type': lic['plan_type'],
        'max_devices': lic['max_devices'],
        'expires_at': lic['expires_at'],
        'message': 'Activation successful!'
    }

@app.post('/bot/heartbeat')
def bot_heartbeat(data: HeartbeatRequest):
    if data.token not in licenses:
        return {'valid': False, 'error': 'INVALID_TOKEN'}

    lic = licenses[data.token]

    if lic['is_revoked']:
        return {'valid': False, 'error': 'REVOKED'}

    if lic['expires_at']:
        if datetime.utcnow() > datetime.fromisoformat(lic['expires_at']):
            return {'valid': False, 'error': 'EXPIRED'}

    hw_hash = hash_hardware_id(data.hardware_id)
    token_devices = devices.get(data.token, [])

    found = False
    for device in token_devices:
        if device['hardware_id'] == hw_hash:
            device['last_seen'] = datetime.utcnow().isoformat()
            found = True
            break

    if not found:
        return {'valid': False, 'error': 'DEVICE_NOT_REGISTERED'}

    return {'valid': True, 'message': 'Heartbeat OK'}

@app.get('/bot/check-revoked/{token}')
def check_revoked(token: str, hardware_id: str):
    if token not in licenses:
        return {'revoked': True, 'error': 'TOKEN_NOT_FOUND'}
    return {'revoked': licenses[token]['is_revoked']}

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
