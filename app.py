from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import bcrypt
import jwt
import uuid
import json
import os
from datetime import datetime, timedelta
import hashlib
import secrets

app = Flask(__name__, static_folder='static')
CORS(app)

# Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-jwt-secret-key')
DATA_DIR = 'data'

# Ensure data directory exists
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# File paths
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
KEYS_FILE = os.path.join(DATA_DIR, 'keys.json')
SESSIONS_FILE = os.path.join(DATA_DIR, 'sessions.json')
LOGS_FILE = os.path.join(DATA_DIR, 'logs.json')

# Initialize JSON files if they don't exist
def init_json_file(file_path, default_data):
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump(default_data, f, indent=2)

init_json_file(USERS_FILE, [])
init_json_file(KEYS_FILE, [])
init_json_file(SESSIONS_FILE, [])
init_json_file(LOGS_FILE, [])

# File operations
def read_json_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except:
        return []

def write_json_file(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

def add_log(action, details):
    logs = read_json_file(LOGS_FILE)
    logs.append({
        'id': str(uuid.uuid4()),
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'details': details
    })
    write_json_file(LOGS_FILE, logs)

# Authentication helpers
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user):
    payload = {
        'user_id': user['id'],
        'email': user['email'],
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_license_key():
    return str(uuid.uuid4())

def generate_md5_token():
    """Generate MD5 token similar to original system"""
    random_data = str(secrets.randbits(128)) + str(datetime.now().timestamp())
    return hashlib.md5(random_data.encode()).hexdigest()

# Authentication decorator
def require_auth(f):
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({'message': 'Invalid token'}), 401
        
        # Find user
        users = read_json_file(USERS_FILE)
        user = next((u for u in users if u['id'] == payload['user_id']), None)
        if not user:
            return jsonify({'message': 'User not found'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password required'}), 400
    
    users = read_json_file(USERS_FILE)
    
    # Check if user exists
    if any(user['email'] == email for user in users):
        return jsonify({'message': 'User already exists'}), 400
    
    # Create new user
    user = {
        'id': str(uuid.uuid4()),
        'email': email,
        'password': hash_password(password),
        'created_at': datetime.now().isoformat()
    }
    
    users.append(user)
    write_json_file(USERS_FILE, users)
    
    # Create JWT token
    token = create_jwt_token(user)
    
    add_log('user_register', {'email': email})
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'email': user['email']
        }
    })

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password required'}), 400
    
    users = read_json_file(USERS_FILE)
    user = next((u for u in users if u['email'] == email), None)
    
    if not user or not verify_password(password, user['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = create_jwt_token(user)
    
    add_log('user_login', {'email': email})
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'email': user['email']
        }
    })

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def get_current_user():
    return jsonify({
        'id': request.current_user['id'],
        'email': request.current_user['email']
    })

# Dashboard routes
@app.route('/api/dashboard/stats', methods=['GET'])
@require_auth
def get_dashboard_stats():
    keys = read_json_file(KEYS_FILE)
    sessions = read_json_file(SESSIONS_FILE)
    
    user_keys = [k for k in keys if k.get('owner_id') == request.current_user['id'] or k.get('userId') == request.current_user['id']]
    
    current_month = datetime.now().strftime('%Y-%m')
    this_month_sessions = [s for s in sessions if s.get('timestamp', '').startswith(current_month)]
    
    return jsonify({
        'totalKeys': len(user_keys),
        'totalSessions': len(sessions),
        'thisMonth': len(this_month_sessions)
    })

# License key management
@app.route('/api/keys', methods=['GET'])
@require_auth
def get_keys():
    keys = read_json_file(KEYS_FILE)
    user_keys = [k for k in keys if k.get('owner_id') == request.current_user['id'] or k.get('userId') == request.current_user['id']]
    return jsonify(user_keys)

@app.route('/api/keys', methods=['POST'])
@require_auth
def create_key():
    data = request.get_json()
    key_name = data.get('keyName')
    key_type = data.get('keyType', 'basic')
    max_users = data.get('maxUsers', 1)
    
    if not key_name:
        return jsonify({'message': 'Key name is required'}), 400
    
    keys = read_json_file(KEYS_FILE)
    
    # Check if keyName already exists for this user
    if any(k['keyName'] == key_name and (k.get('owner_id') == request.current_user['id'] or k.get('userId') == request.current_user['id']) for k in keys):
        return jsonify({'message': 'Key name already exists'}), 400
    
    new_key = {
        'id': str(uuid.uuid4()),
        'keyName': key_name,
        'key': generate_license_key(),
        'keyType': key_type,
        'maxUsers': max_users,
        'currentUsers': 0,
        'status': 'active',
        'owner_id': request.current_user['id'],
        'created_at': datetime.now().isoformat(),
        'expiresAt': None
    }
    
    keys.append(new_key)
    write_json_file(KEYS_FILE, keys)
    
    add_log('key_created', {'keyName': key_name, 'keyType': key_type})
    
    return jsonify(new_key)

@app.route('/api/keys/<key_id>', methods=['DELETE'])
@require_auth
def delete_key(key_id):
    keys = read_json_file(KEYS_FILE)
    
    # Find key and check ownership
    key_to_delete = None
    for i, key in enumerate(keys):
        if key['id'] == key_id and (key.get('owner_id') == request.current_user['id'] or key.get('userId') == request.current_user['id']):
            key_to_delete = keys.pop(i)
            break
    
    if not key_to_delete:
        return jsonify({'message': 'Key not found or access denied'}), 404
    
    # Remove related sessions
    sessions = read_json_file(SESSIONS_FILE)
    updated_sessions = [s for s in sessions if s.get('keyName') != key_to_delete['keyName']]
    write_json_file(SESSIONS_FILE, updated_sessions)
    
    write_json_file(KEYS_FILE, keys)
    
    add_log('key_deleted', {'keyName': key_to_delete['keyName'], 'keyId': key_id})
    
    return jsonify({'message': 'Key deleted successfully'})

@app.route('/api/keys/<key_id>/toggle', methods=['POST'])
@require_auth
def toggle_key_status(key_id):
    keys = read_json_file(KEYS_FILE)
    
    # Find key and check ownership
    key_to_toggle = None
    for key in keys:
        if key['id'] == key_id and (key.get('owner_id') == request.current_user['id'] or key.get('userId') == request.current_user['id']):
            key_to_toggle = key
            break
    
    if not key_to_toggle:
        return jsonify({'message': 'Key not found or access denied'}), 404
    
    # Toggle status
    new_status = 'disabled' if key_to_toggle['status'] == 'active' else 'active'
    key_to_toggle['status'] = new_status
    key_to_toggle['updatedAt'] = datetime.now().isoformat()
    
    # If disabling, remove active sessions
    if new_status == 'disabled':
        sessions = read_json_file(SESSIONS_FILE)
        updated_sessions = [s for s in sessions if s.get('keyName') != key_to_toggle['keyName']]
        write_json_file(SESSIONS_FILE, updated_sessions)
        key_to_toggle['currentUsers'] = 0
    
    write_json_file(KEYS_FILE, keys)
    
    add_log('key_status_changed', {
        'keyName': key_to_toggle['keyName'], 
        'keyId': key_id, 
        'newStatus': new_status
    })
    
    return jsonify({
        'message': f'Key {new_status}',
        'status': new_status,
        'key': key_to_toggle
    })

@app.route('/api/keys/<key_id>', methods=['PUT'])
@require_auth
def update_key(key_id):
    data = request.get_json()
    keys = read_json_file(KEYS_FILE)
    
    # Find key and check ownership
    key_to_update = None
    for key in keys:
        if key['id'] == key_id and (key.get('owner_id') == request.current_user['id'] or key.get('userId') == request.current_user['id']):
            key_to_update = key
            break
    
    if not key_to_update:
        return jsonify({'message': 'Key not found or access denied'}), 404
    
    # Update allowed fields
    if 'keyName' in data:
        # Check if new name already exists
        new_name = data['keyName']
        if any(k['keyName'] == new_name and k['id'] != key_id and (k.get('owner_id') == request.current_user['id'] or k.get('userId') == request.current_user['id']) for k in keys):
            return jsonify({'message': 'Key name already exists'}), 400
        key_to_update['keyName'] = new_name
    
    if 'keyType' in data:
        key_to_update['keyType'] = data['keyType']
    
    if 'maxUsers' in data:
        key_to_update['maxUsers'] = int(data['maxUsers'])
    
    key_to_update['updatedAt'] = datetime.now().isoformat()
    
    write_json_file(KEYS_FILE, keys)
    
    add_log('key_updated', {
        'keyName': key_to_update['keyName'], 
        'keyId': key_id,
        'changes': data
    })
    
    return jsonify(key_to_update)

# API logs endpoint
@app.route('/api/logs', methods=['GET'])
@require_auth
def get_api_logs():
    logs = read_json_file(LOGS_FILE)
    # Return last 50 logs
    return jsonify(logs[-50:])

# PUBG Mod Menu API - Connect endpoint
@app.route('/connect', methods=['POST'])
@app.route('/api/connect', methods=['POST'])
def connect_api():
    # Handle both JSON and form data
    if request.content_type == 'application/json':
        data = request.get_json()
        game = data.get('game')
        user_key = data.get('user_key')  # This is keyName from PUBG mod menu
        serial = data.get('serial')  # HWID
    else:
        game = request.form.get('game')
        user_key = request.form.get('user_key')  # This is keyName from PUBG mod menu
        serial = request.form.get('serial')  # HWID
    
    if not all([game, user_key, serial]):
        return jsonify({
            'status': False,
            'reason': 'Missing required parameters: game, user_key, serial'
        })
    
    # Find key by keyName (not the actual license key)
    keys = read_json_file(KEYS_FILE)
    key = next((k for k in keys if k['keyName'] == user_key), None)
    
    if not key:
        add_log('connect_failed', {
            'reason': 'Key not found',
            'keyName': user_key,
            'hwid': serial
        })
        return jsonify({
            'status': False,
            'reason': 'Invalid key name'
        })
    
    if key['status'] != 'active':
        add_log('connect_failed', {
            'reason': 'Key inactive',
            'keyName': user_key,
            'hwid': serial
        })
        return jsonify({
            'status': False,
            'reason': 'Key is not active'
        })
    
    # Check max users limit
    sessions = read_json_file(SESSIONS_FILE)
    active_sessions = [s for s in sessions if s.get('keyName') == user_key]
    
    # Check if this HWID already has a session
    existing_session = next((s for s in active_sessions if s.get('hwid') == serial), None)
    
    if not existing_session and len(active_sessions) >= key['maxUsers']:
        add_log('connect_failed', {
            'reason': 'Max users reached',
            'keyName': user_key,
            'hwid': serial,
            'maxUsers': key['maxUsers'],
            'currentUsers': len(active_sessions)
        })
        return jsonify({
            'status': False,
            'reason': f'Maximum users ({key["maxUsers"]}) reached for this key'
        })
    
    # Create or update session
    if not existing_session:
        session = {
            'id': str(uuid.uuid4()),
            'keyName': user_key,
            'licenseKey': key['key'],
            'hwid': serial,
            'game': game,
            'timestamp': datetime.now().isoformat(),
            'token': generate_md5_token(),
            'rng': int(datetime.now().timestamp())
        }
        sessions.append(session)
    else:
        # Update existing session
        existing_session['timestamp'] = datetime.now().isoformat()
        existing_session['token'] = generate_md5_token()
        existing_session['rng'] = int(datetime.now().timestamp())
        session = existing_session
    
    write_json_file(SESSIONS_FILE, sessions)
    
    # Update key current users count
    active_sessions_count = len([s for s in sessions if s.get('keyName') == user_key])
    for k in keys:
        if k['keyName'] == user_key:
            k['currentUsers'] = active_sessions_count
            break
    write_json_file(KEYS_FILE, keys)
    
    add_log('connect_success', {
        'keyName': user_key,
        'hwid': serial,
        'game': game,
        'token': session['token']
    })
    
    return jsonify({
        'status': True,
        'data': {
            'token': session['token'],
            'rng': session['rng'],
            'keyName': user_key,
            'keyType': key['keyType'],
            'expiresAt': key['expiresAt'],
            'maxUsers': key['maxUsers'],
            'currentUsers': active_sessions_count
        }
    })

# Disconnect endpoint
@app.route('/disconnect', methods=['POST'])
@app.route('/api/disconnect', methods=['POST'])
def disconnect_api():
    # Handle both JSON and form data
    if request.content_type == 'application/json':
        data = request.get_json()
        user_key = data.get('user_key')  # keyName
        serial = data.get('serial')  # HWID
    else:
        user_key = request.form.get('user_key')  # keyName
        serial = request.form.get('serial')  # HWID
    
    if not all([user_key, serial]):
        return jsonify({
            'status': False,
            'reason': 'Missing required parameters: user_key, serial'
        })
    
    sessions = read_json_file(SESSIONS_FILE)
    
    # Find and remove session
    updated_sessions = [s for s in sessions if not (s.get('keyName') == user_key and s.get('hwid') == serial)]
    
    if len(updated_sessions) == len(sessions):
        return jsonify({
            'status': False,
            'reason': 'Session not found'
        })
    
    write_json_file(SESSIONS_FILE, updated_sessions)
    
    # Update key current users count
    keys = read_json_file(KEYS_FILE)
    remaining_sessions = [s for s in updated_sessions if s.get('keyName') == user_key]
    for key in keys:
        if key['keyName'] == user_key:
            key['currentUsers'] = len(remaining_sessions)
            break
    write_json_file(KEYS_FILE, keys)
    
    add_log('disconnect_success', {
        'keyName': user_key,
        'hwid': serial
    })
    
    return jsonify({'status': True})

# License validation endpoint (for external apps)
@app.route('/api/validate/<license_key>', methods=['POST'])
def validate_license(license_key):
    data = request.get_json()
    hwid = data.get('hwid')
    
    if not hwid:
        return jsonify({
            'valid': False,
            'message': 'HWID required'
        }), 400
    
    keys = read_json_file(KEYS_FILE)
    key = next((k for k in keys if k['key'] == license_key), None)
    
    if not key:
        return jsonify({
            'valid': False,
            'message': 'Invalid license key'
        })
    
    if key['status'] != 'active':
        return jsonify({
            'valid': False,
            'message': 'License key is inactive'
        })
    
    # Check if there's an active session for this key and HWID
    sessions = read_json_file(SESSIONS_FILE)
    session = next((s for s in sessions if s.get('licenseKey') == license_key and s.get('hwid') == hwid), None)
    
    return jsonify({
        'valid': True,
        'keyName': key['keyName'],
        'keyType': key['keyType'],
        'expiresAt': key['expiresAt'],
        'hasActiveSession': session is not None,
        'sessionInfo': {
            'token': session['token'],
            'timestamp': session['timestamp']
        } if session else None
    })

# API status endpoints
@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({
        'status': True,
        'message': 'PUBG Mod Menu API Sistemi Aktif - Python/Flask Edition',
        'storage': 'JSON File Storage',
        'info': 'Bu sistem orijinal GameKeyPanel ile %100 uyumludur',
        'pubg_integration': {
            'mod_menu_usage': 'Mod menu user_key parametresine keyName değerini gönderir',
            'hwid_tracking': 'HWID bazlı kullanıcı sınırları aktif',
            'session_management': 'Otomatik session yönetimi ve cleanup'
        },
        'endpoints': {
            'connect': {
                'url': '/connect veya /api/connect',
                'method': 'POST',
                'format': 'application/x-www-form-urlencoded',
                'parameters': 'game=PUBG&user_key={key_name}&serial={hwid}',
                'description': 'PUBG mod menu bağlantısı için ana endpoint'
            },
            'disconnect': {
                'url': '/disconnect veya /api/disconnect',
                'method': 'POST',
                'format': 'application/x-www-form-urlencoded',
                'parameters': 'user_key={key_name}&serial={hwid}',
                'description': 'PUBG mod menu bağlantı kesme endpoint'
            },
            'validate': {
                'url': '/api/validate/{license_key}',
                'method': 'POST',
                'format': 'application/json',
                'parameters': '{"hwid": "hardware_id"}',
                'description': 'Harici uygulamalar için anahtar doğrulama'
            }
        },
        'example_usage': {
            'connect': 'curl -X POST /connect -d "game=PUBG&user_key=YourKeyName&serial=hwid123"',
            'disconnect': 'curl -X POST /disconnect -d "user_key=YourKeyName&serial=hwid123"',
            'validate': 'curl -X POST /api/validate/YOUR_LICENSE_KEY -H "Content-Type: application/json" -d \'{"hwid": "hwid123"}\''
        },
        'timestamp': datetime.now().isoformat()
    })

@app.route('/connect', methods=['GET'])
def connect_info():
    return jsonify({
        'status': True,
        'message': 'PUBG Mod Menu Connect Endpoint Aktif',
        'version': 'Python/Flask Edition - GameKeyPanel Compatible',
        'storage': 'JSON File Storage',
        'info': 'Bu endpoint PUBG mod menu POST istekleri için hazırlanmıştır.',
        'integration_note': 'Mod menu user_key parametresine keyName (kullanıcının verdiği isim) gönderir',
        'usage': {
            'method': 'POST',
            'contentType': 'application/x-www-form-urlencoded',
            'required_parameters': {
                'game': 'PUBG (sabit değer)',
                'user_key': 'keyName (kullanıcının anahtara verdiği isim)',
                'serial': 'hwid (donanım kimliği)'
            }
        },
        'example': 'curl -X POST /connect -d "game=PUBG&user_key=YourKeyName&serial=hwid123"',
        'response_format': {
            'success': {
                'status': True,
                'data': {
                    'token': 'generated_md5_token',
                    'rng': 'unix_timestamp',
                    'keyName': 'key_name',
                    'keyType': 'basic|premium|lifetime',
                    'expiresAt': 'iso_date_or_null',
                    'maxUsers': 'number',
                    'currentUsers': 'number'
                }
            },
            'error': {
                'status': False,
                'reason': 'error_description'
            }
        }
    })

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KeyPanel - Professional License Management</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .container {
            max-width: 500px;
            width: 100%;
            padding: 2rem;
            margin: 0 1rem;
        }
        
        .logo {
            font-size: 2.5rem;
            font-weight: bold;
            text-align: center;
            color: white;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            text-align: center;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 2rem;
            font-size: 1.1rem;
        }
        
        .landing {
            text-align: center;
        }
        
        .auth-form {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            display: none;
        }
        
        .auth-form.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #333;
        }
        
        .form-group input, .form-group select {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            margin: 0.5rem;
            min-width: 120px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .btn-secondary {
            background: #6c757d;
        }
        
        .btn-secondary:hover {
            box-shadow: 0 5px 15px rgba(108, 117, 125, 0.4);
        }
        
        .toggle-link {
            color: #667eea;
            text-decoration: none;
            cursor: pointer;
        }
        
        .toggle-link:hover {
            text-decoration: underline;
        }
        
        .dashboard {
            display: none;
        }
        
        .dashboard.active {
            display: block;
        }
        
        .user-info {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 1.5rem;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-label {
            font-size: 0.9rem;
            color: #666;
        }
        
        .error {
            color: #e74c3c;
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }
        
        .success {
            color: #27ae60;
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }
        
        .keys-list {
            text-align: left;
            margin-top: 2rem;
        }
        
        .key-item {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        
        .key-value {
            font-family: monospace;
            background: #e9ecef;
            padding: 0.5rem;
            border-radius: 4px;
            margin: 0.5rem 0;
            word-break: break-all;
        }
        
        #apiTest {
            display: none;
            margin-top: 2rem;
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
        }
        
        #testResults {
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 0.8rem;
            max-height: 300px;
            overflow-y: auto;
            background: #e9ecef;
            padding: 1rem;
            border-radius: 4px;
        }
        
        .btn-small {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 0.4rem 0.8rem;
            border-radius: 4px;
            font-size: 0.8rem;
            cursor: pointer;
            min-width: 60px;
        }
        
        .btn-small:hover {
            opacity: 0.9;
        }
        
        .btn-danger {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔑 KeyPanel</div>
        <div class="subtitle">Professional License Management System</div>
        
        <!-- Landing -->
        <div id="landing" class="landing">
            <button class="btn" onclick="showLogin()">Login</button>
            <button class="btn btn-secondary" onclick="showRegister()">Register</button>
        </div>
        
        <!-- Login Form -->
        <div id="loginForm" class="auth-form">
            <h2 style="margin-bottom: 1.5rem;">Login</h2>
            <div id="loginError" class="error" style="display: none;"></div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="loginEmail" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="loginPassword" required>
            </div>
            <button class="btn" onclick="login()">Login</button>
            <div style="margin-top: 1rem; text-align: center;">
                Don't have an account? <a href="#" onclick="showRegister()" class="toggle-link">Register here</a>
            </div>
        </div>
        
        <!-- Register Form -->
        <div id="registerForm" class="auth-form">
            <h2 style="margin-bottom: 1.5rem;">Register</h2>
            <div id="registerError" class="error" style="display: none;"></div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="registerEmail" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="registerPassword" required>
            </div>
            <button class="btn" onclick="register()">Register</button>
            <div style="margin-top: 1rem; text-align: center;">
                Already have an account? <a href="#" onclick="showLogin()" class="toggle-link">Login here</a>
            </div>
        </div>
        
        <!-- Dashboard -->
        <div id="dashboard" class="auth-form dashboard">
            <div class="user-info">
                <h3>Welcome back!</h3>
                <p>Email: <span id="userEmail"></span></p>
                <div style="margin-top: 1rem;">
                    <button class="btn" onclick="showCreateKey()">Create New Key</button>
                    <button class="btn btn-secondary" onclick="testConnectAPI()">Test Connect API</button>
                    <button class="btn btn-secondary" onclick="showLogs()">View Logs</button>
                    <button class="btn btn-secondary" onclick="logout()">Logout</button>
                </div>
            </div>
            
            <div id="dashboardStats"></div>
            <div id="dashboardKeys" class="keys-list"></div>
            
            <div id="apiTest">
                <h4>API Test Results</h4>
                <pre id="testResults"></pre>
            </div>
        </div>
        
        <!-- Create Key Form -->
        <div id="createKeyForm" class="auth-form">
            <h2 style="margin-bottom: 1.5rem;">Create License Key</h2>
            <div id="createKeyError" class="error" style="display: none;"></div>
            <div class="form-group">
                <label>Key Name</label>
                <input type="text" id="keyName" required>
            </div>
            <div class="form-group">
                <label>Key Type</label>
                <select id="keyType" style="width: 100%; padding: 0.75rem; border: 2px solid #e1e5e9; border-radius: 8px;">
                    <option value="basic">Basic</option>
                    <option value="premium">Premium</option>
                    <option value="lifetime">Lifetime</option>
                </select>
            </div>
            <div class="form-group">
                <label>Max Users</label>
                <input type="number" id="maxUsers" value="1" min="1">
            </div>
            <button class="btn" onclick="createKey()">Create Key</button>
            <button class="btn btn-secondary" onclick="showDashboard()">Back to Dashboard</button>
        </div>
        
        <!-- Logs View -->
        <div id="logsView" class="auth-form">
            <h2 style="margin-bottom: 1.5rem;">API Logs</h2>
            <div id="logsContainer" style="max-height: 400px; overflow-y: auto;">
                Loading logs...
            </div>
            <button class="btn btn-secondary" onclick="showDashboard()">Back to Dashboard</button>
        </div>
    </div>

    <script src="/static/script.js"></script>
</body>
</html>
    ''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)