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

# Global variable to store current user
current_user = None

# Middleware to verify JWT token
def authenticate_token(f):
    def wrapper(*args, **kwargs):
        global current_user
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Access token required'}), 401
        
        try:
            token = auth_header.split(' ')[1]
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            user_id = decoded['userId']
            
            users = read_json_file(USERS_FILE)
            user = next((u for u in users if u['id'] == user_id), None)
            if not user:
                return jsonify({'message': 'Invalid token'}), 401
            
            current_user = user
            return f(*args, **kwargs)
        except:
            return jsonify({'message': 'Invalid token'}), 403
    
    wrapper.__name__ = f.__name__
    return wrapper

# Middleware to check admin role
def require_admin(f):
    def wrapper(*args, **kwargs):
        global current_user
        if current_user.get('role') != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    
    wrapper.__name__ = f.__name__
    return wrapper

# Auth routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'user')
        
        if not username or not email or not password:
            return jsonify({'message': 'Missing required fields'}), 400
        
        users = read_json_file(USERS_FILE)
        
        # Check if user already exists
        if any(u['email'] == email for u in users):
            return jsonify({'message': 'User already exists'}), 400
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create new user
        user = {
            'id': str(uuid.uuid4()),
            'username': username,
            'email': email,
            'password': hashed_password,
            'role': role,
            'isActive': True,
            'createdAt': datetime.now().isoformat(),
            'updatedAt': datetime.now().isoformat()
        }
        
        users.append(user)
        write_json_file(USERS_FILE, users)
        
        # Generate JWT token
        token = jwt.encode({'userId': user['id']}, JWT_SECRET, algorithm='HS256')
        
        user_response = user.copy()
        del user_response['password']
        
        return jsonify({'user': user_response, 'token': token})
    
    except Exception as e:
        return jsonify({'message': 'Registration failed'}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        users = read_json_file(USERS_FILE)
        user = next((u for u in users if u['email'] == email), None)
        
        if not user:
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # Check password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        if not user['isActive']:
            return jsonify({'message': 'Account suspended'}), 401
        
        # Generate JWT token
        token = jwt.encode({'userId': user['id']}, JWT_SECRET, algorithm='HS256')
        
        user_response = user.copy()
        del user_response['password']
        
        return jsonify({'user': user_response, 'token': token})
    
    except Exception as e:
        return jsonify({'message': 'Login failed'}), 400

@app.route('/api/auth/me', methods=['GET'])
@authenticate_token
def get_me():
    global current_user
    user_response = current_user.copy()
    del user_response['password']
    return jsonify(user_response)

# User routes
@app.route('/api/users', methods=['GET'])
@authenticate_token
@require_admin
def get_users():
    users = read_json_file(USERS_FILE)
    for user in users:
        del user['password']
    return jsonify(users)

@app.route('/api/users/<user_id>', methods=['PUT'])
@authenticate_token
@require_admin
def update_user(user_id):
    try:
        data = request.json
        users = read_json_file(USERS_FILE)
        
        user_index = next((i for i, u in enumerate(users) if u['id'] == user_id), None)
        if user_index is None:
            return jsonify({'message': 'User not found'}), 404
        
        users[user_index].update(data)
        users[user_index]['updatedAt'] = datetime.now().isoformat()
        
        write_json_file(USERS_FILE, users)
        
        user_response = users[user_index].copy()
        del user_response['password']
        
        return jsonify(user_response)
    
    except Exception as e:
        return jsonify({'message': 'Update failed'}), 400

@app.route('/api/users/<user_id>', methods=['DELETE'])
@authenticate_token
@require_admin
def delete_user(user_id):
    try:
        users = read_json_file(USERS_FILE)
        users = [u for u in users if u['id'] != user_id]
        write_json_file(USERS_FILE, users)
        
        return jsonify({'message': 'User deleted'})
    
    except Exception as e:
        return jsonify({'message': 'Delete failed'}), 400

# License key routes
@app.route('/api/keys', methods=['GET'])
@authenticate_token
def get_keys():
    global current_user
    keys = read_json_file(KEYS_FILE)
    
    if current_user['role'] != 'admin':
        # Regular users can only see their own keys
        keys = [k for k in keys if k['userId'] == current_user['id']]
    
    return jsonify(keys)

@app.route('/api/keys', methods=['POST'])
@authenticate_token
def create_key():
    global current_user
    try:
        data = request.json
        key_name = data.get('keyName')
        key_type = data.get('keyType')
        max_users = data.get('maxUsers', 1)
        expires_at = data.get('expiresAt')
        
        if not key_name or not key_type:
            return jsonify({'message': 'Missing required fields'}), 400
        
        # Generate random key
        key_value = secrets.token_hex(16).upper()
        
        new_key = {
            'id': str(uuid.uuid4()),
            'key': key_value,
            'keyName': key_name,
            'userId': current_user['id'],
            'keyType': key_type,
            'status': 'active',
            'maxUsers': max_users,
            'currentUsers': 0,
            'expiresAt': expires_at,
            'lastUsed': None,
            'hwids': [],
            'createdAt': datetime.now().isoformat(),
            'updatedAt': datetime.now().isoformat()
        }
        
        keys = read_json_file(KEYS_FILE)
        keys.append(new_key)
        write_json_file(KEYS_FILE, keys)
        
        return jsonify(new_key)
    
    except Exception as e:
        return jsonify({'message': 'Key creation failed'}), 400

@app.route('/api/keys/<key_id>', methods=['PUT'])
@authenticate_token
def update_key(key_id):
    global current_user
    try:
        data = request.json
        keys = read_json_file(KEYS_FILE)
        
        key_index = next((i for i, k in enumerate(keys) if k['id'] == key_id), None)
        if key_index is None:
            return jsonify({'message': 'Key not found'}), 404
        
        # Check permissions
        if current_user['role'] != 'admin' and keys[key_index]['userId'] != current_user['id']:
            return jsonify({'message': 'Permission denied'}), 403
        
        keys[key_index].update(data)
        keys[key_index]['updatedAt'] = datetime.now().isoformat()
        
        write_json_file(KEYS_FILE, keys)
        
        return jsonify(keys[key_index])
    
    except Exception as e:
        return jsonify({'message': 'Update failed'}), 400

@app.route('/api/keys/<key_id>', methods=['DELETE'])
@authenticate_token
def delete_key(key_id):
    global current_user
    try:
        keys = read_json_file(KEYS_FILE)
        key_to_delete = next((k for k in keys if k['id'] == key_id), None)
        
        if not key_to_delete:
            return jsonify({'message': 'Key not found'}), 404
        
        # Check permissions
        if current_user['role'] != 'admin' and key_to_delete['userId'] != current_user['id']:
            return jsonify({'message': 'Permission denied'}), 403
        
        keys = [k for k in keys if k['id'] != key_id]
        write_json_file(KEYS_FILE, keys)
        
        return jsonify({'message': 'Key deleted'})
    
    except Exception as e:
        return jsonify({'message': 'Delete failed'}), 400

# Dashboard stats
@app.route('/api/dashboard/stats', methods=['GET'])
@authenticate_token
def get_dashboard_stats():
    global current_user
    users = read_json_file(USERS_FILE)
    keys = read_json_file(KEYS_FILE)
    sessions = read_json_file(SESSIONS_FILE)
    logs = read_json_file(LOGS_FILE)
    
    if current_user['role'] != 'admin':
        # Regular users see only their own stats
        user_keys = [k for k in keys if k['userId'] == current_user['id']]
        stats = {
            'totalUsers': 1,
            'activeKeys': len([k for k in user_keys if k['status'] == 'active']),
            'apiRequests': len([l for l in logs if l.get('userId') == current_user['id']]),
            'activeSessions': len([s for s in sessions if any(k['id'] == s['keyId'] for k in user_keys)])
        }
    else:
        stats = {
            'totalUsers': len(users),
            'activeKeys': len([k for k in keys if k['status'] == 'active']),
            'apiRequests': len(logs),
            'activeSessions': len(sessions)
        }
    
    return jsonify(stats)

# API logs
@app.route('/api/logs', methods=['GET'])
@authenticate_token
@require_admin
def get_logs():
    logs = read_json_file(LOGS_FILE)
    limit = request.args.get('limit', 100, type=int)
    
    # Sort by creation date (newest first) and limit
    logs.sort(key=lambda x: x['createdAt'], reverse=True)
    
    return jsonify(logs[:limit])

# Helper functions for storage operations
def create_api_log(endpoint, method, success, response, ip_address, user_agent, key_id=None, user_id=None, hwid=None):
    logs = read_json_file(LOGS_FILE)
    log_entry = {
        'id': str(uuid.uuid4()),
        'endpoint': endpoint,
        'method': method,
        'keyId': key_id,
        'userId': user_id,
        'hwid': hwid,
        'ipAddress': ip_address,
        'userAgent': user_agent,
        'response': response,
        'success': success,
        'createdAt': datetime.now().isoformat()
    }
    logs.append(log_entry)
    write_json_file(LOGS_FILE, logs)
    return log_entry

def get_license_key_by_key_or_name(key_or_name):
    keys = read_json_file(KEYS_FILE)
    # First try by exact key match
    key = next((k for k in keys if k['key'] == key_or_name), None)
    # If not found, try by key name
    if not key:
        key = next((k for k in keys if k['keyName'] == key_or_name), None)
    return key

def create_active_session(key_id, hwid, ip_address, user_agent):
    sessions = read_json_file(SESSIONS_FILE)
    # Remove existing session with same keyId and hwid
    sessions = [s for s in sessions if not (s['keyId'] == key_id and s['hwid'] == hwid)]
    
    new_session = {
        'id': str(uuid.uuid4()),
        'keyId': key_id,
        'hwid': hwid,
        'ipAddress': ip_address,
        'userAgent': user_agent,
        'lastSeen': datetime.now().isoformat(),
        'createdAt': datetime.now().isoformat()
    }
    sessions.append(new_session)
    write_json_file(SESSIONS_FILE, sessions)
    return new_session

def get_active_sessions_for_key(key_id):
    sessions = read_json_file(SESSIONS_FILE)
    return [s for s in sessions if s['keyId'] == key_id]

def remove_active_session(key_id, hwid):
    sessions = read_json_file(SESSIONS_FILE)
    sessions = [s for s in sessions if not (s['keyId'] == key_id and s['hwid'] == hwid)]
    write_json_file(SESSIONS_FILE, sessions)

def clean_expired_sessions():
    sessions = read_json_file(SESSIONS_FILE)
    five_minutes_ago = datetime.now() - timedelta(minutes=5)
    active_sessions = [s for s in sessions if datetime.fromisoformat(s['lastSeen']) > five_minutes_ago]
    write_json_file(SESSIONS_FILE, active_sessions)

# Connect API for PUBG mod menu integration
def connect_handler():
    try:
        # Mod menu sends form data: game=PUBG&user_key={key}&serial={hwid}
        user_key = request.form.get('user_key')
        serial = request.form.get('serial')
        game = request.form.get('game')
        
        # Fallback to JSON if form data is empty
        if not user_key and request.json:
            user_key = request.json.get('user_key')
        if not serial and request.json:
            serial = request.json.get('serial')
        if not game and request.json:
            game = request.json.get('game')
        
        if not user_key:
            create_api_log('/api/connect', 'POST', False, 'error: key required', 
                         request.remote_addr, request.headers.get('User-Agent', ''), hwid=serial)
            return jsonify({'status': False, 'reason': 'License key required'}), 400

        if not serial:
            create_api_log('/api/connect', 'POST', False, 'error: hwid required',
                         request.remote_addr, request.headers.get('User-Agent', ''), hwid=serial)
            return jsonify({'status': False, 'reason': 'Hardware ID required'}), 400

        license_key = get_license_key_by_key_or_name(user_key)
        
        if not license_key:
            create_api_log('/api/connect', 'POST', False, 'error: invalid key',
                         request.remote_addr, request.headers.get('User-Agent', ''), hwid=serial)
            return jsonify({'status': False, 'reason': 'Invalid license key'}), 401

        # Check if key is active
        if license_key['status'] != 'active':
            create_api_log('/api/connect', 'POST', False, 'error: key not active',
                         request.remote_addr, request.headers.get('User-Agent', ''), 
                         key_id=license_key['id'], hwid=serial)
            return jsonify({'status': False, 'reason': 'License key is suspended'}), 401

        # Check if key has expired
        if license_key['expiresAt'] and datetime.now() > datetime.fromisoformat(license_key['expiresAt']):
            # Update key status to expired
            keys = read_json_file(KEYS_FILE)
            key_index = next(i for i, k in enumerate(keys) if k['id'] == license_key['id'])
            keys[key_index]['status'] = 'expired'
            keys[key_index]['updatedAt'] = datetime.now().isoformat()
            write_json_file(KEYS_FILE, keys)
            
            create_api_log('/api/connect', 'POST', False, 'error: key expired',
                         request.remote_addr, request.headers.get('User-Agent', ''),
                         key_id=license_key['id'], hwid=serial)
            return jsonify({'status': False, 'reason': 'License key has expired'}), 401

        # Clean expired sessions first
        clean_expired_sessions()

        # Get current active sessions for this key
        active_sessions = get_active_sessions_for_key(license_key['id'])
        
        # Check if this HWID is already connected
        existing_session = next((s for s in active_sessions if s['hwid'] == serial), None)
        
        if existing_session:
            # Update existing session timestamp
            create_active_session(license_key['id'], serial, request.remote_addr, 
                                request.headers.get('User-Agent', ''))
        else:
            # Check if we've reached the max users limit
            if len(active_sessions) >= license_key['maxUsers']:
                create_api_log('/api/connect', 'POST', False, 'error: max users reached',
                             request.remote_addr, request.headers.get('User-Agent', ''),
                             key_id=license_key['id'], hwid=serial)
                return jsonify({'status': False, 'reason': f'Maximum users limit reached ({license_key["maxUsers"]})'}), 429

            # Create new session
            create_active_session(license_key['id'], serial, request.remote_addr,
                                request.headers.get('User-Agent', ''))

        # Update license key statistics
        updated_sessions = get_active_sessions_for_key(license_key['id'])
        keys = read_json_file(KEYS_FILE)
        key_index = next(i for i, k in enumerate(keys) if k['id'] == license_key['id'])
        keys[key_index]['lastUsed'] = datetime.now().isoformat()
        keys[key_index]['currentUsers'] = len(updated_sessions)
        keys[key_index]['updatedAt'] = datetime.now().isoformat()
        write_json_file(KEYS_FILE, keys)

        # Log successful connection
        create_api_log('/api/connect', 'POST', True, 'success: access granted',
                     request.remote_addr, request.headers.get('User-Agent', ''),
                     key_id=license_key['id'], user_id=license_key['userId'], hwid=serial)

        # Generate token and timestamp as expected by mod menu
        current_time = int(datetime.now().timestamp())
        auth_string = f"PUBG-{user_key}-{serial}-Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E"
        token = hashlib.md5(auth_string.encode()).hexdigest()

        return jsonify({
            'status': True,
            'data': {
                'token': token,
                'rng': current_time,
                'keyName': license_key['keyName'],
                'keyType': license_key['keyType'],
                'expiresAt': license_key['expiresAt'],
                'maxUsers': license_key['maxUsers'],
                'currentUsers': len(updated_sessions)
            }
        })
    except Exception as e:
        print(f"Connect API error: {e}")
        create_api_log('/api/connect', 'POST', False, f'error: {str(e)}',
                     request.remote_addr, request.headers.get('User-Agent', ''))
        return jsonify({'status': False, 'reason': f'Internal server error: {str(e)}'}), 500

# Register both /connect and /api/connect endpoints
@app.route('/connect', methods=['POST'])
def connect():
    return connect_handler()

@app.route('/api/connect', methods=['POST'])
def api_connect():
    return connect_handler()

# Disconnect API for mod menu
def disconnect_handler():
    try:
        user_key = request.form.get('user_key')
        serial = request.form.get('serial')
        
        # Fallback to JSON if form data is empty
        if not user_key and request.json:
            user_key = request.json.get('user_key')
        if not serial and request.json:
            serial = request.json.get('serial')
        
        if not user_key or not serial:
            return jsonify({'status': False, 'reason': 'License key and hardware ID required'}), 400

        license_key = get_license_key_by_key_or_name(user_key)
        
        if license_key:
            # Remove the session
            remove_active_session(license_key['id'], serial)
            
            # Update current users count
            active_sessions = get_active_sessions_for_key(license_key['id'])
            keys = read_json_file(KEYS_FILE)
            key_index = next(i for i, k in enumerate(keys) if k['id'] == license_key['id'])
            keys[key_index]['currentUsers'] = len(active_sessions)
            keys[key_index]['updatedAt'] = datetime.now().isoformat()
            write_json_file(KEYS_FILE, keys)

            # Log the disconnection
            create_api_log('/api/disconnect', 'POST', True, 'success: disconnected',
                         request.remote_addr, request.headers.get('User-Agent', ''),
                         key_id=license_key['id'], user_id=license_key['userId'], hwid=serial)

        return jsonify({'status': True})
    except Exception as e:
        return jsonify({'status': False, 'reason': 'Internal server error'}), 500

@app.route('/disconnect', methods=['POST'])
def disconnect():
    return disconnect_handler()

@app.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    return disconnect_handler()

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

# Key validation API (for external applications)
@app.route('/api/validate/<key_value>', methods=['POST'])
def validate_key(key_value):
    try:
        data = request.json or {}
        hwid = data.get('hwid')
        
        keys = read_json_file(KEYS_FILE)
        key = next((k for k in keys if k['key'] == key_value), None)
        
        if not key:
            create_api_log(f'/api/validate/{key_value}', 'POST', False, 'Key not found',
                         request.remote_addr, request.headers.get('User-Agent', ''), hwid=hwid)
            return jsonify({'valid': False, 'message': 'Invalid key'}), 404
        
        if key['status'] != 'active':
            create_api_log(f'/api/validate/{key_value}', 'POST', False, 'Key inactive',
                         request.remote_addr, request.headers.get('User-Agent', ''), 
                         key_id=key['id'], hwid=hwid)
            return jsonify({'valid': False, 'message': 'Key is not active'}), 403
        
        # Check expiration
        if key['expiresAt']:
            try:
                expiry_date = datetime.fromisoformat(key['expiresAt'].replace('Z', ''))
                if expiry_date < datetime.now():
                    create_api_log(f'/api/validate/{key_value}', 'POST', False, 'Key expired',
                                 request.remote_addr, request.headers.get('User-Agent', ''),
                                 key_id=key['id'], hwid=hwid)
                    return jsonify({'valid': False, 'message': 'Key has expired'}), 403
            except:
                pass
        
        # Check HWID limits if provided
        if hwid and key['maxUsers'] > 0:
            if hwid not in key['hwids']:
                if len(key['hwids']) >= key['maxUsers']:
                    create_api_log(f'/api/validate/{key_value}', 'POST', False, 'Max users exceeded',
                                 request.remote_addr, request.headers.get('User-Agent', ''),
                                 key_id=key['id'], hwid=hwid)
                    return jsonify({'valid': False, 'message': 'Maximum users exceeded'}), 403
                
                # Add new HWID
                keys = read_json_file(KEYS_FILE)
                key_index = next(i for i, k in enumerate(keys) if k['id'] == key['id'])
                keys[key_index]['hwids'].append(hwid)
                keys[key_index]['currentUsers'] = len(keys[key_index]['hwids'])
                keys[key_index]['lastUsed'] = datetime.now().isoformat()
                keys[key_index]['updatedAt'] = datetime.now().isoformat()
                write_json_file(KEYS_FILE, keys)
            else:
                # Update last used
                keys = read_json_file(KEYS_FILE)
                key_index = next(i for i, k in enumerate(keys) if k['id'] == key['id'])
                keys[key_index]['lastUsed'] = datetime.now().isoformat()
                keys[key_index]['updatedAt'] = datetime.now().isoformat()
                write_json_file(KEYS_FILE, keys)
        
        create_api_log(f'/api/validate/{key_value}', 'POST', True, 'Key valid',
                     request.remote_addr, request.headers.get('User-Agent', ''),
                     key_id=key['id'], user_id=key['userId'], hwid=hwid)
        
        return jsonify({
            'valid': True,
            'keyType': key['keyType'],
            'expiresAt': key['expiresAt'],
            'message': 'Key is valid'
        })
    
    except Exception as e:
        return jsonify({'valid': False, 'message': 'Validation failed'}), 500

# Frontend
@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KeyPanel - License Management System</title>
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
            background: white;
            padding: 3rem;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
            width: 90%;
        }
        
        .logo {
            font-size: 2.5rem;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 1rem;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 2rem;
            font-size: 1.1rem;
        }
        
        .auth-form {
            display: none;
        }
        
        .auth-form.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
            text-align: left;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
        }
        
        input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            width: 100%;
            padding: 0.75rem;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.3s;
            margin-bottom: 1rem;
        }
        
        .btn:hover {
            background: #5a6fd8;
        }
        
        .btn-secondary {
            background: transparent;
            color: #667eea;
            border: 2px solid #667eea;
        }
        
        .btn-secondary:hover {
            background: #667eea;
            color: white;
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
            <p>Don't have an account? <a href="#" class="toggle-link" onclick="showRegister()">Register here</a></p>
        </div>
        
        <!-- Register Form -->
        <div id="registerForm" class="auth-form">
            <h2 style="margin-bottom: 1.5rem;">Register</h2>
            <div id="registerError" class="error" style="display: none;"></div>
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="registerUsername" required>
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="registerEmail" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="registerPassword" required>
            </div>
            <button class="btn" onclick="register()">Register</button>
            <p>Already have an account? <a href="#" class="toggle-link" onclick="showLogin()">Login here</a></p>
        </div>
        
        <!-- Dashboard -->
        <div id="dashboard" class="dashboard">
            <div id="userInfo" class="user-info"></div>
            
            <div id="stats" class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" id="totalUsers">0</div>
                    <div class="stat-label">Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="activeKeys">0</div>
                    <div class="stat-label">Active Keys</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="apiRequests">0</div>
                    <div class="stat-label">API Requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="activeSessions">0</div>
                    <div class="stat-label">Sessions</div>
                </div>
            </div>
            
            <button class="btn" onclick="showCreateKey()">Create New Key</button>
            <button class="btn btn-secondary" onclick="testConnectAPI()">Test Connect API</button>
            <button class="btn btn-secondary" onclick="logout()">Logout</button>
            
            <div id="keys" class="keys-list"></div>
            <div id="apiTest" style="margin-top: 2rem; padding: 1rem; background: #f8f9fa; border-radius: 8px; display: none;">
                <h4>API Test Results</h4>
                <pre id="testResults" style="background: #e9ecef; padding: 1rem; border-radius: 4px; overflow-x: auto;"></pre>
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
    </div>

    <script>
        
        // Check if user is already logged in
        if (token) {
            checkAuth();
        }
        
        function showLogin() {
            hideAll();
            document.getElementById('loginForm').classList.add('active');
        }
        
        function showRegister() {
            hideAll();
            document.getElementById('registerForm').classList.add('active');
        }
        
        function showDashboard() {
            hideAll();
            document.getElementById('dashboard').classList.add('active');
            loadDashboard();
        }
        
        function showCreateKey() {
            hideAll();
            document.getElementById('createKeyForm').classList.add('active');
        }
        
        function hideAll() {
            document.getElementById('landing').style.display = 'none';
            document.getElementById('loginForm').classList.remove('active');
            document.getElementById('registerForm').classList.remove('active');
            document.getElementById('dashboard').classList.remove('active');
            document.getElementById('createKeyForm').classList.remove('active');
        }
        
        async function checkAuth() {
            try {
                const response = await fetch('/api/auth/me', {
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                
                if (response.ok) {
                    currentUser = await response.json();
                    showDashboard();
                } else {
                    localStorage.removeItem('token');
                    token = null;
                }
            } catch (error) {
                localStorage.removeItem('token');
                token = null;
            }
        }
        
        async function login() {
            var email = document.getElementById('loginEmail').value;
            var password = document.getElementById('loginPassword').value;
            
            try {
                var response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    token = data.token;
                    currentUser = data.user;
                    localStorage.setItem('token', token);
                    showDashboard();
                } else {
                    document.getElementById('loginError').textContent = data.message;
                    document.getElementById('loginError').style.display = 'block';
                }
            } catch (error) {
                document.getElementById('loginError').textContent = 'Login failed';
                document.getElementById('loginError').style.display = 'block';
            }
        }
        
        async function register() {
            const username = document.getElementById('registerUsername').value;
            const email = document.getElementById('registerEmail').value;
            const password = document.getElementById('registerPassword').value;
            
            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, email, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    token = data.token;
                    currentUser = data.user;
                    localStorage.setItem('token', token);
                    showDashboard();
                } else {
                    document.getElementById('registerError').textContent = data.message;
                    document.getElementById('registerError').style.display = 'block';
                }
            } catch (error) {
                document.getElementById('registerError').textContent = 'Registration failed';
                document.getElementById('registerError').style.display = 'block';
            }
        }
        
        async function loadDashboard() {
            // Load user info
            document.getElementById('userInfo').innerHTML = `
                <h3>Welcome, ${currentUser.username}!</h3>
                <p>Role: ${currentUser.role}</p>
                <p>Email: ${currentUser.email}</p>
            `;
            
            // Load stats
            try {
                const response = await fetch('/api/dashboard/stats', {
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                
                if (response.ok) {
                    const stats = await response.json();
                    document.getElementById('totalUsers').textContent = stats.totalUsers;
                    document.getElementById('activeKeys').textContent = stats.activeKeys;
                    document.getElementById('apiRequests').textContent = stats.apiRequests;
                    document.getElementById('activeSessions').textContent = stats.activeSessions;
                }
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
            
            // Load keys
            await loadKeys();
        }
        
        async function loadKeys() {
            try {
                const response = await fetch('/api/keys', {
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                
                if (response.ok) {
                    const keys = await response.json();
                    const keysContainer = document.getElementById('keys');
                    
                    if (keys.length === 0) {
                        keysContainer.innerHTML = '<p style="text-align: center; color: #666; margin-top: 2rem;">No license keys found.</p>';
                    } else {
                        keysContainer.innerHTML = '<h3>Your License Keys</h3>' + keys.map(function(key) {
                            var expiryInfo = key.expiresAt ? '<br><small>Expires: ' + new Date(key.expiresAt).toLocaleDateString() + '</small>' : '';
                            return '<div class="key-item">' +
                                '<strong>' + key.keyName + '</strong> (' + key.keyType + ')' +
                                '<div class="key-value">' + key.key + '</div>' +
                                '<small>Status: ' + key.status + ' | Users: ' + key.currentUsers + '/' + key.maxUsers + '</small>' +
                                expiryInfo +
                                '</div>';
                        }).join('');
                    }
                }
            } catch (error) {
                console.error('Failed to load keys:', error);
            }
        }
        
        async function createKey() {
            const keyName = document.getElementById('keyName').value;
            const keyType = document.getElementById('keyType').value;
            const maxUsers = parseInt(document.getElementById('maxUsers').value);
            
            try {
                const response = await fetch('/api/keys', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify({ keyName, keyType, maxUsers })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Clear form
                    document.getElementById('keyName').value = '';
                    document.getElementById('maxUsers').value = '1';
                    showDashboard();
                } else {
                    document.getElementById('createKeyError').textContent = data.message;
                    document.getElementById('createKeyError').style.display = 'block';
                }
            } catch (error) {
                document.getElementById('createKeyError').textContent = 'Key creation failed';
                document.getElementById('createKeyError').style.display = 'block';
            }
        }
        
        async function testConnectAPI() {
            const keys = await (await fetch('/api/keys', {
                headers: { 'Authorization': 'Bearer ' + token }
            })).json();
            
            if (keys.length === 0) {
                alert('Önce bir lisans anahtarı oluşturun');
                return;
            }
            
            const testKey = keys[0];
            const testHwid = 'TEST-HWID-' + Math.random().toString(36).substr(2, 9);
            
            let results = '';
            
            try {
                // Test connect API with keyName (as PUBG mod menu does)
                results += '=== Connect API Test ===\n';
                results += 'PUBG Mod Menu Usage:\n';
                results += 'Key Name: ' + testKey.keyName + ' (this is what mod menu sends as user_key)\n';
                results += 'Key Value: ' + testKey.key + ' (this is the actual license key)\n';
                results += 'Test HWID: ' + testHwid + '\n\n';
                
                const connectResponse = await fetch('/connect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'game=PUBG&user_key=' + testKey.keyName + '&serial=' + testHwid
                });
                
                const connectData = await connectResponse.json();
                results += 'Connect Response:\n' + JSON.stringify(connectData, null, 2) + '\n\n';
                
                if (connectData.status) {
                    // Test validate API
                    results += '=== Validate API Test ===\n';
                    const validateResponse = await fetch('/api/validate/' + testKey.key, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ hwid: testHwid })
                    });
                    
                    const validateData = await validateResponse.json();
                    results += 'Validate Response:\n' + JSON.stringify(validateData, null, 2) + '\n\n';
                    
                    // Test disconnect API
                    results += '=== Disconnect API Test ===\n';
                    const disconnectResponse = await fetch('/disconnect', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: 'user_key=' + testKey.keyName + '&serial=' + testHwid
                    });
                    
                    const disconnectData = await disconnectResponse.json();
                    results += 'Disconnect Response:\n' + JSON.stringify(disconnectData, null, 2) + '\n\n';
                }
                
                // Test status API
                results += '=== Status API Test ===\n';
                const statusResponse = await fetch('/api/status');
                const statusData = await statusResponse.json();
                results += 'Status Response:\n' + JSON.stringify(statusData, null, 2);
                
            } catch (error) {
                results += 'Error: ' + error.message;
            }
            
            document.getElementById('testResults').textContent = results;
            document.getElementById('apiTest').style.display = 'block';
        }
        
        function logout() {
            localStorage.removeItem('token');
            token = null;
            currentUser = null;
            hideAll();
            document.getElementById('landing').style.display = 'block';
        }
    </script>
    <script src="/static/script.js"></script>
</body>
</html>
    ''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)