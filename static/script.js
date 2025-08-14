var currentUser = null;
var token = localStorage.getItem('token');

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

function showLogs() {
    hideAll();
    document.getElementById('logsView').classList.add('active');
    loadLogs();
}

function hideAll() {
    document.getElementById('landing').style.display = 'none';
    document.getElementById('loginForm').classList.remove('active');
    document.getElementById('registerForm').classList.remove('active');
    document.getElementById('dashboard').classList.remove('active');
    document.getElementById('createKeyForm').classList.remove('active');
    document.getElementById('logsView').classList.remove('active');
}

async function checkAuth() {
    try {
        var response = await fetch('/api/auth/me', {
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
            body: JSON.stringify({ email: email, password: password })
        });
        
        var data = await response.json();
        
        if (response.ok) {
            token = data.token;
            localStorage.setItem('token', token);
            currentUser = data.user;
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
    var email = document.getElementById('registerEmail').value;
    var password = document.getElementById('registerPassword').value;
    
    try {
        var response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email: email, password: password })
        });
        
        var data = await response.json();
        
        if (response.ok) {
            token = data.token;
            localStorage.setItem('token', token);
            currentUser = data.user;
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
    document.getElementById('userEmail').textContent = currentUser.email;
    
    // Stats HTML
    var statsHtml = '<div class="stats-grid">' +
        '<div class="stat-card"><div class="stat-number">0</div><div class="stat-label">Active Keys</div></div>' +
        '<div class="stat-card"><div class="stat-number">0</div><div class="stat-label">Total Sessions</div></div>' +
        '<div class="stat-card"><div class="stat-number">0</div><div class="stat-label">This Month</div></div>' +
        '</div>';
    
    // Load stats
    try {
        var response = await fetch('/api/dashboard/stats', {
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
        
        if (response.ok) {
            var stats = await response.json();
            statsHtml = '<div class="stats-grid">' +
                '<div class="stat-card"><div class="stat-number">' + stats.totalKeys + '</div><div class="stat-label">Active Keys</div></div>' +
                '<div class="stat-card"><div class="stat-number">' + stats.totalSessions + '</div><div class="stat-label">Total Sessions</div></div>' +
                '<div class="stat-card"><div class="stat-number">' + stats.thisMonth + '</div><div class="stat-label">This Month</div></div>' +
                '</div>';
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
    
    document.getElementById('dashboardStats').innerHTML = statsHtml;
    loadKeys();
}

async function loadKeys() {
    try {
        var response = await fetch('/api/keys', {
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
        
        if (response.ok) {
            var keys = await response.json();
            var keysContainer = document.getElementById('dashboardKeys');
            
            if (keys.length === 0) {
                keysContainer.innerHTML = '<p style="text-align: center; color: #666; margin-top: 2rem;">No license keys found.</p>';
            } else {
                keysContainer.innerHTML = '<h3>Your License Keys</h3>' + keys.map(function(key) {
                    var expiryInfo = key.expiresAt ? '<br><small>Expires: ' + new Date(key.expiresAt).toLocaleDateString() + '</small>' : '';
                    var statusBadge = key.status === 'active' ? 
                        '<span style="color: green;">●</span> Active' : 
                        '<span style="color: red;">●</span> Disabled';
                    var toggleText = key.status === 'active' ? 'Disable' : 'Enable';
                    
                    return '<div class="key-item">' +
                        '<div style="display: flex; justify-content: space-between; align-items: center;">' +
                            '<div>' +
                                '<strong>' + key.keyName + '</strong> (' + key.keyType + ')' +
                                '<div class="key-value">' + key.key + '</div>' +
                                '<small>Status: ' + statusBadge + ' | Users: ' + key.currentUsers + '/' + key.maxUsers + '</small>' +
                                expiryInfo +
                            '</div>' +
                            '<div style="display: flex; gap: 10px; flex-direction: column;">' +
                                '<button class="btn-small" onclick="toggleKeyStatus(\'' + key.id + '\')">' + toggleText + '</button>' +
                                '<button class="btn-small btn-danger" onclick="deleteKey(\'' + key.id + '\')">Delete</button>' +
                            '</div>' +
                        '</div>' +
                        '</div>';
                }).join('');
            }
        }
    } catch (error) {
        console.error('Failed to load keys:', error);
    }
}

async function createKey() {
    var keyName = document.getElementById('keyName').value;
    var keyType = document.getElementById('keyType').value;
    var maxUsers = parseInt(document.getElementById('maxUsers').value);
    
    try {
        var response = await fetch('/api/keys', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({ keyName: keyName, keyType: keyType, maxUsers: maxUsers })
        });
        
        var data = await response.json();
        
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
    var keys = await (await fetch('/api/keys', {
        headers: { 'Authorization': 'Bearer ' + token }
    })).json();
    
    if (keys.length === 0) {
        alert('Önce bir lisans anahtarı oluşturun');
        return;
    }
    
    var testKey = keys[0];
    var testHwid = 'TEST-HWID-' + Math.random().toString(36).substr(2, 9);
    
    var results = '';
    
    try {
        // Test connect API with keyName (as PUBG mod menu does)
        results += '=== Connect API Test ===\n';
        results += 'PUBG Mod Menu Usage:\n';
        results += 'Key Name: ' + testKey.keyName + ' (this is what mod menu sends as user_key)\n';
        results += 'Key Value: ' + testKey.key + ' (this is the actual license key)\n';
        results += 'Test HWID: ' + testHwid + '\n\n';
        
        var connectResponse = await fetch('/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'game=PUBG&user_key=' + testKey.keyName + '&serial=' + testHwid
        });
        
        var connectData = await connectResponse.json();
        results += 'Connect Response:\n' + JSON.stringify(connectData, null, 2) + '\n\n';
        
        if (connectData.status) {
            // Test validate API
            results += '=== Validate API Test ===\n';
            var validateResponse = await fetch('/api/validate/' + testKey.key, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hwid: testHwid })
            });
            
            var validateData = await validateResponse.json();
            results += 'Validate Response:\n' + JSON.stringify(validateData, null, 2) + '\n\n';
            
            // Test disconnect API
            results += '=== Disconnect API Test ===\n';
            var disconnectResponse = await fetch('/disconnect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'user_key=' + testKey.keyName + '&serial=' + testHwid
            });
            
            var disconnectData = await disconnectResponse.json();
            results += 'Disconnect Response:\n' + JSON.stringify(disconnectData, null, 2) + '\n\n';
        }
        
        // Test status API
        results += '=== Status API Test ===\n';
        var statusResponse = await fetch('/api/status');
        var statusData = await statusResponse.json();
        results += 'Status Response:\n' + JSON.stringify(statusData, null, 2);
        
    } catch (error) {
        results += 'Error: ' + error.message;
    }
    
    document.getElementById('testResults').textContent = results;
    document.getElementById('apiTest').style.display = 'block';
}

async function toggleKeyStatus(keyId) {
    if (!confirm('Are you sure you want to toggle this key status?')) {
        return;
    }
    
    try {
        var response = await fetch('/api/keys/' + keyId + '/toggle', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
        
        var data = await response.json();
        
        if (response.ok) {
            alert('Key status updated: ' + data.status);
            loadKeys(); // Refresh the keys list
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Failed to toggle key status');
    }
}

async function deleteKey(keyId) {
    if (!confirm('Are you sure you want to delete this key? This action cannot be undone.')) {
        return;
    }
    
    try {
        var response = await fetch('/api/keys/' + keyId, {
            method: 'DELETE',
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
        
        var data = await response.json();
        
        if (response.ok) {
            alert('Key deleted successfully');
            loadKeys(); // Refresh the keys list
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Failed to delete key');
    }
}

async function loadLogs() {
    try {
        var response = await fetch('/api/logs', {
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
        
        if (response.ok) {
            var logs = await response.json();
            var logsContainer = document.getElementById('logsContainer');
            
            if (logs.length === 0) {
                logsContainer.innerHTML = '<p>No logs found.</p>';
            } else {
                logsContainer.innerHTML = logs.reverse().map(function(log) {
                    var timestamp = new Date(log.timestamp).toLocaleString();
                    var details = JSON.stringify(log.details, null, 2);
                    return '<div style="background: #f8f9fa; margin-bottom: 1rem; padding: 1rem; border-radius: 8px;">' +
                        '<div style="font-weight: bold;">' + log.action + '</div>' +
                        '<div style="font-size: 0.9rem; color: #666;">' + timestamp + '</div>' +
                        '<pre style="background: #e9ecef; padding: 0.5rem; border-radius: 4px; margin-top: 0.5rem; font-size: 0.8rem;">' + details + '</pre>' +
                        '</div>';
                }).join('');
            }
        } else {
            document.getElementById('logsContainer').innerHTML = '<p style="color: red;">Failed to load logs.</p>';
        }
    } catch (error) {
        document.getElementById('logsContainer').innerHTML = '<p style="color: red;">Error loading logs.</p>';
    }
}

function logout() {
    localStorage.removeItem('token');
    token = null;
    currentUser = null;
    hideAll();
    document.getElementById('landing').style.display = 'block';
}