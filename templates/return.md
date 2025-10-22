Here's how to add user-specific data endpoints with live updates:

## 1. Updated Quart App with User-Specific Endpoints:

```python
from quart import Quart, jsonify, request
import aiosqlite
import json
from datetime import datetime
import asyncio

app = Quart(__name__)

# Database connection helper
async def get_db():
    return await aiosqlite.connect('your_database.db')

# Generic function to fetch data by user ID
async def fetch_user_data(table_name, user_id, limit=1000):
    async with await get_db() as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            f"SELECT * FROM {table_name} WHERE user_id = ? ORDER BY id DESC LIMIT ?", 
            (user_id, limit)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

# Get specific user profile
async def fetch_user_by_id(user_id):
    async with await get_db() as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

# User profile endpoint
@app.route('/api/user/<int:user_id>')
async def get_user_profile(user_id):
    try:
        user = await fetch_user_by_id(user_id)
        if user:
            return jsonify({
                'success': True,
                'data': user
            })
        else:
            return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User sessions
@app.route('/api/user/<int:user_id>/sessions')
async def get_user_sessions(user_id):
    try:
        sessions = await fetch_user_data('sessions', user_id)
        return jsonify({
            'success': True,
            'data': sessions,
            'count': len(sessions)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User uploads
@app.route('/api/user/<int:user_id>/uploads')
async def get_user_uploads(user_id):
    try:
        uploads = await fetch_user_data('uploads', user_id)
        return jsonify({
            'success': True,
            'data': uploads,
            'count': len(uploads)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User jobs
@app.route('/api/user/<int:user_id>/jobs')
async def get_user_jobs(user_id):
    try:
        jobs = await fetch_user_data('jobs', user_id)
        return jsonify({
            'success': True,
            'data': jobs,
            'count': len(jobs)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User detections
@app.route('/api/user/<int:user_id>/detections')
async def get_user_detections(user_id):
    try:
        detections = await fetch_user_data('detections', user_id)
        return jsonify({
            'success': True,
            'data': detections,
            'count': len(detections)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User logs
@app.route('/api/user/<int:user_id>/logs')
async def get_user_logs(user_id):
    try:
        logs = await fetch_user_data('logs', user_id)
        return jsonify({
            'success': True,
            'data': logs,
            'count': len(logs)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User activity
@app.route('/api/user/<int:user_id>/activity')
async def get_user_activity(user_id):
    try:
        activity = await fetch_user_data('user_activity', user_id)
        return jsonify({
            'success': True,
            'data': activity,
            'count': len(activity)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Get all user data in one endpoint
@app.route('/api/user/<int:user_id>/all')
async def get_all_user_data(user_id):
    try:
        user = await fetch_user_by_id(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Fetch all user data concurrently
        sessions, uploads, jobs, detections, logs, activity = await asyncio.gather(
            fetch_user_data('sessions', user_id),
            fetch_user_data('uploads', user_id),
            fetch_user_data('jobs', user_id),
            fetch_user_data('detections', user_id),
            fetch_user_data('logs', user_id),
            fetch_user_data('user_activity', user_id)
        )
        
        return jsonify({
            'success': True,
            'data': {
                'profile': user,
                'sessions': sessions,
                'uploads': uploads,
                'jobs': jobs,
                'detections': detections,
                'logs': logs,
                'activity': activity
            },
            'summary': {
                'sessions_count': len(sessions),
                'uploads_count': len(uploads),
                'jobs_count': len(jobs),
                'detections_count': len(detections),
                'logs_count': len(logs),
                'activity_count': len(activity)
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Get recent user activity (for live updates)
@app.route('/api/user/<int:user_id>/recent')
async def get_recent_user_activity(user_id):
    try:
        async with await get_db() as conn:
            conn.row_factory = aiosqlite.Row
            
            # Get recent activity (last 10 items)
            cursor = await conn.execute("""
                SELECT * FROM user_activity 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT 10
            """, (user_id,))
            recent_activity = [dict(row) for row in await cursor.fetchall()]
            
            # Get latest job status
            cursor = await conn.execute("""
                SELECT id, status, task_name, started_at, completed_at 
                FROM jobs 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT 5
            """, (user_id,))
            recent_jobs = [dict(row) for row in await cursor.fetchall()]
            
            # Get user current credits
            cursor = await conn.execute("SELECT credits FROM users WHERE id = ?", (user_id,))
            user_credits = (await cursor.fetchone())[0]
            
            return jsonify({
                'success': True,
                'data': {
                    'recent_activity': recent_activity,
                    'recent_jobs': recent_jobs,
                    'current_credits': user_credits,
                    'timestamp': datetime.now().isoformat()
                }
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Search users by username or email
@app.route('/api/users/search')
async def search_users():
    try:
        query = request.args.get('q', '')
        if not query:
            return jsonify({'success': False, 'error': 'Query parameter required'}), 400
        
        async with await get_db() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT id, username, email, role, credits, created_at 
                FROM users 
                WHERE username LIKE ? OR email LIKE ?
                LIMIT 20
            """, (f'%{query}%', f'%{query}%'))
            
            users = [dict(row) for row in await cursor.fetchall()]
            return jsonify({
                'success': True,
                'data': users,
                'count': len(users)
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Get all users (for admin)
@app.route('/api/users/list')
async def get_all_users():
    try:
        async with await get_db() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT id, username, email, role, credits, is_active, 
                       email_verified, wallet_verified, created_at, last_login
                FROM users 
                ORDER BY created_at DESC
            """)
            
            users = [dict(row) for row in await cursor.fetchall()]
            return jsonify({
                'success': True,
                'data': users,
                'count': len(users)
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
```

## 2. HTML with Live User Data Dashboard:

**user_dashboard.html**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Data Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .dashboard-card { margin-bottom: 20px; }
        .live-badge { animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .stat-card { text-align: center; padding: 15px; }
        .stat-number { font-size: 2rem; font-weight: bold; }
        .user-search { max-width: 400px; }
        .recent-activity { max-height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="container-fluid py-4">
        <h1 class="mb-4">User Data Dashboard <span class="live-badge badge bg-success">LIVE</span></h1>
        
        <!-- User Search -->
        <div class="card dashboard-card">
            <div class="card-header">
                <h5 class="mb-0">Find User</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <div class="input-group">
                            <input type="text" class="form-control" id="userSearch" placeholder="Search by username or email...">
                            <button class="btn btn-primary" onclick="searchUsers()">Search</button>
                        </div>
                        <div id="searchResults" class="mt-2"></div>
                    </div>
                    <div class="col-md-6">
                        <div class="input-group">
                            <input type="number" class="form-control" id="userIdInput" placeholder="Or enter User ID directly">
                            <button class="btn btn-success" onclick="loadUserData()">Load User Data</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Current User Info -->
        <div id="currentUser" class="card dashboard-card" style="display: none;">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">User Profile: <span id="userName"></span></h5>
                <div>
                    <span class="badge bg-info" id="userCredits"></span>
                    <button class="btn btn-sm btn-outline-primary ms-2" onclick="startLiveUpdates()">Start Live Updates</button>
                    <button class="btn btn-sm btn-outline-secondary ms-1" onclick="stopLiveUpdates()">Stop</button>
                </div>
            </div>
            <div class="card-body">
                <div id="userProfile"></div>
            </div>
        </div>

        <!-- Live Stats -->
        <div id="liveStats" class="row" style="display: none;">
            <div class="col-md-3">
                <div class="card stat-card bg-primary text-white">
                    <div class="card-body">
                        <div class="stat-number" id="creditsCount">0</div>
                        <div>Credits</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card bg-success text-white">
                    <div class="card-body">
                        <div class="stat-number" id="jobsCount">0</div>
                        <div>Recent Jobs</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card bg-warning text-dark">
                    <div class="card-body">
                        <div class="stat-number" id="activityCount">0</div>
                        <div>Recent Activity</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card bg-info text-white">
                    <div class="card-body">
                        <div class="stat-number" id="lastUpdate">-</div>
                        <div>Last Update</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- User Data Tabs -->
        <div id="userDataTabs" style="display: none;">
            <ul class="nav nav-tabs" id="userTabs">
                <li class="nav-item">
                    <button class="nav-link active" onclick="showUserTab('profile')">Profile</button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" onclick="showUserTab('jobs')">Jobs</button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" onclick="showUserTab('uploads')">Uploads</button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" onclick="showUserTab('activity')">Activity</button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" onclick="showUserTab('all')">All Data</button>
                </li>
            </ul>

            <div class="tab-content mt-3">
                <div class="tab-pane fade show active" id="tabContent">
                    <!-- Content will be loaded here -->
                </div>
            </div>
        </div>
    </div>

    <script>
        const API_BASE = '/api';
        let currentUserId = null;
        let liveUpdateInterval = null;

        // Search users
        async function searchUsers() {
            const query = document.getElementById('userSearch').value.trim();
            if (!query) return;

            try {
                const response = await fetch(`${API_BASE}/users/search?q=${encodeURIComponent(query)}`);
                const result = await response.json();
                
                const resultsDiv = document.getElementById('searchResults');
                if (result.success && result.data.length > 0) {
                    resultsDiv.innerHTML = result.data.map(user => `
                        <div class="card mb-2">
                            <div class="card-body py-2">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <strong>${user.username}</strong> (${user.email})
                                        <br><small class="text-muted">ID: ${user.id} | Role: ${user.role} | Credits: ${user.credits}</small>
                                    </div>
                                    <button class="btn btn-sm btn-primary" onclick="selectUser(${user.id}, '${user.username}')">Select</button>
                                </div>
                            </div>
                        </div>
                    `).join('');
                } else {
                    resultsDiv.innerHTML = '<div class="alert alert-warning">No users found</div>';
                }
            } catch (error) {
                document.getElementById('searchResults').innerHTML = 
                    `<div class="alert alert-danger">Error: ${error.message}</div>`;
            }
        }

        // Select user from search results
        function selectUser(userId, username) {
            document.getElementById('userIdInput').value = userId;
            document.getElementById('userSearch').value = username;
            document.getElementById('searchResults').innerHTML = '';
            loadUserData();
        }

        // Load user data
        async function loadUserData() {
            const userId = document.getElementById('userIdInput').value;
            if (!userId) return;

            currentUserId = userId;
            
            try {
                // Load user profile
                const response = await fetch(`${API_BASE}/user/${userId}`);
                const result = await response.json();
                
                if (result.success) {
                    displayUserProfile(result.data);
                    showUserTab('profile');
                    startLiveUpdates();
                } else {
                    alert('User not found: ' + result.error);
                }
            } catch (error) {
                alert('Error loading user: ' + error.message);
            }
        }

        // Display user profile
        function displayUserProfile(user) {
            document.getElementById('currentUser').style.display = 'block';
            document.getElementById('userDataTabs').style.display = 'block';
            document.getElementById('liveStats').style.display = 'flex';
            
            document.getElementById('userName').textContent = user.username;
            document.getElementById('userCredits').textContent = `${user.credits} credits`;
            
            document.getElementById('userProfile').innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <table class="table table-sm">
                            <tr><th>ID:</th><td>${user.id}</td></tr>
                            <tr><th>Email:</th><td>${user.email}</td></tr>
                            <tr><th>Role:</th><td>${user.role}</td></tr>
                            <tr><th>Status:</th><td>${user.is_active ? 'Active' : 'Inactive'}</td></tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <table class="table table-sm">
                            <tr><th>Credits:</th><td>${user.credits}</td></tr>
                            <tr><th>Email Verified:</th><td>${user.email_verified ? 'Yes' : 'No'}</td></tr>
                            <tr><th>Wallet Verified:</th><td>${user.wallet_verified ? 'Yes' : 'No'}</td></tr>
                            <tr><th>Created:</th><td>${new Date(user.created_at).toLocaleString()}</td></tr>
                        </table>
                    </div>
                </div>
            `;
        }

        // Show user tab content
        async function showUserTab(tabName) {
            if (!currentUserId) return;

            const tabContent = document.getElementById('tabContent');
            tabContent.innerHTML = '<div class="text-center py-4"><div class="spinner-border"></div><p>Loading...</p></div>';

            try {
                let endpoint = '';
                switch(tabName) {
                    case 'profile':
                        endpoint = `${API_BASE}/user/${currentUserId}`;
                        break;
                    case 'jobs':
                        endpoint = `${API_BASE}/user/${currentUserId}/jobs`;
                        break;
                    case 'uploads':
                        endpoint = `${API_BASE}/user/${currentUserId}/uploads`;
                        break;
                    case 'activity':
                        endpoint = `${API_BASE}/user/${currentUserId}/activity`;
                        break;
                    case 'all':
                        endpoint = `${API_BASE}/user/${currentUserId}/all`;
                        break;
                }

                const response = await fetch(endpoint);
                const result = await response.json();
                
                if (result.success) {
                    displayTabContent(tabName, result.data, result.summary);
                } else {
                    tabContent.innerHTML = `<div class="alert alert-danger">Error: ${result.error}</div>`;
                }
            } catch (error) {
                tabContent.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
            }
        }

        // Display tab content
        function displayTabContent(tabName, data, summary = null) {
            const tabContent = document.getElementById('tabContent');
            
            switch(tabName) {
                case 'profile':
                    // Already displayed in profile section
                    tabContent.innerHTML = '<div class="alert alert-info">Profile information displayed above</div>';
                    break;
                    
                case 'jobs':
                    tabContent.innerHTML = createTableView(data, 'Jobs');
                    break;
                    
                case 'uploads':
                    tabContent.innerHTML = createTableView(data, 'Uploads');
                    break;
                    
                case 'activity':
                    tabContent.innerHTML = createTableView(data, 'Activity');
                    break;
                    
                case 'all':
                    tabContent.innerHTML = `
                        <div class="row">
                            <div class="col-md-6">
                                <h5>Summary</h5>
                                <ul class="list-group">
                                    <li class="list-group-item">Sessions: ${summary.sessions_count}</li>
                                    <li class="list-group-item">Uploads: ${summary.uploads_count}</li>
                                    <li class="list-group-item">Jobs: ${summary.jobs_count}</li>
                                    <li class="list-group-item">Detections: ${summary.detections_count}</li>
                                    <li class="list-group-item">Logs: ${summary.logs_count}</li>
                                    <li class="list-group-item">Activity: ${summary.activity_count}</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <h5>Raw Data</h5>
                                <pre class="bg-light p-3"><code>${JSON.stringify(data, null, 2)}</code></pre>
                            </div>
                        </div>
                    `;
                    break;
            }
        }

        // Create table view
        function createTableView(data, title) {
            if (!data || data.length === 0) {
                return `<div class="alert alert-warning">No ${title.toLowerCase()} found</div>`;
            }

            const headers = Object.keys(data[0]);
            const headerRow = headers.map(header => 
                `<th>${header.replace(/_/g, ' ').toUpperCase()}</th>`
            ).join('');

            const rows = data.map(row => {
                const cells = headers.map(header => {
                    let value = row[header];
                    if (value === null || value === undefined) value = 'NULL';
                    if (typeof value === 'boolean') value = value ? '✓' : '✗';
                    if (typeof value === 'string' && value.length > 50) value = value.substring(0, 50) + '...';
                    return `<td>${value}</td>`;
                }).join('');
                return `<tr>${cells}</tr>`;
            }).join('');

            return `
                <h5>${title} (${data.length} records)</h5>
                <div class="table-responsive">
                    <table class="table table-striped table-bordered">
                        <thead class="table-dark">
                            <tr>${headerRow}</tr>
                        </thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            `;
        }

        // Live updates
        async function updateLiveData() {
            if (!currentUserId) return;

            try {
                const response = await fetch(`${API_BASE}/user/${currentUserId}/recent`);
                const result = await response.json();
                
                if (result.success) {
                    const liveData = result.data;
                    
                    // Update stats
                    document.getElementById('creditsCount').textContent = liveData.current_credits;
                    document.getElementById('jobsCount').textContent = liveData.recent_jobs.length;
                    document.getElementById('activityCount').textContent = liveData.recent_activity.length;
                    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
                    
                    // Update user credits badge
                    document.getElementById('userCredits').textContent = `${liveData.current_credits} credits`;
                }
            } catch (error) {
                console.error('Live update error:', error);
            }
        }

        function startLiveUpdates() {
            if (liveUpdateInterval) clearInterval(liveUpdateInterval);
            updateLiveData(); // Immediate update
            liveUpdateInterval = setInterval(updateLiveData, 5000); // Update every 5 seconds
        }

        function stopLiveUpdates() {
            if (liveUpdateInterval) {
                clearInterval(liveUpdateInterval);
                liveUpdateInterval = null;
            }
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            // Add enter key support for search
            document.getElementById('userSearch').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') searchUsers();
            });
            
            document.getElementById('userIdInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') loadUserData();
            });
        });
    </script>
</body>
</html>
```

## New API Endpoints:

1. **`/api/user/<user_id>`** - User profile
2. **`/api/user/<user_id>/sessions`** - User sessions
3. **`/api/user/<user_id>/uploads`** - User uploads
4. **`/api/user/<user_id>/jobs`** - User jobs
5. **`/api/user/<user_id>/detections`** - User detections
6. **`/api/user/<user_id>/logs`** - User logs
7. **`/api/user/<user_id>/activity`** - User activity
8. **`/api/user/<user_id>/all`** - All user data
9. **`/api/user/<user_id>/recent`** - Recent activity (for live updates)
10. **`/api/users/search`** - Search users
11. **`/api/users/list`** - List all users

## Features:

- **User Search**: Find users by username or email
- **Live Updates**: Real-time credit balance and activity updates
- **Tabbed Interface**: Organized view of different data types
- **Statistics Dashboard**: Quick overview of user activity
- **Auto-refresh**: Configurable live data updates
- **Responsive Design**: Works on different screen sizes

The live updates will automatically refresh user credits, recent jobs, and activity every 5 seconds when enabled.