#!/usr/bin/env python3
"""
Forensic Video Analysis Platform with Enhanced Multi-Chain Web3 Authentication
Features:
- Multi-chain wallet support (Ethereum, Bitcoin, Solana, Polygon, Avalanche, Lisk, etc.)
- Enhanced user management with email verification links
- Multi-country support and Individual/Company account types
- Role-based access control with bonus credit system
- Secure video processing with user isolation
- JWT tokens for API authentication
- Rust-based wallet connector for cryptographic operations
- Email verification system with links (not codes)

Requirements:
pip install quart aiosqlite aiofiles pillow opencv-python psutil bcrypt pyjwt cryptography

Run:
  python app.py
"""

import os
import sys

# Monkey-patch Flask Config to always include PROVIDE_AUTOMATIC_OPTIONS
import flask.config

original_config_getitem = flask.config.Config.__getitem__

def patched_config_getitem(self, key):
    if key == "PROVIDE_AUTOMATIC_OPTIONS":
        return True
    return original_config_getitem(self, key)

flask.config.Config.__getitem__ = patched_config_getitem



import os
import io
import json
import zipfile
import cv2
import numpy as np
import json

import base64
import asyncio
import tempfile
import shutil
import subprocess
import time
import hashlib
import psutil
import bcrypt
import jwt
import random
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode
from collections import defaultdict, deque



import matplotlib.pyplot as plt
import matplotlib.patches as patches
import seaborn as sns
from matplotlib.backends.backend_agg import FigureCanvasAgg
from scipy.spatial.distance import euclidean
from scipy import ndimage
from sklearn.cluster import DBSCAN
from filterpy.kalman import KalmanFilter
from scipy.optimize import linear_sum_assignment



import aiosqlite
import aiofiles
import cv2
from PIL import Image
from quart import Quart, render_template_string, render_template, request, jsonify, session, websocket, send_file, g , redirect
from functools import wraps
import secrets


# Import Rust wallet connector
from rust_wallet import get_wallet_connector, close_wallet_connector
from utils import utility as utils 

# -------------------------
# Configuration
# -------------------------
BASE_DIR = Path(__file__).parent.resolve()
DB_PATH =  DB_PATH = os.environ.get('DATABASE_URL', 'forensics.db')
UPLOAD_DIR = str(BASE_DIR / "uploads")
UPLOAD_FOLDER = Path('uploads')
OUTPUT_DIR = str(BASE_DIR / "outputs")
SNAPSHOTS_FOLDER = Path('object_snapshots')
SNAPSHOTS_FOLDER.mkdir(exist_ok=True)
DETECTIONS_DIR = os.path.join(BASE_DIR , 'static' ,  "detections")
ALLOWED_EXTENSIONS = {"mp4", "avi", "mov", "mkv", "flv", "wmv"}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024 * 1024  # 2 GB

# Authentication settings
JWT_SECRET_KEY = os.environ.get('JWT_SECRET', 'your-super-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DELTA = timedelta(hours=24)
SESSION_TIMEOUT = timedelta(hours=8)

# Enhanced authentication settings
VERIFICATION_TOKEN_LENGTH = 32
VERIFICATION_TOKEN_EXPIRY_HOURS = 24

# Global job storage for progress tracking
active_jobs = {}

# Multi-chain configuration
SUPPORTED_CHAINS = {
    'ethereum': {
        'name': 'Ethereum',
        'chain_id': 1,
        'symbol': 'ETH',
        'address_prefix': '0x',
        'address_length': 42,
        'signing_methods': ['personal_sign', 'eth_signTypedData_v4'],
        'explorer': 'https://etherscan.io/address/'
    },
    'bitcoin': {
        'name': 'Bitcoin',
        'chain_id': 0,
        'symbol': 'BTC',
        'address_prefix': ['1', '3', 'bc1'],
        'address_length': [26, 35, 42],
        'signing_methods': ['bip322', 'message_sign'],
        'explorer': 'https://blockstream.info/address/'
    },
    'solana': {
        'name': 'Solana',
        'chain_id': 101,
        'symbol': 'SOL',
        'address_prefix': '',
        'address_length': 32,  # Base58 encoded, typically 44 chars
        'signing_methods': ['solana_signMessage'],
        'explorer': 'https://explorer.solana.com/address/'
    },
    'polygon': {
        'name': 'Polygon',
        'chain_id': 137,
        'symbol': 'MATIC',
        'address_prefix': '0x',
        'address_length': 42,
        'signing_methods': ['personal_sign', 'eth_signTypedData_v4'],
        'explorer': 'https://polygonscan.com/address/'
    },
    'avalanche': {
        'name': 'Avalanche',
        'chain_id': 43114,
        'symbol': 'AVAX',
        'address_prefix': '0x',
        'address_length': 42,
        'signing_methods': ['personal_sign', 'eth_signTypedData_v4'],
        'explorer': 'https://snowtrace.io/address/'
    },
    'lisk': {
        'name': 'Lisk',
        'chain_id': 1,
        'symbol': 'LSK',
        'address_prefix': '',  # Lisk uses base58 addresses
        'address_length': 41,  # Lisk addresses are typically 41 chars
        'signing_methods': ['ed25519_sign'],
        'explorer': 'https://liskscan.com/account/'
    }
}

# Countries list for dropdown
COUNTRIES = [
    "Afghanistan", "Albania", "Algeria", "Argentina", "Australia", "Austria", 
    "Bangladesh", "Belgium", "Brazil", "Canada", "China", "Denmark", "Egypt", 
    "France", "Germany", "Ghana", "India", "Indonesia", "Iran", "Iraq", "Italy", 
    "Japan", "Jordan", "Kenya", "Malaysia", "Mexico", "Netherlands", "Nigeria", 
    "Pakistan", "Philippines", "Poland", "Russia", "Saudi Arabia", "South Africa", 
    "Spain", "Sweden", "Switzerland", "Turkey", "Uganda", "Ukraine", 
    "United Kingdom", "United States", "Vietnam", "Zimbabwe"
]


ProductID = str("Knott-Forensics")
CompanyID = str("Sense-AI")

# URL processing settings
URL_JOB_EXPIRY_HOURS = 24
TEMP_DETECTION_CLEANUP_HOURS = 48

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(DETECTIONS_DIR, exist_ok=True)


# WITH THIS:
class PreConfiguredQuart(Quart):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set critical configuration BEFORE any internal setup
        self.config.update({
            "PROVIDE_AUTOMATIC_OPTIONS": True,
            "SECRET_KEY": os.environ.get('JWT_SECRET', JWT_SECRET_KEY),
            "MAX_CONTENT_LENGTH": MAX_CONTENT_LENGTH,
        })

# Use the pre-configured class
app = PreConfiguredQuart(__name__)

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = JWT_SECRET_KEY

# -------------------------
# Global runtime state
# -------------------------
job_tasks: Dict[int, asyncio.Task] = {}
job_ws_clients: Dict[int, List] = {}

# -------------------------
# Enhanced Database Schema with Multi-Chain Support
# -------------------------
CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,  -- NULL for Web3-only users
    role TEXT DEFAULT 'user',  -- user, premium, admin
    is_active BOOLEAN DEFAULT 1,
    email_verified BOOLEAN DEFAULT 0,
    credits INTEGER DEFAULT 10,  -- Processing credits
    country TEXT,
    account_type TEXT DEFAULT 'individual',  -- individual, company
    phone_number TEXT,
    company_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT,
    login_method TEXT DEFAULT 'web2'  -- web2, web3, both
);
"""

CREATE_WALLETS = """
CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    chain_type TEXT NOT NULL,
    wallet_address TEXT NOT NULL,
    public_key TEXT,
    is_verified BOOLEAN DEFAULT 0,
    is_primary BOOLEAN DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE(user_id, chain_type, wallet_address)
);
"""

CREATE_VERIFICATION_TOKENS = """
CREATE TABLE IF NOT EXISTS verification_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    type TEXT DEFAULT 'email_verification',  -- email_verification, password_reset
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    user_agent TEXT,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_UPLOADS = """
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    saved_path TEXT NOT NULL,
    size_bytes INTEGER,
    file_hash TEXT,
    upload_method TEXT DEFAULT 'web',  -- web, api
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_JOBS = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    upload_id INTEGER,
    source_url TEXT,
    source_type TEXT DEFAULT 'file',
    object_filter TEXT DEFAULT 'all',
    confidence REAL DEFAULT 0.5,
    frame_skip INTEGER DEFAULT 10,
    status TEXT DEFAULT 'pending',
    credits_cost INTEGER DEFAULT 1,
    started_at TEXT,
    completed_at TEXT,
    expires_at TEXT,
    process_pid INTEGER,
    task_name TEXT DEFAULT 'extraction',
    time_taken REAL,
    error_message TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (upload_id) REFERENCES uploads (id)
);
"""

CREATE_DETECTIONS = """
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    frame_number INTEGER,
    timestamp REAL,
    class_name TEXT,
    class_id INTEGER,
    confidence REAL,
    bbox TEXT,
    image_base64 TEXT,
    image_path TEXT,
    detection_group TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (job_id) REFERENCES jobs (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_LOGS = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER,
    user_id INTEGER,
    level TEXT,
    message TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (job_id) REFERENCES jobs (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_USER_ACTIVITY = """
CREATE TABLE IF NOT EXISTS user_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,  -- login, logout, upload, job_start, etc.
    details TEXT,  -- JSON details
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_MOTION_TRAJECTORY_TABLE = """
    CREATE TABLE IF NOT EXISTS motion_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        total_objects INTEGER,
        analysis_data TEXT,
        heatmap_image TEXT,
        trajectory_heatmap TEXT,  
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (job_id) REFERENCES jobs (id)
    );
"""
    

CREATE_OBJECT_TRAJECTORY_TABLE = """
    CREATE TABLE IF NOT EXISTS object_trajectories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL,
        object_id INTEGER,
        object_class TEXT,
        trajectory_data TEXT,
        speed_data TEXT,
        direction_data TEXT,
        total_distance REAL,
        avg_speed REAL,
        max_speed REAL,
        duration REAL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (analysis_id) REFERENCES motion_analysis (id)
    );
"""


CREATE_TIMELINE_TABLE = """
CREATE TABLE IF NOT EXISTS timeline_videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                duration REAL,
                metadata TEXT,
                upload_time TEXT DEFAULT (datetime('now')),
                analysis_status TEXT DEFAULT 'pending',
                video_hash TEXT UNIQUE
            );
        """


CREATE_SEARCH_VIDEOS = """ 
CREATE TABLE IF NOT EXISTS search_videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                upload_time TEXT DEFAULT (datetime('now')),
                media_type TEXT
            );
"""

CREATE_SEARCH_IMAGES = """
  CREATE TABLE IF NOT EXISTS search_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                upload_time TEXT DEFAULT (datetime('now')),
                media_type TEXT DEFAULT 'target_image'
            );
"""


CREATE_SEARCH_RESULTS = """ 
 CREATE TABLE IF NOT EXISTS search_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                search_id TEXT NOT NULL,
                target_media_path TEXT NOT NULL,
                source_video_path TEXT NOT NULL,
                matches_data TEXT NOT NULL,
                total_matches INTEGER NOT NULL,
                search_timestamp TEXT DEFAULT (datetime('now'))
            );
"""
# Database initialization


async def init_enhanced_db():
    """Initialize enhanced database with all tables and migrations"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA foreign_keys=ON;")
        
        # Create all tables
        await db.execute(CREATE_USERS)
        await db.execute(CREATE_WALLETS)
        await db.execute(CREATE_VERIFICATION_TOKENS)
        await db.execute(CREATE_SESSIONS)
        await db.execute(CREATE_UPLOADS)
        await db.execute(CREATE_JOBS)
        await db.execute(CREATE_DETECTIONS)
        await db.execute(CREATE_LOGS)
        await db.execute(CREATE_USER_ACTIVITY)
        await db.execute(CREATE_MOTION_TRAJECTORY_TABLE)
        await db.execute(CREATE_OBJECT_TRAJECTORY_TABLE)
        await db.execute(CREATE_TIMELINE_TABLE)
        await db.execute(CREATE_SEARCH_VIDEOS)
        await db.execute(CREATE_SEARCH_IMAGES)
        await db.execute(CREATE_SEARCH_RESULTS)

    
        await db.commit()
        
        # Create admin user if doesn't exist
        admin_exists = await db.execute("SELECT id FROM users WHERE username='admin'")
        if not await admin_exists.fetchone():
            admin_hash = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
            await db.execute("""
                INSERT INTO users (username, email, password_hash, role, is_active, email_verified, credits, country, account_type)
                VALUES ('admin', 'admin@forensics.app', ?, 'admin', 1, 1, 1000, 'United States', 'individual')
            """, (admin_hash,))
            await db.commit()
            print("Created default admin user: admin/admin123")

# -------------------------
# Database Helpers
# -------------------------
async def db_insert(table: str, data: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cols = ", ".join(data.keys())
        placeholders = ", ".join("?" for _ in data)
        query = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"
        cur = await db.execute(query, tuple(data.values()))
        await db.commit()
        return cur.lastrowid

async def db_update(table: str, data: dict, where: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        set_clause = ", ".join([f"{k}=?" for k in data.keys()])
        where_clause = " AND ".join([f"{k}=?" for k in where.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        await db.execute(query, tuple(data.values()) + tuple(where.values()))
        await db.commit()

async def db_query(sql: str, params: tuple = ()):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(sql, params)
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

async def db_query_one(sql: str, params: tuple = ()):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(sql, params)
        row = await cur.fetchone()
        return dict(row) if row else None
    
    

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



# Get specific user profile
async def fetch_user_by_addr(addr):
    async with await get_db() as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute("SELECT * FROM users WHERE username = ?", (addr,))
        row = await cursor.fetchone()
        return dict(row) if row else None

# -------------------------
# Enhanced Verification System with Links (Not Codes)
# -------------------------
def generate_verification_token():
    """Generate a secure verification token"""
    import secrets
    return secrets.token_urlsafe(VERIFICATION_TOKEN_LENGTH)

async def send_verification_email(email: str, verification_url: str, name: str = "User"):
    """Send verification link via email (simulated for demo)"""
    print(f"[EMAIL] Sending verification link to {email}")
    print(f"[EMAIL] Verification URL: {verification_url}")
    print(f"[EMAIL] Dear {name}, please click the link above to verify your email address.")
    # In production, integrate with SendGrid, Mailgun, etc.
    return True

async def send_password_reset_email(email: str, reset_url: str, name: str = "User"):
    """Send password reset link via email"""
    print(f"[EMAIL] Sending password reset link to {email}")
    print(f"[EMAIL] Reset URL: {reset_url}")
    return True

async def create_verification_token(user_id: int, email: str, token_type: str = 'email_verification'):
    """Create and store verification token"""
    token = generate_verification_token()
    expires_at = (datetime.utcnow() + timedelta(hours=VERIFICATION_TOKEN_EXPIRY_HOURS)).isoformat()
    
    # Deactivate any existing tokens for this user/type
    await db_update("verification_tokens", 
                   {"used_at": datetime.utcnow().isoformat()}, 
                   {"user_id": user_id, "type": token_type, "used_at": None})
    
    # Create new token
    await db_insert("verification_tokens", {
        "user_id": user_id,
        "email": email,
        "token": token,
        "type": token_type,
        "expires_at": expires_at
    })
    
    return token

async def verify_token(token: str, token_type: str = 'email_verification'):
    """Verify a verification token"""
    # Get the token record
    token_record = await db_query_one("""
        SELECT * FROM verification_tokens 
        WHERE token = ? AND type = ? AND used_at IS NULL AND expires_at > datetime('now')
        LIMIT 1
    """, (token, token_type))
    
    if not token_record:
        return {"success": False, "error": "Invalid or expired verification link"}
    
    # Mark token as used
    await db_update("verification_tokens", {"used_at": datetime.utcnow().isoformat()}, {"id": token_record['id']})
    
    # Mark user as verified if this is email verification
    if token_type == 'email_verification' and token_record['user_id']:
        await db_update("users", {"email_verified": 1}, {"id": token_record['user_id']})
    
    return {"success": True, "user_id": token_record['user_id'], "email": token_record['email']}

# -------------------------
# Multi-Chain Wallet Validation with Rust Connector
# -------------------------
def validate_ethereum_address(address):
    """Validate Ethereum-style address (0x + 40 hex chars)"""
    if not address.startswith('0x'):
        return False
    if len(address) != 42:
        return False
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False

def validate_bitcoin_address(address):
    """Basic Bitcoin address validation"""
    # Check common Bitcoin address formats
    if address.startswith('1') and 26 <= len(address) <= 34:
        return True
    if address.startswith('3') and 26 <= len(address) <= 34:
        return True
    if address.startswith('bc1') and len(address) >= 14:
        return True
    return False

def validate_solana_address(address):
    """Validate Solana address (base58, 32-44 chars)"""
    try:
        # Solana addresses are base58 encoded 32-byte public keys
        import base58
        decoded = base58.b58decode(address)
        return len(decoded) == 32
    except:
        return False

def validate_lisk_address(address):
    """Validate Lisk address (base58, typically 41 chars)"""
    try:
        # Lisk addresses are base58 encoded
        import base58
        decoded = base58.b58decode(address)
        return len(address) == 41  # Standard Lisk address length
    except:
        return False

def validate_address(chain_type, address):
    """Universal address validator"""
    validators = {
        'ethereum': validate_ethereum_address,
        'polygon': validate_ethereum_address,  # Same format as Ethereum
        'avalanche': validate_ethereum_address,  # Same format as Ethereum
        'bitcoin': validate_bitcoin_address,
        'solana': validate_solana_address,
        'lisk': validate_lisk_address
    }
    
    if chain_type in validators:
        return validators[chain_type](address)
    return True  # Accept any address for unknown chains

def get_signing_message(chain_type, address, nonce):
    """Generate chain-appropriate signing message"""
    base_message = f"ForensicPlatform: Verify ownership of {address} on {chain_type} with nonce: {nonce}"
    
    # Chain-specific message formats
    message_formats = {
        'bitcoin': f"ForensicPlatform Bitcoin Verification\nAddress: {address}\nNonce: {nonce}",
        'solana': f"ForensicPlatform Solana Verification\nAddress: {address}\nNonce: {nonce}",
        'lisk': f"ForensicPlatform Lisk Verification\nAddress: {address}\nNonce: {nonce}",
        'ethereum': base_message,
        'polygon': base_message,
        'avalanche': base_message
    }
    
    return message_formats.get(chain_type, base_message)

async def verify_wallet_signature(chain_type: str, address: str, public_key: str, message: str, signature: str) -> bool:
    """Verify wallet signature using Rust connector"""
    try:
        wallet_connector = get_wallet_connector()
        
        if chain_type == 'lisk':
            # Use Rust connector for Lisk
            return wallet_connector.verify_signature(public_key, message, signature)
        else:
            # For other chains, use Python implementation
            # This is a simplified version - in production you'd use chain-specific libraries
            if chain_type in ['ethereum', 'polygon', 'avalanche']:
                # Use web3.py for EVM chains
                try:
                    from web3 import Web3
                    w3 = Web3()
                    recovered_address = w3.eth.account.recover_message(text=message, signature=signature)
                    return recovered_address.lower() == address.lower()
                except ImportError:
                    # Fallback to basic verification
                    return len(signature) > 0
            else:
                # For other chains, accept any non-empty signature (simplified)
                return len(signature) > 0
                
    except Exception as e:
        print(f"Error verifying signature for {chain_type}: {e}")
        return False

# -------------------------
# Authentication & Authorization
# -------------------------
def generate_jwt_token(user_data: dict) -> str:
    """Generate JWT token for user"""
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role'],
        'exp': datetime.utcnow() + JWT_EXPIRATION_DELTA,
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> dict:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def create_session(user_id: int, user_agent: str = None, ip_address: str = None) -> str:
    """Create new session for user"""
    session_id = hashlib.sha256(f"{user_id}{datetime.utcnow().isoformat()}".encode()).hexdigest()
    expires_at = (datetime.utcnow() + SESSION_TIMEOUT).isoformat()
    
    await db_insert("sessions", {
        "id": session_id,
        "user_id": user_id,
        "expires_at": expires_at,
        "user_agent": user_agent,
        "ip_address": ip_address
    })
    
    return session_id

async def verify_session(session_id: str) -> dict:
    """Verify session and return user data"""
    session_data = await db_query_one("""
        SELECT s.*, u.* FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.id = ? AND s.expires_at > datetime('now') AND u.is_active = 1
    """, (session_id,))
    
    return session_data

async def log_user_activity(user_id: int, action: str, details: dict = None, ip_address: str = None, user_agent: str = None):
    """Log user activity"""
    await db_insert("user_activity", {
        "user_id": user_id,
        "action": action,
        "details": json.dumps(details) if details else None,
        "ip_address": ip_address,
        "user_agent": user_agent
    })

def auth_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        # Check for JWT token in header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            token_data = verify_jwt_token(token)
            if token_data:
                user = await db_query_one("SELECT * FROM users WHERE id = ? AND is_active = 1", (token_data['user_id'],))
                if user:
                    g.current_user = user
                    return await f(*args, **kwargs)
        
        # Check for session ID in cookie
        session_id = session.get('session_id')
        if session_id:
            session_data = await verify_session(session_id)
            if session_data:
                g.current_user = session_data
                return await f(*args, **kwargs)
        
        return jsonify({"error": "Authentication required "}), 401
    
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user') or g.current_user['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return await f(*args, **kwargs)
    
    return decorated_function

# -------------------------
# Utility Functions
# -------------------------
async def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of uploaded file asynchronously"""
    hash_sha256 = hashlib.sha256()
    async with aiofiles.open(file_path, 'rb') as f:
        while chunk := await f.read(8192):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def generate_detection_group(class_name: str, bbox: list) -> str:
    """Generate detection group identifier"""
    x1, y1, x2, y2 = bbox
    grid_x = int((x1 + x2) / 2 / 200)
    grid_y = int((y1 + y2) / 2 / 150)
    return f"{class_name}_grid_{grid_x}_{grid_y}"

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

async def log(job_id: Optional[int], level: str, message: str, user_id: int = None):
    """Enhanced logging with user context"""
    rec = {
        "job_id": job_id,
        "user_id": user_id or (g.current_user['id'] if hasattr(g, 'current_user') else None),
        "level": level,
        "message": message,
    }
    row_id = await db_insert("logs", rec)
    
    # WebSocket notifications
    if job_id in job_ws_clients:
        payload = json.dumps({
            "type": "log", 
            "job_id": job_id, 
            "level": level, 
            "message": message, 
            "created_at": datetime.utcnow().isoformat()
        })
        for ws in list(job_ws_clients.get(job_id, [])):
            try:
                asyncio.create_task(ws.send(payload))
            except Exception:
                pass
    
    return row_id


    # Notify connected websockets for this job
    if job_id in job_ws_clients:
        payload = json.dumps({"type": "log", "job_id": job_id, "level": level, "message": message, "created_at": datetime.utcnow().isoformat()})
        # send in background to avoid blocking DB writes
        for ws in list(job_ws_clients.get(job_id, [])):
            try:
                asyncio.create_task(ws.send(payload))
            except Exception:
                # ignore; connection cleanup happens elsewhere
                pass
    return row_id
# -------------------------


# -------------------------
# Enhanced Authentication Routes with Multi-Chain Support
# -------------------------
@app.route('/auth/register', methods=['POST'])
async def register():
    data = await request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    country = data.get('country')
    account_type = data.get('account_type', 'individual')
    company_name = data.get('company_name')
    phone_number = data.get('phone_number')
    
    if not username or not email or not country:
        return jsonify({"error": "Username, email, and country are required"}), 400
    
    if account_type == 'company' and not company_name:
        return jsonify({"error": "Company name is required for company accounts"}), 400
    
    # Check if user exists
    existing = await db_query_one("SELECT id FROM users WHERE username=? OR email=?", (username, email))
    if existing:
        return jsonify({"error": "User already exists"}), 400
    
    # Create user
    user_data = {
        "username": username,
        "email": email,
        "country": country,
        "account_type": account_type,
        "phone_number": phone_number,
        "company_name": company_name,
        "login_method": "web2",
        "email_verified": 0
    }
    
    if password:
        user_data["password_hash"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    user_id = await db_insert("users", user_data)
    
    # Generate and send verification link (not code)
    verification_token = await create_verification_token(user_id, email)
    verification_url = f"{request.host_url}auth/verify-email?token={verification_token}"
    
    name = company_name if account_type == 'company' else username
    email_sent = await send_verification_email(email, verification_url, name)
    
    if not email_sent:
        return jsonify({"error": "Failed to send verification email"}), 500
    
    await log_user_activity(user_id, "register", {
        "method": "web2",
        "country": country,
        "account_type": account_type
    }, request.remote_addr, request.headers.get('User-Agent'))
    
    return jsonify({
        "success": True,
        "message": "Registration successful. Please check your email for verification link.",
        "user_id": user_id,
        "email": email,
        "requires_verification": True
    })

@app.route('/auth/verify-email')
async def verify_email_page():
    """Email verification page that handles the verification token"""
    token = request.args.get('token')
    
    if not token:
        return await render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verification - Forensic Analysis</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex items-center justify-center">
            <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
                <h1 class="text-2xl font-bold text-red-600 mb-4">Invalid Verification Link</h1>
                <p class="text-gray-600">The verification link is invalid or has expired.</p>
                <a href="/" class="mt-4 inline-block bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
                    Return to Login
                </a>
            </div>
        </body>
        </html>
        ''')
    
    # Verify the token
    result = await verify_token(token, 'email_verification')
    
    if not result['success']:
        return await render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verification - Forensic Analysis</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex items-center justify-center">
            <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
                <h1 class="text-2xl font-bold text-red-600 mb-4">Verification Failed</h1>
                <p class="text-gray-600">{{ error }}</p>
                <a href="/" class="mt-4 inline-block bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
                    Return to Login
                </a>
            </div>
        </body>
        </html>
        ''', error=result.get('error', 'Unknown error'))
    
    # Get user data
    user = await db_query_one("SELECT * FROM users WHERE id=?", (result['user_id'],))
    if not user:
        return await render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verification - Forensic Analysis</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex items-center justify-center">
            <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
                <h1 class="text-2xl font-bold text-red-600 mb-4">User Not Found</h1>
                <p class="text-gray-600">The user associated with this verification link was not found.</p>
                <a href="/" class="mt-4 inline-block bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
                    Return to Login
                </a>
            </div>
        </body>
        </html>
        ''')
    
    # Create session and token
    session_id = await create_session(user['id'], request.headers.get('User-Agent'), request.remote_addr)
    token = generate_jwt_token(user)
    
    session['session_id'] = session_id
    
    await log_user_activity(user['id'], "email_verified", {}, 
                           request.remote_addr, request.headers.get('User-Agent'))
    
    return await render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Verified - Forensic Analysis</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            // Store the JWT token for API calls
            localStorage.setItem('jwt_token', '{{ token }}');
            
            function connectWallet() {
                window.location.href = '/auth/connect-wallet';
            }
            
            function goToDashboard() {
                window.location.href = '/dashboard';
            }
        </script>
    </head>
    <body class="bg-gray-100 min-h-screen flex items-center justify-center">
        <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
            <div class="text-center mb-6">
                <div class="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <svg class="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                </div>
                <h1 class="text-2xl font-bold text-green-600 mb-2">Email Verified!</h1>
                <p class="text-gray-600">Your email has been successfully verified.</p>
            </div>
            
            <div class="space-y-4">
                <button onclick="connectWallet()" class="w-full bg-purple-600 hover:bg-purple-700 text-white py-3 px-4 rounded-lg font-semibold transition duration-200 flex items-center justify-center">
                    <span class="mr-2">🔗</span>
                    Connect Wallet & Get Bonus Credits
                </button>
                
                <button onclick="goToDashboard()" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 px-4 rounded-lg font-semibold transition duration-200">
                    Skip to Dashboard
                </button>
            </div>
            
            <p class="text-xs text-gray-500 text-center mt-4">
                You can connect your wallet later from your profile settings
            </p>
        </div>
    </body>
    </html>
    ''', token=token, user=user)







@app.route('/auth/connect-wallet')
@auth_required
async def connect_wallet_page():
    """Wallet connection page with multi-chain support"""
    wallets = await db_query("""
    SELECT chain_type, wallet_address, is_verified, is_primary, created_at 
    FROM wallets WHERE user_id = ? ORDER BY is_primary DESC, created_at DESC
""", (g.current_user['id'],))
    return await render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Connect Wallet - Forensic Analysis</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.ethers.io/lib/ethers-5.7.2.umd.min.js"></script>
    </head>
    <body class="bg-gray-100 min-h-screen">
        <nav class="bg-white shadow-lg">
            <div class="max-w-7xl mx-auto px-4">
                <div class="flex justify-between h-16">
                    <div class="flex items-center">
                        <h1 class="text-xl font-bold text-gray-800">Forensic Analysis</h1>
                    </div>
                    <div class="flex items-center space-x-4">
                        <span class="text-gray-600">Welcome, {{ user.username }}</span>
                        <a href="/dashboard" class="text-blue-600 hover:text-blue-800">Dashboard</a>
                    </div>
                </div>
            </div>
        </nav>

        <div class="max-w-4xl mx-auto py-8 px-4">
            <div class="bg-white rounded-lg shadow-lg p-8">
                <h1 class="text-3xl font-bold text-gray-800 mb-2">Connect Your Wallet</h1>
                <p class="text-gray-600 mb-8">Connect your wallet to get bonus credits and enable Web3 features</p>
                
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
                    <!-- Ethereum/MetaMask -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-blue-500 transition duration-200 cursor-pointer" onclick="connectEthereum()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-orange-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-orange-600 font-bold">🦊</span>
                            </div>
                            <h3 class="text-lg font-semibold">Ethereum</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Connect with MetaMask or any Ethereum wallet</p>
                        <div class="text-xs text-gray-500">Supports: ETH, MATIC, AVAX</div>
                    </div>
                    
                    <!-- Bitcoin -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-orange-500 transition duration-200 cursor-pointer" onclick="connectBitcoin()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-orange-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-orange-600 font-bold">₿</span>
                            </div>
                            <h3 class="text-lg font-semibold">Bitcoin</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Connect with Bitcoin wallet</p>
                        <div class="text-xs text-gray-500">Supports: BTC</div>
                    </div>
                    
                    <!-- Solana -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-purple-500 transition duration-200 cursor-pointer" onclick="connectSolana()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-purple-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-purple-600 font-bold">◎</span>
                            </div>
                            <h3 class="text-lg font-semibold">Solana</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Connect with Solana wallet</p>
                        <div class="text-xs text-gray-500">Supports: SOL</div>
                    </div>
                    
                    <!-- Lisk -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-blue-500 transition duration-200 cursor-pointer" onclick="connectLisk()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-blue-600 font-bold">⛓️</span>
                            </div>
                            <h3 class="text-lg font-semibold">Lisk</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Connect with Lisk wallet</p>
                        <div class="text-xs text-gray-500">Supports: LSK</div>
                    </div>
                    
                    <!-- Manual Entry -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-green-500 transition duration-200 cursor-pointer" onclick="showManualEntry()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-green-600 font-bold">📝</span>
                            </div>
                            <h3 class="text-lg font-semibold">Manual Entry</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Enter wallet details manually</p>
                        <div class="text-xs text-gray-500">All chains supported</div>
                    </div>
                </div>
                
                <!-- Manual Entry Form -->
                <div id="manualEntry" class="hidden bg-gray-50 p-6 rounded-lg mb-6">
                    <h3 class="text-xl font-semibold mb-4">Manual Wallet Entry</h3>
                    <form id="manualWalletForm" class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Blockchain</label>
                            <select id="chainType" class="w-full p-3 border border-gray-300 rounded-lg" required>
                                <option value="">Select Blockchain</option>
                                <option value="ethereum">Ethereum</option>
                                <option value="bitcoin">Bitcoin</option>
                                <option value="solana">Solana</option>
                                <option value="lisk">Lisk</option>
                                <option value="polygon">Polygon</option>
                                <option value="avalanche">Avalanche</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Wallet Address</label>
                            <input type="text" id="walletAddress" class="w-full p-3 border border-gray-300 rounded-lg" placeholder="Enter wallet address" required>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Public Key (Optional)</label>
                            <input type="text" id="publicKey" class="w-full p-3 border border-gray-300 rounded-lg" placeholder="Enter public key if available">
                        </div>
                        <button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white py-3 px-4 rounded-lg font-semibold">
                            Connect Wallet
                        </button>
                    </form>
                </div>
                
                <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <div class="flex items-start">
                        <div class="flex-shrink-0">
                            <span class="text-blue-600">💎</span>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-sm font-medium text-blue-800">Bonus Credits</h3>
                            <p class="text-sm text-blue-700 mt-1">
                                Connect your first wallet and receive <strong>5 bonus credits</strong> for video processing!
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
        async function connectEthereum() {
            if (typeof window.ethereum !== 'undefined') {
                try {
                    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
                    const address = accounts[0];
                    
                    // Get chain ID
                    const chainId = await window.ethereum.request({ method: 'eth_chainId' });
                    
                    // Sign message for verification
                    const message = `ForensicPlatform: Verify ownership of ${address} on Ethereum`;
                    const signature = await window.ethereum.request({
                        method: 'personal_sign',
                        params: [message, address]
                    });
                    
                    await registerWallet('ethereum', address, '', signature, message);
                    
                } catch (error) {
                    alert('Ethereum connection failed: ' + error.message);
                }
            } else {
                alert('MetaMask is not installed. Please install MetaMask or use manual entry.');
            }
        }
        
        function connectBitcoin() {
            alert('Bitcoin wallet connection would be implemented here. Use manual entry for now.');
            showManualEntry();
        }
        
        function connectSolana() {
            alert('Solana wallet connection would be implemented here. Use manual entry for now.');
            showManualEntry();
        }
        
        function connectLisk() {
            alert('Lisk wallet connection would be implemented here. Use manual entry for now.');
            showManualEntry();
        }
        
        function showManualEntry() {
            document.getElementById('manualEntry').classList.remove('hidden');
        }
        
        document.getElementById('manualWalletForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const chainType = document.getElementById('chainType').value;
            const address = document.getElementById('walletAddress').value;
            const publicKey = document.getElementById('publicKey').value;
            
            if (!chainType || !address) {
                alert('Please fill in all required fields');
                return;
            }
            
            await registerWallet(chainType, address, publicKey, '', '');
        });
        
        async function registerWallet(chainType, address, publicKey, signature, message) {
            try {
                const token = localStorage.getItem('jwt_token');
                const response = await fetch('/auth/connect-wallet', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        chain_type: chainType,
                        wallet_address: address,
                        public_key: publicKey,
                        signature: signature,
                        message: message
                    })
                });
                
                const result = await response.json();
                if (response.ok) {
                    alert('Wallet connected successfully! ' + result.message);
                    window.location.href = '/dashboard';
                } else {
                    alert('Failed to connect wallet: ' + result.error);
                }
            } catch (error) {
                alert('Error connecting wallet: ' + error.message);
            }
        }
        </script>
    </body>
    </html>
    ''', user=g.current_user)


@app.route('/auth/profile/json')
@auth_required
async def json_profile():
    """Get user profile with connected wallets"""
    wallets = await db_query("""
        SELECT chain_type, wallet_address, is_verified, is_primary, created_at 
        FROM wallets WHERE user_id = ? ORDER BY is_primary DESC, created_at DESC
    """, (g.current_user['id'],))
    
    pid = await db_query("""
        SELECT id
        FROM users WHERE email = ? 
    """, (g.current_user['username'],))
    
    
    
    return jsonify({
        "user": {
            "id": g.current_user["id"],
            "username": g.current_user["username"],
            "email": g.current_user["email"],
            "role": g.current_user["role"],
            "credits": g.current_user["credits"],
            "country": g.current_user.get("country"),
            "account_type": g.current_user.get("account_type"),
            "company_name": g.current_user.get("company_name"),
            "created_at": g.current_user["created_at"],
            "last_login": g.current_user["last_login"] ,
            "profileid" : pid 
        },
        "wallets": wallets
    })




@app.route('/auth/profile/<string:sect>/')
@auth_required
async def profile(sect):
    """Get user profile with connected wallets"""
    wallets = await db_query("""
        SELECT chain_type, wallet_address, is_verified, is_primary, created_at 
        FROM wallets WHERE user_id = ? ORDER BY is_primary DESC, created_at DESC
    """, (g.current_user['id'],))
    
    return await render_template("Account-Profile-Concept.html" , user = g.current_user  ,  sect = sect  , ProductID = ProductID , CompanyID = CompanyID )



@app.route('/auth/login', methods=['POST'])
async def login():
    """Login with email/password or wallet"""
    data = await request.get_json()
    username = data.get('username')
    password = data.get('password')
    wallet_address = data.get('wallet_address')
    chain_type = data.get('chain_type', 'ethereum')
    
    user = None
    
    if wallet_address:
        # Web3 login - find user by wallet address
        wallet = await db_query_one("""
            SELECT w.*, u.* FROM wallets w
            JOIN users u ON w.user_id = u.id
            WHERE w.wallet_address = ? AND w.chain_type = ? AND u.is_active = 1
        """, (wallet_address, chain_type))
        
        if wallet:
            user = wallet
        else:
            return jsonify({"error": "Wallet not registered"}), 401
    
    elif username and password:
        # Web2 login
        user = await db_query_one("SELECT * FROM users WHERE (username=? OR email=?) AND is_active=1", (username, username))
        if not user or not user['password_hash']:
            return jsonify({"error": "Invalid credentials"}), 401
        
        if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            return jsonify({"error": "Invalid credentials"}), 401
    
    else:
        return jsonify({"error": "Invalid login data"}), 400
    
    # Update last login
    await db_update("users", {"last_login": datetime.utcnow().isoformat()}, {"id": user['id']})
    
    # Create session and token
    session_id = await create_session(user['id'], request.headers.get('User-Agent'), request.remote_addr)
    token = generate_jwt_token(user)
    
    session['session_id'] = session_id
    
    await log_user_activity(user['id'], "login", {
        "method": "web3" if wallet_address else "web2",
        "chain_type": chain_type if wallet_address else None
    }, request.remote_addr, request.headers.get('User-Agent'))
    
    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "credits": user["credits"],
            "email_verified": user["email_verified"]
        }
    })

# ... (rest of the routes remain similar but with multi-chain support)



@app.route('/')
async def login_page():
    return await render_template("Auth-Context-Provider.html")



@app.route('/signup/')
async def signup_page():
    return await render_template("New.html")




@app.route('/platform/tools/')
@auth_required
async def platform_units():

    return await render_template("Platform-Tools-Pro.html")




@app.route('/dashboard/')
@auth_required
async def dashboard():
    """Get user profile with connected wallets"""
    Projects = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    
    print(Projects)
    # Sanitization 
    
    if(Projects):
        Projects_Index = len(Projects) 
    else:
        Projects_Index = int(0)
    profile_id = (g.current_user['user_id'])
    
    
    
    # Since Projects Already Exists Lets Hook Our Indexing here 
    # If Projects Doesnt Exist Then CMI , ARI  FSI , OTH
    
    if(Projects):
        # Was being logically Rev By The CMI Block from 1504
        # Init All Holdings With Int(0) 
        # Holding Inc : CMI , ARI , FSI , OTH 
        for x in CMI , ARI , FSI , OTH : 
            x = int(0) 
            
        
 
      
    CMI = len(await db_query("""
SELECT * FROM jobs WHERE user_id = ?  AND status = ? 
""", (g.current_user['user_id'], "completed")))
    ARI = len(await db_query("""
SELECT * FROM jobs WHERE user_id = ?  AND status = ? 
""", (g.current_user['user_id'], "started")))
    
    FSI = len(await db_query("""
SELECT * FROM jobs WHERE user_id = ?  AND status = ? 
""", (g.current_user['user_id'], "failed")))
    
    OTH = len(await db_query("""
SELECT * FROM jobs WHERE user_id = ?  AND status = ? 
""", (g.current_user['user_id'], "shared")))
    
    print(profile_id)
    
    Timestamp = utils.Space_Time_Generator("Mutate")
    
    # LEts extract All Jobs Run By This Account 
    return await render_template("Dashboard-Context-Provider.html", user=g.current_user , Projects = Projects  , Projects_Index = Projects_Index , Timestamp = Timestamp  , CMI = CMI  , ARI  = ARI  , FSI = FSI  , OTH = OTH  )




@app.route('/explorer/<string:sect>/<int:sid>/')
@auth_required
async def explorer(sect , sid):
    # Detections  : Unit Logs : Uploaded Files 
    """Get user profile with connected wallets"""
    Detections = await db_query("""
        SELECT id , job_id , user_id , frame_number , timestamp , class_name ,  class_id , confidence , bbox , image_path ,detection_group , created_at  FROM detections WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Detections)
    # Sanitization 
    
    if(Detections):
        Detections_Index = len(Detections) 
    else:
        Detections_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    # Detections  : Unit Logs : Uploaded Files 
    """Get user profile with connected wallets"""
    Projects = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Projects)
    # Sanitization 
    
    
    
    # Detections  : Unit Logs : Uploaded Files 
    """Get user profile with connected wallets"""
    Time_Analysis = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? AND task_name = ?  
    """, (g.current_user['user_id'], 'time_analysis'))
    print(Time_Analysis)
    
    Time_Index = len(Time_Analysis) if not Time_Analysis else int(0)
    
    
    

    
    # Detections  : Unit Logs : Uploaded Files 
    """Get user profile with connected wallets"""
    Motion_Analysis = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? AND task_name = ? 
    """, (g.current_user['user_id'],'motion_tracking'))
    print(Motion_Analysis)
    
    Motion_Index = len(Motion_Analysis) if not Motion_Analysis else int(0)
    
    
    # Sanitization 
    
    if(Projects):
        Projects_Index = len(Projects) 
    else:
        Projects_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    """Get user profile with connected wallets"""
    Upload_Feed = await db_query("""
        SELECT * FROM uploads WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Upload_Feed)
    # Sanitization 
    
    if(Upload_Feed):
        Upload_Index = len(Upload_Feed) 
    else:
        Upload_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    """Get user profile with connected wallets"""
    Projects_Listings = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Projects_Listings)
    # Sanitization 
    if not sid or sid == int(0) :
        sid = Projects_Listings[-1]['id']

    sid = await db_query("""
        SELECT id FROM jobs WHERE user_id = ? AND id = ? 
    """, (g.current_user['user_id'],sid))
    
    if(sid):
        print('this is sid' , sid[0]['id'])
    else:
        return redirect('explorer' , sect = "Dashboard" )
    
    if(Projects_Listings):
        Projects_Index = len(Projects_Listings) 
    else:
        Projects_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    #  Get The Last Job 
    
    #print("this is last job" , Last_Job['id'])
    fixer = (str('job_') + str(sid[0]['id']))
    
    Export_Path = str((os.path.join(app.static_folder , 'detections' , fixer)))
    
    # Lets HAndle This Exclusively To Prevent Replay Errors For Missing Directories If Not FOund Under **JOb_**


    try:
        Media_Gallery =  os.listdir(os.path.join(app.root_path , 'detections' , fixer))
        print(os.path.join(app.root_path , 'detections' , fixer))
    except Exception as e :
        Media_Gallery = "No Files"
    
    if(Media_Gallery):
        Media_Index = len(Media_Gallery)
    else: 

        Media_Index = int(0) 
        
    print("this is " , (Media_Gallery))
    print(Export_Path)
    

    
    
    return await render_template("Explorer-Context-Provider.html", sect = sect  , user=g.current_user , Detection = Detections , Detections_Index = Detections_Index  , Upload_Feed = Upload_Feed , Upload_Index = Upload_Index  , Projects = Projects  , Projects_Index = Projects_Index , Time_Analysis = Time_Analysis , Time_Index = Time_Index , Motion_Analysis = Motion_Analysis , Motion_Index = Motion_Index , Projects_Listings = Projects_Listings , fixer = fixer , Export_Path = Export_Path , Media_Gallery = Media_Gallery , Media_Index = Media_Index  ) 
                                  






@app.route('/projects/')
@auth_required
async def augmented_projects():
    """Get user profile with connected wallets"""
    Projects = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    
    # Since Projects Already Exists Lets Hook Our Indexing here 
    # If Projects Doesnt Exist Then CMI , ARI  FSI , OTH
    if(Projects):
        CMI = len(await db_query("""
    SELECT * FROM jobs WHERE user_id = ?  AND status = ? 
""", (g.current_user['user_id'], "completed")))
        ARI = len(await db_query("""
    SELECT * FROM jobs WHERE user_id = ?  AND status = ? 
""", (g.current_user['user_id'], "started")))
        
        FSI = len(await db_query("""
    SELECT * FROM jobs WHERE user_id = ?  AND status = ? 
""", (g.current_user['user_id'], "failed")))
        
        OTH = len(await db_query("""
    SELECT * FROM jobs WHERE user_id = ?  AND status = ? 
""", (g.current_user['user_id'], "shared")))
    else:
        # Init All Holdings With Int(0) 
        # Holding Inc : CMI , ARI , FSI , OTH 
        for x in CMI , ARI , FSI , OTH : 
            x = int(0) 
            
        
    print(Projects)
    # Sanitization 
    
    if(Projects):
        Projects_Index = len(Projects) 
    else:
        Projects_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    return await render_template("Projects-Context-Provider.html", Projects = Projects  , Projects_Index = Projects_Index ,  CMI = CMI , ARI = ARI , FSI =FSI , OTH = OTH , user=g.current_user)


# -------------------------
# Main Application Routes (Same structure as before)
# -------------------------

# User profile endpoint
@app.route('/api/user/<int:user_id>')
async def get_user_profile(user_id):
    try:
        user = await fetch_user_by_addr(user_id)
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


# ... (MOTION TRAJECTORY LINEUP)
# Fix the average filter and update the results route


@app.template_filter('average')
def average_filter(values):
    """Calculate average of a list of values"""
    if values is None:
        return 0
    
    # Convert async generator or other iterable to list
    if hasattr(values, '__aiter__'):
        # Handle async generators by converting to list (in practice, we should await this)
        # For template filters, we need to work with sync data
        return 0
    elif hasattr(values, '__iter__'):
        values_list = list(values)
    else:
        values_list = [values]
    
    if not values_list or len(values_list) == 0:
        return 0
    
    numeric_values = [v for v in values_list if isinstance(v, (int, float))]
    return sum(numeric_values) / len(numeric_values) if numeric_values else 0

# Add a new filter to handle async data safely
@app.template_filter('sync_list')
def sync_list_filter(values):
    """Convert async generator to list for template usage"""
    if hasattr(values, '__aiter__'):
        # In template context, we can't await, so return empty list
        return []
    elif hasattr(values, '__iter__'):
        return list(values)
    else:
        return [values]



##############################################################################################################
############################################## MOTION TRACKER RIDGELINE ##########################################
class MotionTracker:
    """Advanced multi-object tracking with Kalman filtering"""
    
    def __init__(self, max_disappeared=10, max_distance=100):
        self.next_object_id = 0
        self.objects = {}
        self.disappeared = {}
        self.max_disappeared = max_disappeared
        self.max_distance = max_distance
        
        # Trajectory storage
        self.trajectories = defaultdict(list)
        self.speed_history = defaultdict(list)
        self.direction_history = defaultdict(list)
        self.kalman_filters = {}
        
    def _create_kalman_filter(self):
        """Create a Kalman filter for object tracking"""
        kf = KalmanFilter(dim_x=4, dim_z=2)
        
        kf.F = np.array([[1, 0, 1, 0],
                         [0, 1, 0, 1], 
                         [0, 0, 1, 0],
                         [0, 0, 0, 1]])
        
        kf.H = np.array([[1, 0, 0, 0],
                         [0, 1, 0, 0]])
        
        kf.Q = np.eye(4) * 0.1
        kf.R = np.eye(2) * 1
        kf.P *= 100
        
        return kf
        
    def register(self, centroid, bbox, class_name, confidence, frame_num, timestamp):
        """Register a new object"""
        object_id = self.next_object_id
        
        self.objects[object_id] = {
            'centroid': centroid,
            'bbox': bbox,
            'class_name': class_name,
            'confidence': confidence,
            'last_seen': frame_num,
            'first_seen': frame_num
        }
        self.disappeared[object_id] = 0
        self.trajectories[object_id].append((centroid[0], centroid[1], frame_num, timestamp))
        
        # Initialize Kalman filter
        kf = self._create_kalman_filter()
        kf.x = np.array([centroid[0], centroid[1], 0, 0])
        self.kalman_filters[object_id] = kf
        
        self.next_object_id += 1
        return object_id
    
    def deregister(self, object_id):
        """Remove an object that has disappeared"""
        if object_id in self.objects:
            del self.objects[object_id]
        if object_id in self.disappeared:
            del self.disappeared[object_id]
        if object_id in self.kalman_filters:
            del self.kalman_filters[object_id]
    
    def update(self, detections, frame_num, timestamp):
        """Update tracker with new detections"""
        # Predict next positions using Kalman filters
        for object_id, kf in self.kalman_filters.items():
            kf.predict()
            
        if len(detections) == 0:
            for object_id in list(self.disappeared.keys()):
                self.disappeared[object_id] += 1
                if self.disappeared[object_id] > self.max_disappeared:
                    self.deregister(object_id)
            return self.objects
        
        if len(self.objects) == 0:
            for detection in detections:
                centroid = self._get_centroid(detection['bbox'])
                self.register(centroid, detection['bbox'], detection['class_name'], 
                            detection['confidence'], frame_num, timestamp)
        else:
            predicted_centroids = []
            object_ids = list(self.objects.keys())
            
            for object_id in object_ids:
                if object_id in self.kalman_filters:
                    predicted_pos = self.kalman_filters[object_id].x[:2]
                    predicted_centroids.append(predicted_pos)
                else:
                    predicted_centroids.append(self.objects[object_id]['centroid'])
            
            detection_centroids = [self._get_centroid(det['bbox']) for det in detections]
            
            distances = np.linalg.norm(np.array(predicted_centroids)[:, np.newaxis] - 
                                     np.array(detection_centroids), axis=2)
            
            rows = distances.min(axis=1).argsort()
            cols = distances.argmin(axis=1)[rows]
            
            used_row_indices = set()
            used_col_indices = set()
            
            for (row, col) in zip(rows, cols):
                if row in used_row_indices or col in used_col_indices:
                    continue
                
                if distances[row, col] <= self.max_distance:
                    object_id = object_ids[row]
                    detection = detections[col]
                    centroid = detection_centroids[col]
                    
                    old_centroid = self.objects[object_id]['centroid']
                    self.objects[object_id]['centroid'] = centroid
                    self.objects[object_id]['bbox'] = detection['bbox']
                    self.objects[object_id]['confidence'] = detection['confidence']
                    self.objects[object_id]['last_seen'] = frame_num
                    self.disappeared[object_id] = 0
                    
                    if object_id in self.kalman_filters:
                        self.kalman_filters[object_id].update(np.array(centroid))
                    
                    if len(self.trajectories[object_id]) > 0:
                        speed = self._calculate_speed(old_centroid, centroid)
                        direction = self._calculate_direction(old_centroid, centroid)
                        
                        self.speed_history[object_id].append(speed)
                        self.direction_history[object_id].append(direction)
                    
                    self.trajectories[object_id].append((centroid[0], centroid[1], frame_num, timestamp))
                    
                    used_row_indices.add(row)
                    used_col_indices.add(col)
            
            unused_row_indices = set(range(0, distances.shape[0])).difference(used_row_indices)
            unused_col_indices = set(range(0, distances.shape[1])).difference(used_col_indices)
            
            for row in unused_row_indices:
                object_id = object_ids[row]
                self.disappeared[object_id] += 1
                if self.disappeared[object_id] > self.max_disappeared:
                    self.deregister(object_id)
            
            for col in unused_col_indices:
                detection = detections[col]
                centroid = detection_centroids[col]
                self.register(centroid, detection['bbox'], detection['class_name'], 
                            detection['confidence'], frame_num, timestamp)
        
        return self.objects
    
    def _get_centroid(self, bbox):
        """Calculate centroid from bounding box"""
        x, y, w, h = bbox
        return (int(x + w/2), int(y + h/2))
    
    def _calculate_speed(self, old_centroid, new_centroid):
        """Calculate speed between two points"""
        return euclidean(old_centroid, new_centroid)
    
    def _calculate_direction(self, old_centroid, new_centroid):
        """Calculate direction angle between two points"""
        dx = new_centroid[0] - old_centroid[0]
        dy = new_centroid[1] - old_centroid[1]
        return np.arctan2(dy, dx) * 180 / np.pi
    
    def get_trajectory_analysis(self):
        """Get comprehensive trajectory analysis"""
        analysis = {}
        
        for object_id, trajectory in self.trajectories.items():
            if len(trajectory) < 2:
                continue
                
            traj_array = np.array(trajectory)
            
            total_distance = 0
            for i in range(1, len(trajectory)):
                total_distance += euclidean(trajectory[i][:2], trajectory[i-1][:2])
            
            avg_speed = np.mean(self.speed_history[object_id]) if self.speed_history[object_id] else 0
            max_speed = np.max(self.speed_history[object_id]) if self.speed_history[object_id] else 0
            
            directions = self.direction_history[object_id]
            direction_variance = np.var(directions) if directions else 0
            
            start_time = trajectory[0][3] if len(trajectory) > 0 else 0
            end_time = trajectory[-1][3] if len(trajectory) > 0 else 0
            duration = end_time - start_time
            
            x_coords = [point[0] for point in trajectory]
            y_coords = [point[1] for point in trajectory]
            
            analysis[object_id] = {
                'object_class': self.objects.get(object_id, {}).get('class_name', 'unknown'),
                'total_distance': total_distance,
                'avg_speed': avg_speed,
                'max_speed': max_speed,
                'duration': duration,
                'direction_variance': direction_variance,
                'path_straightness': 1.0 / (1.0 + direction_variance) if direction_variance > 0 else 1.0,
                'bounding_rect': {
                    'x_min': min(x_coords), 'x_max': max(x_coords),
                    'y_min': min(y_coords), 'y_max': max(y_coords)
                },
                'trajectory_points': len(trajectory),
                'start_frame': trajectory[0][2],
                'end_frame': trajectory[-1][2]
            }
            
        return analysis


class MotionHeatmapGenerator:
    """Generate motion heatmaps and trajectory visualizations"""
    
    def __init__(self, frame_width, frame_height):
        self.frame_width = frame_width
        self.frame_height = frame_height
        self.heatmap_data = np.zeros((frame_height, frame_width), dtype=np.float32)
        self.trajectory_heatmap = np.zeros((frame_height, frame_width), dtype=np.float32)
        
    def add_detection(self, bbox, confidence=1.0):
        """Add a detection to the heatmap"""
        x, y, w, h = bbox
        x, y, w, h = int(x), int(y), int(w), int(h)
        
        x = max(0, min(x, self.frame_width - 1))
        y = max(0, min(y, self.frame_height - 1))
        w = min(w, self.frame_width - x)
        h = min(h, self.frame_height - y)
        
        center_x, center_y = x + w//2, y + h//2
        
        kernel_size = max(w, h) // 2
        if kernel_size < 5:
            kernel_size = 5
            
        y_indices, x_indices = np.ogrid[:kernel_size*2+1, :kernel_size*2+1]
        gaussian = np.exp(-((x_indices - kernel_size)**2 + (y_indices - kernel_size)**2) / (2.0 * (kernel_size/3)**2))
        
        start_y = max(0, center_y - kernel_size)
        end_y = min(self.frame_height, center_y + kernel_size + 1)
        start_x = max(0, center_x - kernel_size)
        end_x = min(self.frame_width, center_x + kernel_size + 1)
        
        gaussian_start_y = max(0, kernel_size - center_y) if center_y < kernel_size else 0
        gaussian_end_y = gaussian_start_y + (end_y - start_y)
        gaussian_start_x = max(0, kernel_size - center_x) if center_x < kernel_size else 0
        gaussian_end_x = gaussian_start_x + (end_x - start_x)
        
        if gaussian_end_y > gaussian_start_y and gaussian_end_x > gaussian_start_x:
            self.heatmap_data[start_y:end_y, start_x:end_x] += gaussian[gaussian_start_y:gaussian_end_y, gaussian_start_x:gaussian_end_x] * confidence
    
    def add_trajectory_point(self, point, intensity=1.0):
        """Add a trajectory point to the trajectory heatmap"""
        x, y = int(point[0]), int(point[1])
        if 0 <= x < self.frame_width and 0 <= y < self.frame_height:
            for dx in range(-2, 3):
                for dy in range(-2, 3):
                    if 0 <= x+dx < self.frame_width and 0 <= y+dy < self.frame_height:
                        if dx*dx + dy*dy <= 4:
                            self.trajectory_heatmap[y+dy, x+dx] += intensity
    
    def generate_heatmap_image(self, colormap='hot'):
        """Generate heatmap visualization"""
        if self.heatmap_data.max() > 0:
            normalized = self.heatmap_data / self.heatmap_data.max()
        else:
            normalized = self.heatmap_data
            
        cmap = plt.get_cmap(colormap)
        colored = cmap(normalized)
        heatmap_img = (colored * 255).astype(np.uint8)
        
        return heatmap_img
    
    def generate_trajectory_heatmap(self, colormap='plasma'):
        """Generate trajectory heatmap visualization"""
        if self.trajectory_heatmap.max() > 0:
            normalized = self.trajectory_heatmap / self.trajectory_heatmap.max()
        else:
            normalized = self.trajectory_heatmap
            
        cmap = plt.get_cmap(colormap)
        colored = cmap(normalized)
        trajectory_img = (colored * 255).astype(np.uint8)
        
        return trajectory_img

    def generate_object_trajectory(self, trajectory_points, frame_width=None, frame_height=None):
        """Generate individual object trajectory visualization"""
        if not frame_width:
            frame_width = self.frame_width
        if not frame_height:
            frame_height = self.frame_height
            
        fig, ax = plt.subplots(figsize=(10, 8))
        
        x_coords = [point[0] for point in trajectory_points]
        y_coords = [point[1] for point in trajectory_points]
        
        ax.plot(x_coords, y_coords, 'b-', linewidth=2, alpha=0.7, label='Trajectory')
        ax.scatter(x_coords, y_coords, c=range(len(x_coords)), cmap='viridis', s=30, alpha=0.8)
        
        if len(trajectory_points) > 0:
            ax.scatter(x_coords[0], y_coords[0], color='green', s=100, marker='o', label='Start')
            ax.scatter(x_coords[-1], y_coords[-1], color='red', s=100, marker='s', label='End')
        
        ax.set_xlim(0, frame_width)
        ax.set_ylim(frame_height, 0)
        ax.set_xlabel('X Position (pixels)')
        ax.set_ylabel('Y Position (pixels)')
        ax.set_title('Object Trajectory Path')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        plt.close()
        
        return buffer.getvalue()


# Update the MotionAnalyzer class to use the standalone function
class MotionAnalyzer:
    """Main motion analysis processor"""
    
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        
    async def process_video_for_motion(self, video_path: str, job_id: int, user_id: int, 
                                     confidence_threshold: float = 0.5, 
                                     frame_skip: int = 5):
        """Process video for motion tracking and analysis"""
        
        try:
            active_jobs[job_id] = {'status': 'processing', 'progress': 0, 'message': 'Initializing...'}
            await self._update_job_status(job_id, 'processing', "Initializing video processing")
            
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise ValueError(f"Cannot open video file: {video_path}")
            
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            tracker = MotionTracker(max_disappeared=15, max_distance=150)
            heatmap_gen = MotionHeatmapGenerator(frame_width, frame_height)
            
            backSub = cv2.createBackgroundSubtractorMOG2(detectShadows=True)
            
            frame_count = 0
            processed_frames = 0
            
            active_jobs[job_id] = {'status': 'processing', 'progress': 0, 'message': f'Processing {total_frames} frames'}
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                current_time = frame_count / fps if fps > 0 else frame_count
                
                if frame_count % (frame_skip + 1) == 0:
                    fg_mask = backSub.apply(frame)
                    
                    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
                    fg_mask = cv2.morphologyEx(fg_mask, cv2.MORPH_OPEN, kernel)
                    
                    contours, _ = cv2.findContours(fg_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                    
                    detections = []
                    for contour in contours:
                        if cv2.contourArea(contour) > 500:
                            x, y, w, h = cv2.boundingRect(contour)
                            
                            if w > 20 and h > 20 and w < frame_width/2 and h < frame_height/2:
                                detection = {
                                    'bbox': (x, y, w, h),
                                    'confidence': 0.8,
                                    'class_name': 'moving_object'
                                }
                                detections.append(detection)
                                heatmap_gen.add_detection((x, y, w, h), 0.8)
                    
                    tracked_objects = tracker.update(detections, frame_count, current_time)
                    
                    for obj_id, obj_info in tracked_objects.items():
                        if obj_id in tracker.trajectories:
                            trajectory = tracker.trajectories[obj_id]
                            if len(trajectory) > 0:
                                latest_point = trajectory[-1]
                                heatmap_gen.add_trajectory_point(latest_point[:2])
                    
                    processed_frames += 1
                    
                    if processed_frames % 20 == 0:
                        progress = (frame_count / total_frames) * 100
                        active_jobs[job_id] = {
                            'status': 'processing', 
                            'progress': progress, 
                            'message': f'Processed {processed_frames} frames ({progress:.1f}%)'
                        }
                
                frame_count += 1
                
                if frame_count % 100 == 0:
                    await asyncio.sleep(0.01)
            
            cap.release()
            
            active_jobs[job_id] = {'status': 'processing', 'progress': 90, 'message': 'Generating analysis...'}
            trajectory_analysis = tracker.get_trajectory_analysis()
            heatmap_img = heatmap_gen.generate_heatmap_image()
            trajectory_heatmap = heatmap_gen.generate_trajectory_heatmap()
            
            results = await self._save_motion_results(
                job_id, user_id, trajectory_analysis, 
                heatmap_img, trajectory_heatmap, tracker
            )
            
            active_jobs[job_id] = {
                'status': 'completed', 
                'progress': 100, 
                'message': f'Analysis completed. Tracked {len(trajectory_analysis)} objects'
            }
            await self._update_job_status(job_id, 'completed', 
                                        f"Motion analysis completed. Tracked {len(trajectory_analysis)} objects")
            
            return results
            
        except Exception as e:
            active_jobs[job_id] = {'status': 'failed', 'progress': 0, 'message': str(e)}
            await self._update_job_status(job_id, 'failed', str(e))
            raise e
    
    async def _save_motion_results(self, job_id: int, user_id: int, analysis: Dict, 
                                 heatmap_img: np.ndarray, trajectory_heatmap: np.ndarray, 
                                 tracker: MotionTracker):
        """Save motion analysis results to database"""
        
        heatmap_b64 = self._image_to_base64(heatmap_img)
        trajectory_b64 = self._image_to_base64(trajectory_heatmap)
        
        # Ensure analysis data is JSON serializable
        serializable_analysis = {}
        for obj_id, obj_analysis in analysis.items():
            serializable_analysis[str(obj_id)] = {
                k: (float(v) if isinstance(v, (int, float, np.number)) else str(v) if v is not None else None)
                for k, v in obj_analysis.items()
            }
        
        async with aiosqlite.connect(self.db_path) as db:
              # Use the standalone function
            
            await db.execute("""
                INSERT INTO motion_analysis 
                (job_id, user_id, total_objects, analysis_data, heatmap_image, trajectory_heatmap)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (job_id, user_id, len(analysis), json.dumps(serializable_analysis), heatmap_b64, trajectory_b64))
            
            analysis_id = job_id
            
            for obj_id, obj_analysis in analysis.items():
                # Ensure trajectory data is properly formatted
                trajectory_points = tracker.trajectories.get(obj_id, [])
                serializable_trajectory = []
                for point in trajectory_points:
                    if len(point) >= 2:
                        trajectory_point = [
                            float(point[0]) if point[0] is not None else 0.0,
                            float(point[1]) if point[1] is not None else 0.0
                        ]
                        if len(point) > 2:
                            trajectory_point.append(int(point[2]) if point[2] is not None else 0)
                        if len(point) > 3:
                            trajectory_point.append(float(point[3]) if point[3] is not None else 0.0)
                        serializable_trajectory.append(trajectory_point)
                
                # Fix: Ensure speed and direction data are proper JSON arrays, not string representations
                speed_data = tracker.speed_history.get(obj_id, [])
                direction_data = tracker.direction_history.get(obj_id, [])
                
                # Convert numpy types to Python native types
                speed_data_clean = [float(s) if isinstance(s, (int, float, np.number)) else 0.0 for s in speed_data]
                direction_data_clean = [float(d) if isinstance(d, (int, float, np.number)) else 0.0 for d in direction_data]
                
                trajectory_json = json.dumps(serializable_trajectory)
                speed_json = json.dumps(speed_data_clean)
                direction_json = json.dumps(direction_data_clean)
                
                await db.execute("""
                    INSERT INTO object_trajectories 
                    (analysis_id, object_id, object_class, trajectory_data, speed_data, 
                     direction_data, total_distance, avg_speed, max_speed, duration)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    analysis_id, 
                    obj_id, 
                    obj_analysis.get('object_class', 'unknown'), 
                    trajectory_json,
                    speed_json, 
                    direction_json, 
                    float(obj_analysis.get('total_distance', 0)),
                    float(obj_analysis.get('avg_speed', 0)), 
                    float(obj_analysis.get('max_speed', 0)), 
                    float(obj_analysis.get('duration', 0))
                ))
            
            await db.commit()
            
        return {
            'analysis_id': analysis_id,
            'total_objects': len(analysis),
            'analysis_data': serializable_analysis,
            'heatmap_available': True,
            'trajectory_heatmap_available': True
        }
    
    def _image_to_base64(self, img: np.ndarray) -> str:
        """Convert numpy image to base64 string"""
        _, buffer = cv2.imencode('.png', img)
        img_b64 = base64.b64encode(buffer).decode('utf-8')
        return img_b64
    
    async def _update_job_status(self, job_id: int, status: str, message: str = ""):
        """Update job status in database"""
        async with aiosqlite.connect(self.db_path) as db:
              # Use the standalone function
            if status == 'completed':
                await db.execute("""
                    UPDATE jobs SET status = ?, completed_at = datetime('now') WHERE id = ?
                """, (status, job_id))
            elif status == 'processing' and message:
                await db.execute("""
                    UPDATE jobs SET status = ?, started_at = datetime('now') WHERE id = ?
                """, (status, job_id))
            else:
                await db.execute("""
                    UPDATE jobs SET status = ? WHERE id = ?
                """, (status, job_id))
                
            await db.commit()

# Also update the database creation to ensure proper data storage
# Fix the _save_motion_results method in MotionAnalyzer class
async def _save_motion_results(self, job_id: int, user_id: int, analysis: Dict, 
                             heatmap_img: np.ndarray, trajectory_heatmap: np.ndarray, 
                             tracker: MotionTracker):
    """Save motion analysis results to database"""
    
    heatmap_b64 = self._image_to_base64(heatmap_img)
    trajectory_b64 = self._image_to_base64(trajectory_heatmap)
    
    # Ensure analysis data is JSON serializable
    serializable_analysis = {}
    for obj_id, obj_analysis in analysis.items():
        serializable_analysis[str(obj_id)] = {
            k: (float(v) if isinstance(v, (int, float, np.number)) else str(v) if v is not None else None)
            for k, v in obj_analysis.items()
        }
    
    async with aiosqlite.connect(self.db_path) as db:
        await self._create_tables(db)
        
        await db.execute("""
            INSERT INTO motion_analysis 
            (job_id, user_id, total_objects, analysis_data, heatmap_image, trajectory_heatmap)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (job_id, g.current_user['user_id'], len(analysis), json.dumps(serializable_analysis), heatmap_b64, trajectory_b64))
        
        analysis_id = job_id
        
        for obj_id, obj_analysis in analysis.items():
            # Ensure trajectory data is properly formatted
            trajectory_points = tracker.trajectories.get(obj_id, [])
            serializable_trajectory = []
            for point in trajectory_points:
                if len(point) >= 2:
                    trajectory_point = [
                        float(point[0]) if point[0] is not None else 0.0,
                        float(point[1]) if point[1] is not None else 0.0
                    ]
                    if len(point) > 2:
                        trajectory_point.append(int(point[2]) if point[2] is not None else 0)
                    if len(point) > 3:
                        trajectory_point.append(float(point[3]) if point[3] is not None else 0.0)
                    serializable_trajectory.append(trajectory_point)
            
            # Fix: Ensure speed and direction data are proper JSON arrays, not string representations
            speed_data = tracker.speed_history.get(obj_id, [])
            direction_data = tracker.direction_history.get(obj_id, [])
            
            # Convert numpy types to Python native types
            speed_data_clean = [float(s) if isinstance(s, (int, float, np.number)) else 0.0 for s in speed_data]
            direction_data_clean = [float(d) if isinstance(d, (int, float, np.number)) else 0.0 for d in direction_data]
            
            trajectory_json = json.dumps(serializable_trajectory)
            speed_json = json.dumps(speed_data_clean)
            direction_json = json.dumps(direction_data_clean)
            
            await db.execute("""
                INSERT INTO object_trajectories 
                (analysis_id, object_id, object_class, trajectory_data, speed_data, 
                 direction_data, total_distance, avg_speed, max_speed, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_id, 
                obj_id, 
                obj_analysis.get('object_class', 'unknown'), 
                trajectory_json,
                speed_json, 
                direction_json, 
                float(obj_analysis.get('total_distance', 0)),
                float(obj_analysis.get('avg_speed', 0)), 
                float(obj_analysis.get('max_speed', 0)), 
                float(obj_analysis.get('duration', 0))
            ))
        
        await db.commit()
        
    return {
        'analysis_id': analysis_id,
        'total_objects': len(analysis),
        'analysis_data': serializable_analysis,
        'heatmap_available': True,
        'trajectory_heatmap_available': True
    }

    
def _image_to_base64(self, img: np.ndarray) -> str:
    """Convert numpy image to base64 string"""
    _, buffer = cv2.imencode('.png', img)
    img_b64 = base64.b64encode(buffer).decode('utf-8')
    return img_b64

async def _update_job_status(self, job_id: int, status: str, message: str = ""):
    """Update job status in database"""
    async with aiosqlite.connect(self.db_path) as db:
        await self._create_tables(db)
        if status == 'completed':
            await db.execute("""
                UPDATE jobs SET status = ?, completed_at = datetime('now') WHERE id = ?
            """, (status, job_id))
        elif status == 'processing' and message:
            await db.execute("""
                UPDATE jobs SET status = ?, started_at = datetime('now') WHERE id = ?
            """, (status, job_id))
        else:
            await db.execute("""
                UPDATE jobs SET status = ? WHERE id = ?
            """, (status, job_id))
            
        await db.commit()




# API ROutes DECL




# API Routes

@app.route('/Motion')
@auth_required
async def handshake_motion():
    """Enhanced dashboard"""
    
    # Returning Augmented Profiles Relating To  Motion Detection Jobs 
    """Get user profile with connected wallets"""
    Projects = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? AND task_name = ?
    """, (g.current_user['user_id'],"motion_tracking"))
    print(Projects)
    # Sanitization 
    
    if(Projects):
        Projects_Index = len(Projects) 
    else:
        Projects_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    return await render_template("Motion-Profiling-Concept.html" , user = g.current_user  ,Projects = Projects , Projects_Index = Projects_Index  )


@app.route('/motion/dashboard')
@auth_required
async def motion_dashboard():
    """Interactive dashboard"""
    stats = await get_dashboard_stats()
    recent_jobs = await get_recent_jobs()
    return await render_template_string("Interactive-Motion-Controller.html", stats=stats, recent_jobs=recent_jobs)


@app.route('/upload', methods=['GET', 'POST'])
@auth_required
async def upload_video():

    """Handle video upload"""
    if request.method == 'GET':
        return await render_template("Motion-Upload-Concept.html" , user = g.current_user )
    
    files = await request.files
    form = await request.form
    
    if 'video' not in files:
        return jsonify({'error': 'No video file provided'}), 400
    
    video_file = files['video']
    if video_file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
      
    up_id = random.randrange(10000000)
    user_id = g.current_user['user_id']
    byte_size = str(int(34))
    filename = f"{int(time.time())}_{video_file.filename}"
    file_path = os.path.join(UPLOAD_DIR , filename)
    Generic_Hash = None
     
    await video_file.save(str(file_path))
    
    async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                INSERT INTO uploads (id , user_id, filename , saved_path , size_bytes , file_hash ,  upload_method , 
                            created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+24 hours'))
             """, (up_id , user_id, filename , file_path , byte_size ,  Generic_Hash if Generic_Hash else '404X' , 'file' if file_path else 'url'))
            await db.commit()
    
    

    
    confidence = float(form.get('confidence', 0.5))
    frame_skip = int(form.get('frame_skip', 5))
    
    user_id = g.current_user['user_id']
    job_id = await create_motion_job(user_id, str(file_path), 
                                   confidence=confidence, frame_skip=frame_skip)
    
    return jsonify({
        'job_id': job_id,
        'status': 'created',
        'message': 'Upload successful, processing started'
    })


# Fix the view_results route to properly handle the data
@app.route('/results/<int:job_id>')
@auth_required
async def view_results(job_id):
    """View analysis results"""
    user_id = g.current_user['user_id']
    results = await get_motion_results(job_id, user_id)
    
    if not results:
        return "Job not found", 404
    
    if results.get('status') != 'completed':
        return await render_template("Motion-Progress-Concept.html", job_id=job_id, status=results)
    
    # Ensure trajectories is a proper list for template usage
    if 'trajectories' in results and hasattr(results['trajectories'], '__aiter__'):
        results['trajectories'] = []
    elif 'trajectories' in results:
        results['trajectories'] = list(results['trajectories'])
    
    return await render_template("Motion-Result-Concept.html", job_id=job_id, results=results)



# Fix the track_object route with better JSON parsing
@app.route('/track/<int:job_id>/<int:object_id>')
@auth_required
async def track_object(job_id, object_id):
    """Individual object tracking view"""
   
    user_id = g.current_user['user_id']
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT ot.*, ma.analysis_data 
                FROM object_trajectories ot
                JOIN motion_analysis ma ON ot.analysis_id = ma.id
                JOIN jobs j ON ma.job_id = j.id
                WHERE j.id = ? AND j.user_id = ? AND ot.object_id = ?
            """, (job_id, user_id, object_id))
            result = await cursor.fetchone()
            
            if not result:
                return "Object trajectory not found", 404
            
            # Safely parse JSON data with comprehensive error handling
            def safe_json_parse(data, default=None):
                """Safely parse JSON data with multiple fallbacks"""
                if data is None or data == '':
                    return default if default is not None else []
                
                # If it's already a list/dict, return it
                if isinstance(data, (list, dict)):
                    return data
                
                # Try to parse as JSON
                try:
                    return json.loads(data)
                except (json.JSONDecodeError, TypeError) as e:
                    print(f"JSON parse error: {e}, data: {repr(data)}")
                    
                    # If it looks like a string representation of a list, try eval (carefully)
                    if isinstance(data, str) and data.startswith('[') and data.endswith(']'):
                        try:
                            # Use ast.literal_eval for safe evaluation
                            import ast
                            return ast.literal_eval(data)
                        except (SyntaxError, ValueError) as e2:
                            print(f"Literal eval error: {e2}")
                    
                    return default if default is not None else []
            
            trajectory_data = safe_json_parse(result[3], [])
            speed_data = safe_json_parse(result[4], [])
            direction_data = safe_json_parse(result[5], [])
            analysis_data = safe_json_parse(result[11], {})
            
            # Fix: Ensure numeric values are properly converted
            def safe_float(value, default=0.0):
                """Safely convert to float"""
                if value is None:
                    return default
                try:
                    return float(value)
                except (ValueError, TypeError):
                    return default
            
            object_info = {
                'object_id': object_id,
                'job_id': job_id,
                'object_class': result[2] or 'unknown',
                'trajectory_points': trajectory_data,
                'speed_data': speed_data,
                'direction_data': direction_data,
                'total_distance': safe_float(result[6]),
                'avg_speed': safe_float(result[7]),
                'max_speed': safe_float(result[8]),
                'duration': safe_float(result[9]),
                'analysis_summary': analysis_data.get(str(object_id), {})
            }
            
            print(f"Loaded object {object_id}: {len(trajectory_data)} trajectory points")
            
            return await render_template("Motion-Object-Tracker.html", object_info=object_info)
            
    except Exception as e:
        print(f"Error loading object tracking: {e}")
        import traceback
        traceback.print_exc()
        return f"Error loading object tracking: {str(e)}", 500





# Update the migrate_database function to use the standalone create_tables function
async def migrate_database():
    """Migrate existing database to fix data format issues"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
              # Use the standalone function
            
            # Check if we need to migrate
            cursor = await db.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND name='object_trajectories'
            """)
            if not await cursor.fetchone():
                return  # No trajectories table yet
            
            # Check for problematic data
            cursor = await db.execute("""
                SELECT object_id, speed_data, direction_data FROM object_trajectories 
                WHERE speed_data LIKE '[%' OR direction_data LIKE '[%'
            """)
            problematic_records = await cursor.fetchall()
            
            for record in problematic_records:
                object_id, speed_data, direction_data = record
                
                # Fix speed data
                if speed_data and speed_data.startswith('[') and speed_data.endswith(']'):
                    try:
                        import ast
                        fixed_speed = json.dumps(ast.literal_eval(speed_data))
                        await db.execute("UPDATE object_trajectories SET speed_data = ? WHERE object_id = ?", 
                                       (fixed_speed, object_id))
                        print(f"Fixed speed data for object {object_id}")
                    except:
                        print(f"Could not fix speed data for object {object_id}")
                
                # Fix direction data
                if direction_data and direction_data.startswith('[') and direction_data.endswith(']'):
                    try:
                        import ast
                        fixed_direction = json.dumps(ast.literal_eval(direction_data))
                        await db.execute("UPDATE object_trajectories SET direction_data = ? WHERE object_id = ?", 
                                       (fixed_direction, object_id))
                        print(f"Fixed direction data for object {object_id}")
                    except:
                        print(f"Could not fix direction data for object {object_id}")
            
            await db.commit()
            print("Database migration completed")
            
    except Exception as e:
        print(f"Database migration error: {e}")



# Add a route to trigger database migration
@app.route('/admin/migrate-db')
async def admin_migrate_db():
    """Admin route to migrate database (one-time use)"""
    await migrate_database()
    return jsonify({'status': 'Migration completed'})





# Update the get_object_trajectory_image function with better error handling
@app.route('/api/motion/object-trajectory/<int:job_id>/<int:object_id>')
@auth_required
async def get_object_trajectory_image(job_id, object_id):
    """Get individual object trajectory visualization"""

    user_id = g.current_user['user_id']
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT trajectory_data FROM object_trajectories ot
                JOIN motion_analysis ma ON ot.analysis_id = ma.id
                JOIN jobs j ON ma.job_id = j.id
                WHERE j.id = ? AND j.user_id = ? AND ot.object_id = ?
            """, (job_id, user_id, object_id))
            result = await cursor.fetchone()
            
            if not result or not result[0]:
                return jsonify({'error': 'Object trajectory not found or empty'}), 404
            
            # Safely parse trajectory data with multiple fallbacks
            trajectory_data = None
            data = result[0]
            
            # Try JSON parse first
            try:
                trajectory_data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                # Try literal eval for string representations
                try:
                    import ast
                    trajectory_data = ast.literal_eval(data)
                except (SyntaxError, ValueError):
                    trajectory_data = []
            
            if not trajectory_data or len(trajectory_data) == 0:
                # Create a simple placeholder image
                fig, ax = plt.subplots(figsize=(10, 8))
                ax.text(0.5, 0.5, 'No trajectory data available', 
                       horizontalalignment='center', verticalalignment='center',
                       transform=ax.transAxes, fontsize=16)
                ax.set_xlim(0, 1)
                ax.set_ylim(0, 1)
                ax.axis('off')
                
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
                plt.close()
                
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                temp_file.write(buffer.getvalue())
                temp_file.close()
                
                return await send_file(temp_file.name, mimetype='image/png')
            
            # Create trajectory visualization
            heatmap_gen = MotionHeatmapGenerator(800, 600)
            trajectory_img = heatmap_gen.generate_object_trajectory(trajectory_data)
            
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
            temp_file.write(trajectory_img)
            temp_file.close()
            
            return await send_file(temp_file.name, mimetype='image/png')
            
    except Exception as e:
        print(f"Error generating trajectory image: {e}")
        # Return a simple error image
        fig, ax = plt.subplots(figsize=(10, 8))
        ax.text(0.5, 0.5, f'Error: {str(e)}', 
               horizontalalignment='center', verticalalignment='center',
               transform=ax.transAxes, fontsize=12, color='red')
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        plt.close()
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
        temp_file.write(buffer.getvalue())
        temp_file.close()
        
        return await send_file(temp_file.name, mimetype='image/png')



@app.route('/api/motion/analyze', methods=['POST'])
async def analyze_motion():
    """Start motion analysis job"""
    data = await request.get_json()
    
    user_id = g.current_user['user_id']
    file_path = data.get('file_path')
    confidence = data.get('confidence', 0.5)
    frame_skip = data.get('frame_skip', 5)
    
    if not file_path:
        return jsonify({'error': 'file_path required'}), 400
    
    try:
        job_id = await create_motion_job(user_id, file_path, confidence=confidence, frame_skip=frame_skip)
        return jsonify({'job_id': job_id, 'status': 'created'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/motion/results/<int:job_id>')
@auth_required
async def get_motion_analysis_results(job_id):
    """Get motion analysis results"""
    user_id = g.current_user['user_id']
    
    
    try:
        results = await get_motion_results(job_id, user_id)
        if results is None:
            return jsonify({'error': 'Job not found'}), 404
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/motion/status/<int:job_id>')
@auth_required
async def get_job_status(job_id):
    """Get real-time job status"""
    if job_id in active_jobs:
        return jsonify(active_jobs[job_id])
    else:
        
        user_id = g.current_user['user_id']
    
        results = await get_motion_results(job_id, user_id)
        if results:
            return jsonify(results)
        else:
            return jsonify({'error': 'Job not found'}), 404

@app.route('/api/motion/heatmap/<int:job_id>')
@auth_required
async def get_motion_heatmap(job_id):
    """Get motion heatmap image"""
    user_id = g.current_user['user_id']
    
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT heatmap_image FROM motion_analysis ma
                JOIN jobs j ON ma.job_id = j.id
                WHERE j.id = ? AND j.user_id = ?
            """, (job_id, user_id))
            result = await cursor.fetchone()
            
            if not result:
                return jsonify({'error': 'Heatmap not found'}), 404
            
            img_data = base64.b64decode(result[0])
            
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
            temp_file.write(img_data)
            temp_file.close()
            
            return await send_file(temp_file.name, mimetype='image/png')
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/motion/trajectory-heatmap/<int:job_id>')
@auth_required
async def get_trajectory_heatmap(job_id):
    """Get trajectory heatmap image"""
   
    user_id = g.current_user['user_id']
    
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT trajectory_heatmap FROM motion_analysis ma
                JOIN jobs j ON ma.job_id = j.id
                WHERE j.id = ? AND j.user_id = ?
            """, (job_id, user_id))
            result = await cursor.fetchone()
            
            if not result:
                return jsonify({'error': 'Trajectory heatmap not found'}), 404
            
            img_data = base64.b64decode(result[0])
            
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
            temp_file.write(img_data)
            temp_file.close()
            
            return await send_file(temp_file.name, mimetype='image/png')
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    


@app.route('/api/dashboard/stats')
async def get_dashboard_api_stats():
    """API endpoint for dashboard statistics"""
    try:
        stats = await get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/jobs/recent')
async def get_recent_jobs_api():
    """API endpoint for recent jobs"""
    try:
        jobs = await get_recent_jobs(limit=10)
        return jsonify(jobs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WebSocket for real-time progress updates
@app.websocket('/ws/progress/<int:job_id>')
async def progress_websocket(job_id):
    """WebSocket endpoint for real-time progress updates"""
    try:
        while True:
            if job_id in active_jobs:
                await websocket.send(json.dumps(active_jobs[job_id]))
                
                if active_jobs[job_id]['status'] in ['completed', 'failed']:
                    break
            else:
                await websocket.send(json.dumps({'status': 'not_found'}))
                break
            
            await asyncio.sleep(2)
    except Exception as e:
        await websocket.send(json.dumps({'error': str(e)}))



# Update the create_motion_job function to use the standalone create_tables function
async def create_motion_job(user_id: int, file_path: str = None, source_url: str = None,
                          confidence: float = 0.5, frame_skip: int = 5):
    """Create a new motion tracking job"""
    
    async with aiosqlite.connect(DB_PATH) as db:
     
        cursor = await db.execute("""
            INSERT INTO jobs (user_id, source_type, confidence, frame_skip, 
                            task_name, status, credits_cost, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+24 hours'))
        """, (g.current_user['user_id'], 'file' if file_path else 'url', confidence, frame_skip, 
              'motion_tracking', 'pending', 2))
        
        job_id = cursor.lastrowid
        await db.commit()
    
    analyzer = MotionAnalyzer()
    
    if file_path:
        asyncio.create_task(analyzer.process_video_for_motion(
            file_path, job_id, user_id, confidence, frame_skip
        ))
    
    return job_id


# Update the get_motion_results function to use the standalone create_tables function
async def get_motion_results(job_id: int, user_id: int):
    """Get motion tracking results"""
    
    async with aiosqlite.connect(DB_PATH) as db:
          # Use the standalone function
        
        cursor = await db.execute("""
            SELECT status, completed_at, error_message FROM jobs 
            WHERE id = ? AND user_id = ? AND task_name = 'motion_tracking'
        """, (job_id, user_id))
        job = await cursor.fetchone()
        
        if not job:
            return None
            
        if job[0] != 'completed':
            return {'status': job[0], 'error': job[2] if len(job) > 2 else None}
        
        cursor = await db.execute("""
            SELECT id, total_objects, analysis_data, heatmap_image, trajectory_heatmap
            FROM motion_analysis WHERE job_id = ?
        """, (job_id,))
        analysis = await cursor.fetchone()
        
        if not analysis:
            return {'status': 'completed', 'error': 'No analysis data found'}
        
        cursor = await db.execute("""
            SELECT object_id, object_class, total_distance, avg_speed, max_speed, duration
            FROM object_trajectories WHERE analysis_id = ?
        """, (analysis[0],))
        trajectories = await cursor.fetchall()
        
        # Convert to proper list of dictionaries
        trajectories_list = [
            {
                'object_id': t[0], 
                'class': t[1] or 'unknown', 
                'distance': float(t[2]) if t[2] is not None else 0.0,
                'avg_speed': float(t[3]) if t[3] is not None else 0.0,
                'max_speed': float(t[4]) if t[4] is not None else 0.0,
                'duration': float(t[5]) if t[5] is not None else 0.0
            }
            for t in trajectories
        ]
        
        # Parse analysis data safely
        analysis_data = {}
        if analysis[2]:
            try:
                analysis_data = json.loads(analysis[2])
            except (json.JSONDecodeError, TypeError):
                analysis_data = {}
        
        return {
            'status': 'completed',
            'total_objects': analysis[1] or 0,
            'analysis_summary': analysis_data,
            'heatmap_image': analysis[3],
            'trajectory_heatmap': analysis[4],
            'trajectories': trajectories_list
        }


        
async def get_dashboard_stats():
    """Get dashboard statistics"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM jobs")
        total_jobs = (await cursor.fetchone())[0]
        
        cursor = await db.execute("SELECT COUNT(*) FROM jobs WHERE status = 'processing'")
        active_jobs_count = (await cursor.fetchone())[0]
        
        cursor = await db.execute("SELECT COALESCE(SUM(total_objects), 0) FROM motion_analysis")
        total_objects = (await cursor.fetchone())[0]
        
        cursor = await db.execute("SELECT COUNT(*) FROM jobs WHERE status = 'completed'")
        completed_jobs = (await cursor.fetchone())[0]
        success_rate = (completed_jobs / total_jobs * 100) if total_jobs > 0 else 0
        
        return {
            'total_jobs': total_jobs,
            'active_jobs': active_jobs_count,
            'total_objects': total_objects,
            'success_rate': round(success_rate, 1)
        }

async def get_recent_jobs(limit=5):
    """Get recent jobs"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            SELECT j.id, j.status, j.created_at, j.completed_at, 
                   COALESCE(ma.total_objects, 0) as objects
            FROM jobs j
            LEFT JOIN motion_analysis ma ON j.id = ma.job_id
            WHERE j.task_name = 'motion_tracking'
            ORDER BY j.created_at DESC
            LIMIT ?
        """, (limit,))
        results = await cursor.fetchall()
        
        jobs = []
        for row in results:
            jobs.append({
                'id': row[0],
                'status': row[1],
                'created_at': row[2],
                'completed_at': row[3],
                'objects': row[4]
            })
        
        return jobs


#####################################################################################
################################### EOF MOTION ######################################



#####################################################################################
##################### ############# TIMELINE ######################################################



# Global storage
active_timeline_jobs = {}
live_websockets = defaultdict(list)
active_trackers = {}

class ObjectProfile:
    """Individual object profile with comprehensive tracking"""
    
    def __init__(self, object_id, first_appearance, bbox, class_name, color):
        self.object_id = object_id
        self.class_name = class_name
        self.color = color
        
        # Appearance tracking
        self.appearance_segments = []  # List of {start_frame, end_frame, start_time, end_time}
        self.current_segment = {
            'start_frame': first_appearance['frame_num'],
            'end_frame': first_appearance['frame_num'],
            'start_time': first_appearance['timestamp'],
            'end_time': first_appearance['timestamp']
        }
        
        # Statistics
        self.total_duration = 0.0
        self.total_frames = 1
        self.appearance_count = 1
        
        # Visual data
        self.snapshots = []  # List of {frame_num, timestamp, bbox, image_data}
        self.keyframes = []  # Important frames for this object
        self.trajectory = []  # Movement path
        
        # Current state
        self.last_seen_frame = first_appearance['frame_num']
        self.last_seen_time = first_appearance['timestamp']
        self.last_bbox = bbox
        self.disappeared_frames = 0
        
        # Take initial snapshot
        self._take_snapshot(first_appearance['frame_num'], first_appearance['timestamp'], bbox, first_appearance.get('frame_data'))
    
    def update_appearance(self, frame_num, timestamp, bbox, frame_data=None):
        """Update object appearance with continuity check"""
        self.last_seen_frame = frame_num
        self.last_seen_time = timestamp
        self.last_bbox = bbox
        self.disappeared_frames = 0
        self.total_frames += 1
        
        # Check if this is a continuation or new appearance
        frame_gap = frame_num - self.current_segment['end_frame']
        time_gap = timestamp - self.current_segment['end_time']
        
        if frame_gap <= 30 and time_gap <= 2.0:  # Continuation threshold
            # Continue current segment
            self.current_segment['end_frame'] = frame_num
            self.current_segment['end_time'] = timestamp
        else:
            # End current segment and start new one
            self._finalize_current_segment()
            self.current_segment = {
                'start_frame': frame_num,
                'end_frame': frame_num,
                'start_time': timestamp,
                'end_time': timestamp
            }
            self.appearance_count += 1
        
        # Take periodic snapshots (every 30 frames or 2 seconds)
        if len(self.snapshots) == 0 or frame_num - self.snapshots[-1]['frame_num'] >= 30:
            self._take_snapshot(frame_num, timestamp, bbox, frame_data)
        
        # Update trajectory
        centroid = self._get_centroid(bbox)
        self.trajectory.append({
            'frame_num': frame_num,
            'timestamp': timestamp,
            'position': centroid,
            'bbox': bbox
        })
    
    def mark_disappeared(self, frame_num):
        """Mark object as disappeared"""
        self.disappeared_frames += 1
        
        # If disappeared for too long, finalize current segment
        if self.disappeared_frames >= 30:  # 1 second at 30fps
            self._finalize_current_segment()
    
    def _finalize_current_segment(self):
        """Finalize current appearance segment"""
        if (self.current_segment['end_frame'] > self.current_segment['start_frame'] or
            self.current_segment['end_time'] > self.current_segment['start_time']):
            
            segment_duration = (self.current_segment['end_time'] - 
                              self.current_segment['start_time'])
            self.total_duration += segment_duration
            
            self.appearance_segments.append(self.current_segment.copy())
    
    def _take_snapshot(self, frame_num, timestamp, bbox, frame_data=None):
        """Take snapshot of object"""
        if frame_data is not None:
            # Extract object from frame using bbox
            x, y, w, h = bbox
            x, y, w, h = int(x), int(y), int(w), int(h)
            
            # Ensure coordinates are within frame bounds
            if (0 <= y < frame_data.shape[0] and 0 <= x < frame_data.shape[1] and
                y + h <= frame_data.shape[0] and x + w <= frame_data.shape[1]):
                
                object_crop = frame_data[y:y+h, x:x+w]
                
                # Encode as base64 for storage
                _, buffer = cv2.imencode('.jpg', object_crop, [cv2.IMWRITE_JPEG_QUALITY, 70])
                image_data = base64.b64encode(buffer).decode('utf-8')
                
                snapshot = {
                    'frame_num': frame_num,
                    'timestamp': timestamp,
                    'bbox': bbox,
                    'image_data': image_data,
                    'position': self._get_centroid(bbox)
                }
                
                self.snapshots.append(snapshot)
                
                # Keep only last 5 snapshots to save space
                if len(self.snapshots) > 5:
                    self.snapshots.pop(0)
    
    def _get_centroid(self, bbox):
        """Calculate centroid from bounding box"""
        x, y, w, h = bbox
        return (int(x + w/2), int(y + h/2))
    
    def get_profile_summary(self):
        """Get comprehensive object profile"""
        # Finalize any active segment
        if (self.current_segment['end_frame'] >= self.current_segment['start_frame'] and
            self.current_segment['end_time'] >= self.current_segment['start_time']):
            self._finalize_current_segment()
        
        return {
            'object_id': self.object_id,
            'class_name': self.class_name,
            'color': self.color,
            'total_duration': self.total_duration,
            'total_frames': self.total_frames,
            'appearance_count': self.appearance_count,
            'last_seen_frame': self.last_seen_frame,
            'last_seen_time': self.last_seen_time,
            'appearance_segments': self.appearance_segments,
            'snapshots_count': len(self.snapshots),
            'trajectory_length': len(self.trajectory),
            'snapshots': self.snapshots,
            'keyframes': [seg['start_frame'] for seg in self.appearance_segments[:3]],  # First 3 appearance starts
            'trajectory': self.trajectory[-20:]  # Last 20 trajectory points
        }

class ObjectTimelineTracker:
    """Main tracker managing all object profiles"""
    
    def __init__(self):
        self.object_profiles = {}  # object_id -> ObjectProfile
        self.next_object_id = 1
        self.color_palette = self._generate_color_palette()
        self.frame_count = 0
        self.current_time = 0.0
        
    def _generate_color_palette(self):
        """Generate distinct colors for object tracking"""
        colors = [
            '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7',
            '#DDA0DD', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E9',
            '#F8C471', '#82E0AA', '#F1948A', '#85C1E9', '#D7BDE2',
            '#F9E79F', '#ABEBC6', '#AED6F1', '#FAD7A0', '#A2D9CE'
        ]
        return deque(colors * 3)  # Repeat to ensure enough colors
    
    def process_frame(self, frame, detections, frame_num, timestamp):
        """Process frame and update all object profiles"""
        self.frame_count = frame_num
        self.current_time = timestamp
        
        # Update existing objects
        updated_objects = set()
        
        for obj_id, profile in list(self.object_profiles.items()):
            # Find best matching detection for this object
            best_match = None
            best_distance = float('inf')
            
            for i, det in enumerate(detections):
                if i in updated_objects:
                    continue
                
                # Calculate distance between object and detection
                obj_center = profile._get_centroid(profile.last_bbox)
                det_center = profile._get_centroid(det['bbox'])
                distance = euclidean(obj_center, det_center)
                
                # Also check class similarity
                class_similarity = 1.0 if profile.class_name == det['class_name'] else 0.3
                adjusted_distance = distance * (2.0 - class_similarity)
                
                if adjusted_distance < 150 and adjusted_distance < best_distance:
                    best_match = (i, det)
                    best_distance = adjusted_distance
            
            if best_match is not None:
                # Update existing object
                det_idx, detection = best_match
                profile.update_appearance(frame_num, timestamp, detection['bbox'], frame)
                updated_objects.add(det_idx)
            else:
                # Mark as disappeared
                profile.mark_disappeared(frame_num)
                # Remove if disappeared for too long
                if profile.disappeared_frames > 90:  # 3 seconds at 30fps
                    del self.object_profiles[obj_id]
        
        # Create new profiles for unmatched detections
        for i, detection in enumerate(detections):
            if i not in updated_objects:
                object_id = f"obj_{self.next_object_id:04d}"
                color = self.color_palette[0]
                self.color_palette.rotate(-1)
                
                profile = ObjectProfile(
                    object_id=object_id,
                    first_appearance={
                        'frame_num': frame_num,
                        'timestamp': timestamp,
                        'frame_data': frame
                    },
                    bbox=detection['bbox'],
                    class_name=detection['class_name'],
                    color=color
                )
                
                self.object_profiles[object_id] = profile
                self.next_object_id += 1
        
        return self._create_visualization_frame(frame)
    
    def _create_visualization_frame(self, frame):
        """Create visualization frame with bounding boxes and info"""
        viz_frame = frame.copy()
        
        for obj_id, profile in self.object_profiles.items():
            if profile.disappeared_frames > 0:
                continue  # Skip disappeared objects
            
            # Draw bounding box
            x, y, w, h = [int(coord) for coord in profile.last_bbox]
            color = self._hex_to_bgr(profile.color)
            
            # Draw main bounding box
            cv2.rectangle(viz_frame, (x, y), (x + w, y + h), color, 3)
            
            # Draw object ID and info
            info_text = f"{obj_id} ({profile.class_name})"
            duration_text = f"Time: {profile.total_duration + (self.current_time - profile.current_segment['start_time']):.1f}s"
            appearances_text = f"Appearances: {profile.appearance_count}"
            
            # Background for text
            text_y = y - 10 if y - 10 > 20 else y + h + 60
            cv2.rectangle(viz_frame, (x, text_y - 60), (x + 200, text_y + 10), (0, 0, 0), -1)
            cv2.rectangle(viz_frame, (x, text_y - 60), (x + 200, text_y + 10), color, 2)
            
            # Draw text
            cv2.putText(viz_frame, info_text, (x + 5, text_y - 40),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
            cv2.putText(viz_frame, duration_text, (x + 5, text_y - 20),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1)
            cv2.putText(viz_frame, appearances_text, (x + 5, text_y),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1)
            
            # Draw trajectory
            if len(profile.trajectory) > 1:
                points = []
                for point in profile.trajectory[-20:]:  # Last 20 points
                    pos = point['position']
                    points.append(pos)
                
                if len(points) >= 2:
                    points = np.array(points, dtype=np.int32)
                    cv2.polylines(viz_frame, [points], False, color, 2)
        
        # Add frame info
        info_text = f"Frame: {self.frame_count} | Objects: {len([p for p in self.object_profiles.values() if p.disappeared_frames == 0])}"
        cv2.putText(viz_frame, info_text, (10, 30),
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 3)
        cv2.putText(viz_frame, info_text, (10, 30),
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
        
        return viz_frame
    
    def _hex_to_bgr(self, hex_color):
        """Convert hex color to BGR for OpenCV"""
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        return (rgb[2], rgb[1], rgb[0])  # BGR format
    
    def get_all_profiles(self):
        """Get all object profiles"""
        return {obj_id: profile.get_profile_summary() 
                for obj_id, profile in self.object_profiles.items()}
    
    def get_active_objects(self):
        """Get currently active objects"""
        return {obj_id: profile for obj_id, profile in self.object_profiles.items() 
                if profile.disappeared_frames == 0}

class EnhancedObjectDetector:
    """Improved object detector with better classification"""
    
    def __init__(self):
        self.back_sub = cv2.createBackgroundSubtractorMOG2(history=500, varThreshold=16, detectShadows=True)
        self.kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
        
    def detect_objects(self, frame, timestamp):
        """Detect objects in frame with enhanced classification"""
        try:
            # Resize for processing efficiency
            height, width = frame.shape[:2]
            if width > 800:
                scale = 800 / width
                new_width = 800
                new_height = int(height * scale)
                frame_resized = cv2.resize(frame, (new_width, new_height))
            else:
                frame_resized = frame
                new_width, new_height = width, height
            
            # Background subtraction
            fg_mask = self.back_sub.apply(frame_resized)
            
            # Noise removal and enhancement
            fg_mask = cv2.morphologyEx(fg_mask, cv2.MORPH_OPEN, self.kernel)
            fg_mask = cv2.dilate(fg_mask, self.kernel, iterations=2)
            
            # Find contours
            contours, _ = cv2.findContours(fg_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            detections = []
            for contour in contours:
                area = cv2.contourArea(contour)
                if 500 < area < 50000:  # Adjusted range
                    x, y, w, h = cv2.boundingRect(contour)
                    
                    # Scale coordinates back to original frame size
                    if width != new_width:
                        scale_x = width / new_width
                        scale_y = height / new_height
                        x, y, w, h = int(x * scale_x), int(y * scale_y), int(w * scale_x), int(h * scale_y)
                    
                    # Enhanced classification
                    class_name, confidence = self._classify_object(w, h, area, contour)
                    
                    detections.append({
                        'bbox': (x, y, w, h),
                        'class_name': class_name,
                        'confidence': confidence,
                        'timestamp': timestamp,
                        'area': area
                    })
            
            return detections
            
        except Exception as e:
            print(f"Detection error: {e}")
            return []
    
    def _classify_object(self, w, h, area, contour):
        """Enhanced object classification"""
        aspect_ratio = w / h if h > 0 else 1.0
        
        # Calculate additional features
        perimeter = cv2.arcLength(contour, True)
        circularity = 4 * np.pi * area / (perimeter * perimeter) if perimeter > 0 else 0
        
        if aspect_ratio > 2.5:
            # Very wide - likely vehicle
            return 'vehicle', min(area / 15000, 1.0)
        elif aspect_ratio > 1.8:
            # Wide object
            if area > 8000:
                return 'vehicle', min(area / 20000, 1.0)
            else:
                return 'small_object', min(area / 5000, 1.0)
        elif 0.7 < aspect_ratio < 1.8:
            # Human-like aspect ratio
            if area > 5000:
                return 'person', min(area / 15000, 1.0)
            elif area > 1500:
                return 'person', min(area / 8000, 0.8)
            else:
                return 'small_object', min(area / 3000, 1.0)
        else:
            # Tall or irregular
            if area > 3000:
                return 'person', min(area / 10000, 0.7)
            else:
                return 'small_object', min(area / 2000, 1.0)

@app.route('/Timeline')
@auth_required
async def object_timeline_dashboard():
    """Main dashboard for object timeline profiling"""
    return await render_template("Timeline-Profiling-Concept.html" , user = g.current_user )

@app.websocket('/ws/object-timeline')
async def object_timeline_websocket():
    """WebSocket for object timeline profiling"""
    await websocket.accept()
    print("Object Timeline WebSocket connected")
    
    current_video_id = None
    tracker = None
    detector = None
    video_capture = None
    
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=300.0)
                
                if data.get('type') == 'start_analysis' and data.get('video_id'):
                    current_video_id = data['video_id']
                    await start_object_analysis(current_video_id, websocket)
                    
                elif data.get('type') == 'stop_analysis':
                    await stop_object_analysis()
                    await websocket.send_json({'type': 'analysis_stopped'})
                    
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({'type': 'ping'})
                except:
                    break
            except Exception as e:
                print(f"WebSocket error: {e}")
                break
                
    except Exception as e:
        print(f"WebSocket connection error: {e}")
    finally:
        await stop_object_analysis()
        print("Object Timeline WebSocket disconnected")

async def start_object_analysis(video_id, websocket):
    """Start object-centric timeline analysis"""
    try:
        # Get video path
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("SELECT file_path FROM timeline_videos WHERE id = ?", (video_id,))
            video = await cursor.fetchone()
            if not video:
                await websocket.send_json({'type': 'error', 'message': 'Video not found'})
                return
        
        video_path = video[0]
        
        # Initialize components
        cap = cv2.VideoCapture(str(video_path))
        if not cap.isOpened():
            await websocket.send_json({'type': 'error', 'message': 'Cannot open video'})
            return
        
        tracker = ObjectTimelineTracker()
        detector = EnhancedObjectDetector()
        
        await websocket.send_json({'type': 'analysis_started'})
        
        fps = cap.get(cv2.CAP_PROP_FPS) or 30
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        frame_interval = 1.0 / fps
        
        frame_count = 0
        last_profile_update = 0
        start_time = time.time()
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            current_time = frame_count / fps
            
            # Detect objects
            detections = detector.detect_objects(frame, current_time)
            
            # Process frame with tracker
            viz_frame = tracker.process_frame(frame, detections, frame_count, current_time)
            
            # Encode frame for streaming
            _, buffer = cv2.imencode('.jpg', viz_frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
            frame_data = base64.b64encode(buffer).decode('utf-8')
            
            # Send frame update
            await websocket.send_json({
                'type': 'video_frame',
                'frame_data': frame_data,
                'frame_number': frame_count,
                'timestamp': current_time,
                'active_objects': len(tracker.get_active_objects()),
                'total_objects': len(tracker.object_profiles),
                'progress': (frame_count / total_frames) * 100 if total_frames > 0 else 0
            })
            
            # Send profile updates every 30 frames
            if frame_count - last_profile_update >= 30:
                profiles = tracker.get_all_profiles()
                await websocket.send_json({
                    'type': 'object_profiles',
                    'profiles': profiles
                })
                last_profile_update = frame_count
            
            frame_count += 1
            
            # Maintain frame rate
            elapsed = time.time() - start_time
            expected_time = frame_count * frame_interval
            if elapsed < expected_time:
                await asyncio.sleep(expected_time - elapsed)
            
        # Final analysis completion
        cap.release()
        
        # Save final profiles to database
        final_profiles = tracker.get_all_profiles()
        await save_object_profiles(video_id, final_profiles)
        
        await websocket.send_json({
            'type': 'analysis_completed',
            'profiles': final_profiles,
            'total_objects': len(final_profiles),
            'total_frames': frame_count,
            'total_duration': frame_count / fps
        })
        
    except Exception as e:
        print(f"Object analysis error: {e}")
        await websocket.send_json({'type': 'error', 'message': str(e)})

async def save_object_profiles(video_id, profiles):
    """Save object profiles to database"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            # Create object profiles table if not exists
            await db.execute("""
                CREATE TABLE IF NOT EXISTS object_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    video_id INTEGER NOT NULL,
                    object_id TEXT NOT NULL,
                    class_name TEXT NOT NULL,
                    color TEXT NOT NULL,
                    total_duration REAL NOT NULL,
                    total_frames INTEGER NOT NULL,
                    appearance_count INTEGER NOT NULL,
                    profile_data TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (video_id) REFERENCES timeline_videos (id)
                );
            """)
            
            # Save each profile
            for obj_id, profile in profiles.items():
                await db.execute("""
                    INSERT INTO object_profiles 
                    (video_id, object_id, class_name, color, total_duration, total_frames, appearance_count, profile_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    video_id, obj_id, profile['class_name'], profile['color'],
                    profile['total_duration'], profile['total_frames'],
                    profile['appearance_count'], json.dumps(profile, default=str)
                ))
            
            await db.commit()
            print(f"Saved {len(profiles)} object profiles to database")
            
    except Exception as e:
        print(f"Error saving object profiles: {e}")

async def stop_object_analysis():
    """Stop object analysis"""
    # Cleanup resources
    pass

@app.route('/api/object-timeline/upload', methods=['POST'])
@auth_required
async def upload_object_timeline_video():
    """Upload video for object timeline analysis"""
    try:
        if 'video' not in (await request.files):
            return jsonify({'error': 'No video file provided'}), 400
        
        video_file = (await request.files)['video']
        if video_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not video_file.filename.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.webm')):
            return jsonify({'error': 'Please upload a video file (mp4, avi, mov, mkv, webm)'}), 400
        
        file_hash = hashlib.md5(f"{time.time()}_{video_file.filename}".encode()).hexdigest()[:8]
        filename = f"object_timeline_{file_hash}_{video_file.filename}"
        file_path =UPLOAD_FOLDER / filename
        
        UPLOAD_FOLDER.mkdir(exist_ok=True)
        await video_file.save(file_path)
        
        # Verify file was saved
        if not file_path.exists():
            return jsonify({'error': 'File save failed'}), 500
        
        user_id = 1
        
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                INSERT INTO timeline_videos 
                (user_id, filename, file_path, file_size, analysis_status, upload_time)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            """, (user_id, filename, str(file_path), 
                  file_path.stat().st_size, 'pending'))
            
            await db.commit()
            
            # Get the last inserted ID properly
            cursor = await db.execute("SELECT last_insert_rowid()")
            result = await cursor.fetchone()
            video_id = result[0] if result else None
        
        if not video_id:
            return jsonify({'error': 'Failed to get video ID'}), 500
        
        return jsonify({
            'video_id': video_id,
            'filename': filename,
            'status': 'uploaded',
            'message': 'Video uploaded successfully'
        })
        
    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/object-timeline/videos')
@auth_required
async def get_uploaded_videos():
    

    """Get list of uploaded videos"""
    try:
        user_id = 1
        
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT id, filename, file_path, upload_time, analysis_status 
                FROM timeline_videos 
                WHERE user_id = ? 
                ORDER BY upload_time DESC
            """, (user_id,))
            
            videos = await cursor.fetchall()
            
            result = []
            for video in videos:
                result.append({
                    'id': video[0],
                    'filename': video[1],
                    'file_path': video[2],
                    'upload_time': video[3],
                    'analysis_status': video[4]
                })
            
            return jsonify({'videos': result})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/object-timeline/profiles/<int:video_id>')
@auth_required
async def get_object_profiles(video_id):
    """Get object profiles for a specific video"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT object_id, class_name, color, total_duration, total_frames, 
                       appearance_count, profile_data
                FROM object_profiles 
                WHERE video_id = ?
            """, (video_id,))
            
            profiles_data = await cursor.fetchall()
            
            profiles = {}
            for profile in profiles_data:
                profile_dict = {
                    'object_id': profile[0],
                    'class_name': profile[1],
                    'color': profile[2],
                    'total_duration': profile[3],
                    'total_frames': profile[4],
                    'appearance_count': profile[5],
                    'profile_data': json.loads(profile[6]) if profile[6] else {}
                }
                profiles[profile[0]] = profile_dict
            
            return jsonify({'profiles': profiles})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

###################################################################
########################## EOF TIMELINE ##########################



############################# START OF FRAME EXTRACTOR #######################
###################################################################################

# -------------------------
# Object Detection Core
# -------------------------
class ObjectDetector:
    def __init__(self, model_name: str = "yolov5s", confidence: float = 0.5):
        self.confidence = confidence
        self.model = None
        self.model_names = None
        
        # Attempt to load torch model if available.
        try:
            import importlib
            torch = importlib.import_module("torch")
            self.model = torch.hub.load("ultralytics/yolov5", model_name, pretrained=True)
            self.model.eval()
            self.model_names = getattr(self.model, "names", None)
            print("[detector] YOLO model loaded")
        except Exception as e:
            print(f"[detector] YOLO load failed ({e}). Running in no-op mode.")

    def detect_sync(self, frame, confidence: Optional[float] = None):
        """
        Synchronous detection wrapper intended to run in a thread executor.
        Returns list of dicts with keys: bbox, confidence, class_id, class_name
        """
        if self.model is None:
            return []  # no-op if model missing
        
        try:
            results = self.model(frame)
            detections = []
            arr = results.xyxy[0].cpu().numpy()
            for *box, conf, cls in arr:
                if conf >= (confidence if confidence is not None else self.confidence):
                    x1, y1, x2, y2 = map(int, box)
                    cid = int(cls)
                    cname = self.model_names[cid] if self.model_names and cid < len(self.model_names) else str(cid)
                    detections.append({
                        "bbox": [x1, y1, x2, y2],
                        "confidence": float(conf),
                        "class_id": cid,
                        "class_name": cname
                    })
            return detections
        except Exception as e:
            print("[detector] detection error:", e)
            return []

    async def process_video(self, job_id: int, video_path: str, object_filter: str, confidence: float, frame_skip: int):
        """
        Core processing loop with enhanced tracking and grouping.
        """
        start_time = datetime.utcnow()
        current_pid = os.getpid()
        
        await db_update("jobs", {
            "status": "running", 
            "started_at": start_time.isoformat(),
            "process_pid": current_pid,
            "task_name": "extraction"
        }, {"id": job_id})
        
        await log(job_id, "info", f"Job {job_id} started (PID: {current_pid}, filter={object_filter} conf={confidence} step={frame_skip})")
        
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            await log(job_id, "error", f"Cannot open video: {video_path}")
            await db_update("jobs", {"status": "failed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            return
        
        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        frame_number = 0
        
        try:
            while True:
                # Check for stop flag in DB to support graceful stops
                job_row = await db_query_one("SELECT status FROM jobs WHERE id=?", (job_id,))
                if job_row and job_row.get("status") == "stopped":
                    await log(job_id, "info", "Job requested to stop — exiting")
                    break
                
                ret, frame = cap.read()
                if not ret:
                    break
                
                if frame_number % frame_skip != 0:
                    frame_number += 1
                    continue
                
                timestamp = round(frame_number / fps, 2)
                
                # Run sync detection in thread pool to avoid blocking event loop
                loop = asyncio.get_running_loop()
                detections = await loop.run_in_executor(None, self.detect_sync, frame, confidence)
                
                # Filter detections
                filtered = []
                for det in detections:
                    cname = det["class_name"]
                    if object_filter == "all" or (object_filter == "people" and cname == "person") or (cname == object_filter):
                        filtered.append(det)
                
                # Save detections & emit per-detection logs
                for det in filtered:
                    x1, y1, x2, y2 = det["bbox"]
                    img_b64 = None
                    img_path = None
                    
                    # Generate detection group for similar detections
                    detection_group = generate_detection_group(det["class_name"], det["bbox"])
                    
                    try:
                        cropped = frame[y1:y2, x1:x2]
                        if cropped.size > 0:
                            rgb = cv2.cvtColor(cropped, cv2.COLOR_BGR2RGB)
                            pil = Image.fromarray(rgb)
                            buf = io.BytesIO()
                            pil.save(buf, format="PNG")
                            img_b64 = base64.b64encode(buf.getvalue()).decode()
                            
                            # Save detection image to disk
                            job_folder = os.path.join(DETECTIONS_DIR, f"job_{job_id}")
                            os.makedirs(job_folder, exist_ok=True)
                            img_filename = f"detection_{frame_number}_{det['class_name']}_{det['confidence']:.2f}.png"
                            img_path = os.path.join(job_folder, img_filename)
                            pil.save(img_path)
                            
                    except Exception as e:
                        img_b64 = None
                        img_path = None
                        await log(job_id, "warn", f"Crop failed for frame {frame_number}: {e}")
                    
                    # Insert detection with image path and grouping
                    detection_id = await db_insert("detections", {
                        "job_id": job_id,
                        "user_id" : g.current_user['user_id'],
                        "frame_number": frame_number,
                        "timestamp": timestamp,
                        "class_name": det["class_name"],
                        "class_id": det["class_id"],
                        "confidence": det["confidence"],
                        "bbox": json.dumps(det["bbox"]),
                        "image_base64": img_b64,
                        "image_path": img_path,
                        "detection_group": detection_group ,
                        "created_at" : datetime.utcnow().isoformat()
                    })
                    
                    # Enhanced real-time notification with detection details
                    payload = json.dumps({
                        "type": "detection",
                        "job_id": job_id,
                        "detection_id": detection_id,
                        "frame_number": frame_number,
                        "timestamp": timestamp,
                        "class_name": det["class_name"],
                        "class_id": det["class_id"],
                        "confidence": det["confidence"],
                        "bbox": det["bbox"],
                        "image_base64": img_b64,
                        "image_path": img_path,
                        "detection_group": detection_group
                    })
                    for ws in list(job_ws_clients.get(job_id, [])):
                        try:
                            asyncio.create_task(ws.send(payload))
                        except Exception:
                            pass
                
                progress = round((frame_number / total_frames) * 100, 2) if total_frames > 0 else 0
                if frame_number % (frame_skip * 5) == 0:  # Less frequent logging
                    await log(job_id, "info", f"Frame {frame_number} processed, detections={len(filtered)}, progress={progress}%")
                
                # send progress message to clients
                progress_payload = json.dumps({"type": "progress", "job_id": job_id, "frame": frame_number, "progress": progress})
                for ws in list(job_ws_clients.get(job_id, [])):
                    try:
                        asyncio.create_task(ws.send(progress_payload))
                    except Exception:
                        pass
                
                frame_number += 1
            
            # Calculate time taken
            end_time = datetime.utcnow()
            time_taken = (end_time - start_time).total_seconds()
            
            # Completed normally
            await db_update("jobs", {
                "status": "completed", 
                "completed_at": end_time.isoformat(),
                "time_taken": time_taken
            }, {"id": job_id})
            await log(job_id, "info", f"Job completed in {time_taken:.2f} seconds")
            
            # notify clients
            done_payload = json.dumps({"type": "done", "job_id": job_id, "time_taken": time_taken})
            for ws in list(job_ws_clients.get(job_id, [])):
                try:
                    asyncio.create_task(ws.send(done_payload))
                except Exception:
                    pass
        
        except asyncio.CancelledError:
            # Task canceled explicitly
            time_taken = (datetime.utcnow() - start_time).total_seconds()
            await db_update("jobs", {
                "status": "stopped", 
                "completed_at": datetime.utcnow().isoformat(),
                "time_taken": time_taken
            }, {"id": job_id})
            await log(job_id, "info", f"Job cancelled after {time_taken:.2f} seconds")
        except Exception as e:
            time_taken = (datetime.utcnow() - start_time).total_seconds()
            await db_update("jobs", {
                "status": "failed", 
                "completed_at": datetime.utcnow().isoformat(),
                "time_taken": time_taken
            }, {"id": job_id})
            await log(job_id, "error", f"Processing error after {time_taken:.2f} seconds: {e}")
        finally:
            cap.release()
            # cleanup job_tasks entry if present
            job_tasks.pop(job_id, None)

detector = ObjectDetector()

# -------------------------
# URL Video Stream Processor
# -------------------------
class URLVideoProcessor:
    def __init__(self):
        self.ytdlp_available = False
        try:
            # Check if yt-dlp is available
            result = subprocess.run(['yt-dlp', '--version'], capture_output=True, timeout=10)
            if result.returncode == 0:
                self.ytdlp_available = True
                print("[URLProcessor] yt-dlp found and available")
        except Exception as e:
            print(f"[URLProcessor] yt-dlp not available: {e}")
            print("[URLProcessor] Install with: pip install yt-dlp")

    def get_video_stream_url(self, url: str) -> Optional[str]:
        """
        Get direct video stream URL using yt-dlp without downloading
        Returns the best video stream URL for direct opencv access
        """
        if not self.ytdlp_available:
            # Fallback: try to use URL directly (works for direct video links)
            return url
        
        try:
            # Get video info without downloading
            cmd = [
                'yt-dlp', 
                '-f', 'best[height<=720]',  # Prefer 720p or lower for processing speed
                '--get-url',
                '--no-playlist',
                url
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                stream_url = result.stdout.strip()
                return stream_url
            else:
                print(f"[URLProcessor] yt-dlp failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"[URLProcessor] yt-dlp timeout for URL: {url}")
            return None
        except Exception as e:
            print(f"[URLProcessor] Error getting stream URL: {e}")
            return None

    async def process_url_video(self, job_id: int, source_url: str, object_filter: str, confidence: float, frame_skip: int):
        """
        Process video directly from URL without downloading to disk
        Uses OpenCV to read from stream URL and processes frames in real-time
        """
        await db_update("jobs", {"status": "running", "started_at": datetime.utcnow().isoformat()}, {"id": job_id})
        await log(job_id, "info", f"URL Job {job_id} started - getting stream URL")
        
        # Get stream URL
        stream_url = self.get_video_stream_url(source_url)
        if not stream_url:
            await log(job_id, "error", f"Could not get video stream from URL: {source_url}")
            await db_update("jobs", {"status": "failed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            return
        
        await log(job_id, "info", f"Got stream URL, starting video processing")
        
        # Open video stream with OpenCV
        cap = cv2.VideoCapture(stream_url)
        if not cap.isOpened():
            await log(job_id, "error", f"Cannot open video stream: {stream_url}")
            await db_update("jobs", {"status": "failed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            return
        
        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        frame_number = 0
        
        await log(job_id, "info", f"Stream opened successfully (fps={fps}, total_frames={total_frames})")
        
        try:
            while True:
                # Check for stop flag
                job_row = await db_query_one("SELECT status FROM jobs WHERE id=?", (job_id,))
                if job_row and job_row.get("status") == "stopped":
                    await log(job_id, "info", "URL job requested to stop — exiting")
                    break
                
                ret, frame = cap.read()
                if not ret:
                    await log(job_id, "info", "End of video stream reached")
                    break
                
                if frame_number % frame_skip != 0:
                    frame_number += 1
                    continue
                
                timestamp = round(frame_number / fps, 2)
                
                # Run detection using the same detector instance
                loop = asyncio.get_running_loop()
                detections = await loop.run_in_executor(None, detector.detect_sync, frame, confidence)
                
                # Filter detections
                filtered = []
                for det in detections:
                    cname = det["class_name"]
                    if object_filter == "all" or (object_filter == "people" and cname == "person") or (cname == object_filter):
                        filtered.append(det)
                
                # Save detections - same as file processing but with URL source
                for det in filtered:
                    x1, y1, x2, y2 = det["bbox"]
                    img_b64 = None
                    img_path = None
                    
                    try:
                        cropped = frame[y1:y2, x1:x2]
                        if cropped.size > 0:
                            rgb = cv2.cvtColor(cropped, cv2.COLOR_BGR2RGB)
                            pil = Image.fromarray(rgb)
                            buf = io.BytesIO()
                            pil.save(buf, format="PNG")
                            img_b64 = base64.b64encode(buf.getvalue()).decode()
                            
                            # Save detection image to disk
                            job_folder = os.path.join(DETECTIONS_DIR, f"job_{job_id}")
                            os.makedirs(job_folder, exist_ok=True)
                            img_filename = f"detection_{frame_number}_{det['class_name']}_{det['confidence']:.2f}.png"
                            img_path = os.path.join(job_folder, img_filename)
                            pil.save(img_path)
                            
                    except Exception as e:
                        img_b64 = None
                        img_path = None
                        await log(job_id, "warn", f"Crop failed for frame {frame_number}: {e}")
                    
                    # Insert detection with image path
                    detection_id = await db_insert("detections", {
                        "job_id": job_id,
                        "frame_number": frame_number,
                        "timestamp": timestamp,
                        "class_name": det["class_name"],
                        "class_id": det["class_id"],
                        "confidence": det["confidence"],
                        "bbox": json.dumps(det["bbox"]),
                        "image_base64": img_b64,
                        "image_path": img_path
                    })
                    
                    # Enhanced real-time notification
                    payload = json.dumps({
                        "type": "detection",
                        "job_id": job_id,
                        "detection_id": detection_id,
                        "frame_number": frame_number,
                        "timestamp": timestamp,
                        "class_name": det["class_name"],
                        "class_id": det["class_id"],
                        "confidence": det["confidence"],
                        "bbox": det["bbox"],
                        "image_base64": img_b64,
                        "image_path": img_path
                    })
                    for ws in list(job_ws_clients.get(job_id, [])):
                        try:
                            asyncio.create_task(ws.send(payload))
                        except Exception:
                            pass
                
                # Progress reporting
                progress = round((frame_number / total_frames) * 100, 2) if total_frames > 0 else 0
                if frame_number % (frame_skip * 10) == 0:  # Less frequent logging for streams
                    await log(job_id, "info", f"Frame {frame_number} processed, detections={len(filtered)}, progress={progress}%")
                
                # Progress WebSocket update
                progress_payload = json.dumps({"type": "progress", "job_id": job_id, "frame": frame_number, "progress": progress})
                for ws in list(job_ws_clients.get(job_id, [])):
                    try:
                        asyncio.create_task(ws.send(progress_payload))
                    except Exception:
                        pass
                
                frame_number += 1
                
                # Prevent runaway processing for very long streams
                if frame_number > 50000:  # ~33 minutes at 25fps
                    await log(job_id, "warn", "Reached frame limit, stopping processing")
                    break
            
            # Completed successfully
            await db_update("jobs", {"status": "completed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            await log(job_id, "info", "URL job completed successfully")
            
            # Notify WebSocket clients
            done_payload = json.dumps({"type": "done", "job_id": job_id})
            for ws in list(job_ws_clients.get(job_id, [])):
                try:
                    asyncio.create_task(ws.send(done_payload))
                except Exception:
                    pass
        
        except asyncio.CancelledError:
            await db_update("jobs", {"status": "stopped", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            await log(job_id, "info", "URL job cancelled")
        except Exception as e:
            await db_update("jobs", {"status": "failed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            await log(job_id, "error", f"URL processing error: {e}")
        finally:
            cap.release()
            job_tasks.pop(job_id, None)

# Initialize processors
url_processor = URLVideoProcessor()

# -------------------------
# Background cleanup task
# -------------------------
async def cleanup_expired_task():
    """
    Background task that runs every hour to cleanup expired URL job data
    """
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour
            now = datetime.utcnow().isoformat()
            
            # Find and cleanup expired URL jobs
            expired_jobs = await db_query(
                "SELECT id FROM jobs WHERE source_type='url' AND expires_at < ? AND status IN ('completed', 'failed', 'stopped')", 
                (now,)
            )
            
            cleanup_count = 0
            for job in expired_jobs:
                job_id = job["id"]
                try:
                    # Delete detection images folder
                    job_folder = os.path.join(DETECTIONS_DIR, f"job_{job_id}")
                    if os.path.exists(job_folder):
                        shutil.rmtree(job_folder)
                    
                    # Delete detections, logs, and job record
                    async with aiosqlite.connect(DB_PATH) as db:
                        await db.execute("DELETE FROM detections WHERE job_id=?", (job_id,))
                        await db.execute("DELETE FROM logs WHERE job_id=?", (job_id,))
                        await db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
                        await db.commit()
                    cleanup_count += 1
                except Exception as e:
                    print(f"[cleanup] Error cleaning up job {job_id}: {e}")
            
            if cleanup_count > 0:
                print(f"[cleanup] Removed {cleanup_count} expired URL jobs")
                
        except Exception as e:
            print(f"[cleanup] Background cleanup error: {e}")


@app.route("/start_url_job", methods=["POST"])
@auth_required
async def start_url_job():
    """
    Starts background detection for a video URL (YouTube, Instagram, TikTok, etc.)
    JSON body:
      { "url": str, "object_filter": "all"|"people"|<class>, "confidence": float, "frame_skip": int }
    """
    payload = await request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Expected JSON body"}), 400
    
    url = payload.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    # Basic URL validation
    if not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"error": "Invalid URL format"}), 400

    object_filter = payload.get("object_filter", "all")
    confidence = float(payload.get("confidence", 0.5))
    frame_skip = int(payload.get("frame_skip", 10))
    
    # Calculate expiry time
    expires_at = (datetime.utcnow() + timedelta(hours=URL_JOB_EXPIRY_HOURS)).isoformat()
    
    # Insert URL job row (no upload_id needed)
    job_id = await db_insert("jobs", {
        
        "source_url": url,
        "source_type": "url",
        "object_filter": object_filter,
        "confidence": confidence,
        "frame_skip": frame_skip,
        "status": "pending",
        "expires_at": expires_at
    })
    
    # Start background URL processing task
    task = asyncio.create_task(url_processor.process_url_video(job_id, url, object_filter, confidence, frame_skip))
    job_tasks[job_id] = task
    
    await log(job_id, "info", f"URL Job {job_id} queued for processing (expires: {expires_at})")
    return jsonify({"job_id": job_id, "expires_at": expires_at, "expiry_hours": URL_JOB_EXPIRY_HOURS})

@app.route("/cleanup_expired", methods=["POST"])
@auth_required
async def cleanup_expired_jobs():
    """
    Manual cleanup of expired URL job data (normally runs automatically)
    """
    try:
        now = datetime.utcnow().isoformat()
        
        # Find expired jobs
        expired_jobs = await db_query(
            "SELECT id FROM jobs WHERE source_type='url' AND expires_at < ? AND status IN ('completed', 'failed', 'stopped')", 
            (now,)
        )
        
        cleanup_count = 0
        for job in expired_jobs:
            job_id = job["id"]
            
            # Delete detection images folder
            job_folder = os.path.join(DETECTIONS_DIR, f"job_{job_id}")
            if os.path.exists(job_folder):
                shutil.rmtree(job_folder)
            
            # Delete detections for expired jobs
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute("DELETE FROM detections WHERE job_id=?", (job_id,))
                await db.execute("DELETE FROM logs WHERE job_id=?", (job_id,))
                await db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
                await db.commit()
            cleanup_count += 1
        
        return jsonify({"cleaned_up": cleanup_count, "message": f"Removed {cleanup_count} expired URL jobs"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/start_job", methods=["POST"])
@auth_required
async def start_job():
    """
    Starts background detection for an existing upload.
    JSON body:
      { "upload_id": int, "object_filter": "all"|"people"|<class>, "confidence": float, "frame_skip": int }
    """
    payload = await request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Expected JSON body"}), 400

    upload_id = payload.get("upload_id")
    if not upload_id:
        return jsonify({"error": "upload_id required"}), 400

    upload = await db_query_one("SELECT * FROM uploads WHERE id=?", (upload_id,))
    if not upload:
        return jsonify({"error": "upload_id not found"}), 404

    object_filter = payload.get("object_filter", "all")
    confidence = float(payload.get("confidence", 0.5))
    frame_skip = int(payload.get("frame_skip", 10))

    # Insert job row
    job_id = await db_insert("jobs", {
        "user_id" : g.current_user['user_id'],
        "upload_id": upload_id,
        "source_type": "file",
        "object_filter": object_filter,
        "confidence": confidence,
        "frame_skip": frame_skip,
        "status": "pending"
    })

    # Start background task
    task = asyncio.create_task(detector.process_video(job_id, upload["saved_path"], object_filter, confidence, frame_skip))
    job_tasks[job_id] = task

    await log(job_id, "info", f"Job {job_id} queued for processing")
    return jsonify({"job_id": job_id})

@app.route("/stop_job", methods=["POST"])
@auth_required
async def stop_job():
    payload = await request.get_json(silent=True)
    job_id = payload.get("job_id") if payload else None
    if not job_id:
        return jsonify({"error": "job_id required"}), 400

    # Mark as stopped in DB; background task checks DB status and exits gracefully.
    await db_update("jobs", {"status": "stopped", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
    await log(job_id, "info", "Stop requested by user")

    # Attempt to cancel task as well (best-effort)
    task = job_tasks.get(job_id)
    if task:
        task.cancel()
        await log(job_id, "info", "Background task cancellation requested")

    return jsonify({"stopped": True, "job_id": job_id})

@app.route("/jobs")
@auth_required
async def list_jobs():
    """
    Returns a list of jobs with join to upload filename (for file jobs) or URL info
    """
    rows = await db_query("""
        SELECT j.*, u.filename as upload_filename, u.saved_path 
        FROM jobs j 
        LEFT JOIN uploads u ON u.id=j.upload_id 
        ORDER BY j.id DESC
    """)
    
    # Add human-readable info for each job
    for row in rows:
        if row['source_type'] == 'url':
            row['source_display'] = f"URL: {row['source_url'][:50]}..." if len(row['source_url']) > 50 else f"URL: {row['source_url']}"
            if row['expires_at']:
                expires = datetime.fromisoformat(row['expires_at'])
                now = datetime.utcnow()
                if expires > now:
                    hours_left = (expires - now).total_seconds() / 3600
                    row['expires_in_hours'] = round(hours_left, 1)
                else:
                    row['expires_in_hours'] = 0
        else:
            row['source_display'] = row['upload_filename'] or 'Unknown file'
    
    return jsonify({"jobs": rows})

@app.route("/jobs/<int:job_id>/detections")
@auth_required
async def job_detections(job_id: int):
    rows = await db_query("SELECT * FROM detections WHERE job_id=? ORDER BY id DESC", (job_id,))
    return jsonify({"detections": rows})

@app.route("/jobs/<int:job_id>/gallery")
@auth_required
async def job_gallery(job_id: int):
    """
    Gallery view of all detections for a job with images and metadata
    """
    # Check if this is a web request (wants HTML) or API request (wants JSON)
    accept_header = request.headers.get('Accept', '')
    wants_html = 'text/html' in accept_header and 'application/json' not in accept_header
    
    # Get job info
    job = await db_query_one("SELECT j.*, u.filename as upload_filename FROM jobs j LEFT JOIN uploads u ON u.id=j.upload_id WHERE j.id=?", (job_id,))
    if not job:
        if wants_html:
            return "Job not found", 404
        return jsonify({"error": "Job not found"}), 404
    
    if wants_html:
        # Return HTML gallery page
        return await render_template("Extractor-Gallery-Concept.html", job_id=job_id)
    
    # Return JSON data for API requests
    detections = await db_query("SELECT * FROM detections WHERE job_id=? ORDER BY frame_number ASC, confidence DESC", (job_id,))
    
    # Group by class for better organization
    by_class = {}
    for det in detections:
        class_name = det['class_name']
        if class_name not in by_class:
            by_class[class_name] = []
        by_class[class_name].append(det)
    
    return jsonify({
        "job": job,
        "total_detections": len(detections),
        "detections": detections,
        "by_class": by_class,
        "class_counts": {k: len(v) for k, v in by_class.items()}
    })

@app.route("/detection_image/<int:detection_id>")
async def serve_detection_image(detection_id: int):
    """
    Serve detection image by ID
    """
    detection = await db_query_one("SELECT image_path, image_base64 FROM detections WHERE id=?", (detection_id,))
    if not detection:
        return jsonify({"error": "Detection not found"}), 404
    
    # Try to serve from file first
    if detection['image_path'] and os.path.exists(detection['image_path']):
        return await send_file(detection['image_path'], mimetype='image/png')
    
    # Fallback to base64 if file doesn't exist
    if detection['image_base64']:
        img_data = base64.b64decode(detection['image_base64'])
        return img_data, 200, {'Content-Type': 'image/png'}
    
    return jsonify({"error": "Image not available"}), 404

@app.route("/jobs/<int:job_id>/logs")
async def job_logs(job_id: int):
    rows = await db_query("SELECT * FROM logs WHERE job_id=? ORDER BY id ASC", (job_id,))
    return jsonify({"logs": rows})

@app.route("/download/<int:job_id>")
async def download_job_zip(job_id: int):
    detections = await db_query("SELECT * FROM detections WHERE job_id=?", (job_id,))
    if not detections:
        return jsonify({"error": "no detections for job"}), 404

    tmpdir = tempfile.mkdtemp()
    zip_path = os.path.join(tmpdir, f"job_{job_id}_results.zip")

    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            metadata = []
            for d in detections:
                det_meta = {
                    "id": d["id"],
                    "frame_number": d["frame_number"],
                    "timestamp": d["timestamp"],
                    "class_name": d["class_name"],
                    "confidence": d["confidence"],
                    "bbox": json.loads(d["bbox"]) if d["bbox"] else None
                }
                metadata.append(det_meta)

                if d.get("image_base64"):
                    try:
                        imgdata = base64.b64decode(d["image_base64"])
                        fname = f"detection_{d['id']}_{d['class_name']}.png"
                        zf.writestr(fname, imgdata)
                    except Exception:
                        pass

            zf.writestr("metadata.json", json.dumps({"job_id": job_id, "detections": metadata}, indent=2))
        
        return await send_file(zip_path, as_attachment=True, download_name=f"job_{job_id}_results.zip")
    finally:
        # cleanup will be handled by OS, but we try to remove tmpdir after send
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

# -------------------------
# WebSocket: subscribe to job logs/events
# -------------------------
@app.websocket("/ws/jobs/<int:job_id>")
async def ws_job_events(job_id: int):
    # register client - get current websocket object correctly
    current_ws = websocket._get_current_object()
    # ensure list exists
    job_ws_clients.setdefault(job_id, []).append(current_ws)

    try:
        await current_ws.send(json.dumps({"type": "info", "message": f"Subscribed to job {job_id} events"}))

        # Send recent logs for context
        recent = await db_query("SELECT * FROM logs WHERE job_id=? ORDER BY id DESC LIMIT 50", (job_id,))
        # send in chronological order
        for r in reversed(recent):
            await current_ws.send(json.dumps({"type": "log", "job_id": job_id, "level": r["level"], "message": r["message"], "created_at": r["created_at"]}))

        # keep connection open and wait for client pings/messages (no-op)
        while True:
            try:
                msg = await current_ws.receive()
                # optionally handle client messages (e.g., request progress), but ignore by default
                # echo back
                await current_ws.send(json.dumps({"type": "echo", "payload": msg}))
            except asyncio.CancelledError:
                break
            except Exception:
                # connection closed or broken
                break
    finally:
        # remove client
        lst = job_ws_clients.get(job_id, [])
        try:
            lst.remove(current_ws)
        except ValueError:
            pass

# -------------------------
# -------------------------
# HTML Templates
# -------------------------







###########################################################################################
########################################### EOF  FRAME EXTRACTOR ################################################## 




######################################################################################################################
###########################################  CORRELATION CONCEPT #####################################################



class ObjectFeatureExtractor:
    """Extract features from objects for matching"""
    
    def __init__(self):
        # Initialize feature detectors
        self.orb = cv2.ORB_create(nfeatures=1000)
        self.sift = cv2.SIFT_create()
        self.bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        
    def extract_features(self, image):
        """Extract key features from image"""
        try:
            # Convert to grayscale if needed
            if len(image.shape) == 3:
                gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            else:
                gray = image
            
            # Resize for consistency
            gray = cv2.resize(gray, (200, 200))
            
            # Extract ORB features
            keypoints, descriptors = self.orb.detectAndCompute(gray, None)
            
            # Extract color histogram
            if len(image.shape) == 3:
                hist = self._extract_color_histogram(image)
            else:
                hist = np.array([])
            
            # Extract shape features
            shape_features = self._extract_shape_features(gray)
            
            return {
                'keypoints': keypoints,
                'descriptors': descriptors,
                'color_histogram': hist,
                'shape_features': shape_features,
                'image_shape': gray.shape
            }
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return None
    
    def _extract_color_histogram(self, image, bins=8):
        """Extract color histogram features"""
        # Convert to HSV for better color representation
        hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
        
        # Compute histogram for each channel
        hist_h = cv2.calcHist([hsv], [0], None, [bins], [0, 180])
        hist_s = cv2.calcHist([hsv], [1], None, [bins], [0, 256])
        hist_v = cv2.calcHist([hsv], [2], None, [bins], [0, 256])
        
        # Normalize histograms
        cv2.normalize(hist_h, hist_h)
        cv2.normalize(hist_s, hist_s)
        cv2.normalize(hist_v, hist_v)
        
        # Flatten and combine
        hist = np.vstack([hist_h, hist_s, hist_v]).flatten()
        return hist
    
    def _extract_shape_features(self, image):
        """Extract shape-based features"""
        # Apply threshold to get binary image
        _, thresh = cv2.threshold(image, 127, 255, cv2.THRESH_BINARY)
        
        # Find contours
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        if not contours:
            return np.array([0, 0, 0, 0])
        
        # Get largest contour
        largest_contour = max(contours, key=cv2.contourArea)
        
        # Calculate shape features
        area = cv2.contourArea(largest_contour)
        perimeter = cv2.arcLength(largest_contour, True)
        x, y, w, h = cv2.boundingRect(largest_contour)
        aspect_ratio = w / h if h > 0 else 0
        
        # Calculate circularity
        circularity = 4 * np.pi * area / (perimeter * perimeter) if perimeter > 0 else 0
        
        return np.array([area, perimeter, aspect_ratio, circularity])
    
    def compare_features(self, features1, features2):
        """Compare two feature sets and return similarity score"""
        try:
            similarity_scores = {}
            
            # Compare ORB descriptors
            if features1['descriptors'] is not None and features2['descriptors'] is not None:
                orb_similarity = self._compare_orb_features(features1, features2)
                similarity_scores['orb'] = orb_similarity
            else:
                similarity_scores['orb'] = 0
            
            # Compare color histograms
            if len(features1['color_histogram']) > 0 and len(features2['color_histogram']) > 0:
                color_similarity = self._compare_histograms(features1['color_histogram'], features2['color_histogram'])
                similarity_scores['color'] = color_similarity
            else:
                similarity_scores['color'] = 0
            
            # Compare shape features
            if len(features1['shape_features']) > 0 and len(features2['shape_features']) > 0:
                shape_similarity = self._compare_shape_features(features1['shape_features'], features2['shape_features'])
                similarity_scores['shape'] = shape_similarity
            else:
                similarity_scores['shape'] = 0
            
            # Calculate weighted overall similarity
            overall_similarity = (
                similarity_scores['orb'] * 0.5 +
                similarity_scores['color'] * 0.3 +
                similarity_scores['shape'] * 0.2
            )
            
            return {
                'overall': overall_similarity,
                'components': similarity_scores,
                'match': overall_similarity > 0.6  # Threshold for match
            }
            
        except Exception as e:
            print(f"Feature comparison error: {e}")
            return {'overall': 0, 'components': {}, 'match': False}
    
    def _compare_orb_features(self, features1, features2):
        """Compare ORB features using brute force matching"""
        try:
            if features1['descriptors'] is None or features2['descriptors'] is None:
                return 0
            
            # Ensure descriptors are the right type
            desc1 = features1['descriptors'].astype(np.uint8)
            desc2 = features2['descriptors'].astype(np.uint8)
            
            # Match descriptors
            matches = self.bf.match(desc1, desc2)
            
            # Calculate similarity based on number of good matches
            good_matches = [m for m in matches if m.distance < 50]
            
            if len(matches) == 0:
                return 0
            
            similarity = len(good_matches) / len(matches)
            return min(similarity * 2, 1.0)  # Scale to 0-1 range
            
        except Exception as e:
            print(f"ORB comparison error: {e}")
            return 0
    
    def _compare_histograms(self, hist1, hist2):
        """Compare histograms using correlation"""
        try:
            # Ensure histograms have same length
            min_len = min(len(hist1), len(hist2))
            hist1 = hist1[:min_len]
            hist2 = hist2[:min_len]
            
            # Calculate correlation
            correlation = cv2.compareHist(hist1.astype(np.float32), hist2.astype(np.float32), cv2.HISTCMP_CORREL)
            
            # Normalize to 0-1 range
            return (correlation + 1) / 2
            
        except Exception as e:
            print(f"Histogram comparison error: {e}")
            return 0
    
    def _compare_shape_features(self, shape1, shape2):
        """Compare shape features"""
        try:
            # Normalize shape features
            shape1_norm = shape1 / (np.linalg.norm(shape1) + 1e-8)
            shape2_norm = shape2 / (np.linalg.norm(shape2) + 1e-8)
            
            # Calculate cosine similarity
            similarity = np.dot(shape1_norm, shape2_norm)
            
            return max(similarity, 0)
            
        except Exception as e:
            print(f"Shape comparison error: {e}")
            return 0

class ObjectSearchEngine:
    """Main search engine for finding objects in videos"""
    
    def __init__(self):
        self.feature_extractor = ObjectFeatureExtractor()
        self.search_results = {}
        
    async def search_objects(self, target_media_path, source_video_path, search_id, websocket):
        """Search for target objects in source video"""
        try:
            await websocket.send_json({
                'type': 'search_started',
                'search_id': search_id,
                'message': 'Starting object search...'
            })
            
            # Extract features from target media
            await websocket.send_json({
                'type': 'search_status',
                'status': 'Analyzing target media...',
                'progress': 10
            })
            
            target_features = await self._extract_target_features(target_media_path)
            if not target_features:
                await websocket.send_json({
                    'type': 'search_error',
                    'message': 'Failed to extract features from target media'
                })
                return
            
            await websocket.send_json({
                'type': 'search_status',
                'status': 'Target analysis complete. Processing source video...',
                'progress': 20
            })
            
            # Process source video
            cap = cv2.VideoCapture(str(source_video_path))
            if not cap.isOpened():
                await websocket.send_json({
                    'type': 'search_error',
                    'message': 'Cannot open source video'
                })
                return
            
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS) or 30
            
            # Detect objects in source video
            detector = EnhancedObjectDetector()
            matches_found = []
            frame_count = 0
            
            await websocket.send_json({
                'type': 'search_status',
                'status': 'Detecting objects in source video...',
                'progress': 30
            })
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                current_time = frame_count / fps
                
                # Detect objects in frame
                detections = detector.detect_objects(frame, current_time)
                
                # Compare each detection with target
                for detection in detections:
                    # Extract object from frame
                    x, y, w, h = [int(coord) for coord in detection['bbox']]
                    object_roi = frame[y:y+h, x:x+w]
                    
                    if object_roi.size == 0:
                        continue
                    
                    # Extract features from detected object
                    object_features = self.feature_extractor.extract_features(object_roi)
                    if not object_features:
                        continue
                    
                    # Compare with target
                    similarity_result = self.feature_extractor.compare_features(
                        target_features, object_features
                    )
                    
                    if similarity_result['match']:
                        match_data = {
                            'frame_number': frame_count,
                            'timestamp': current_time,
                            'bbox': detection['bbox'],
                            'similarity': similarity_result['overall'],
                            'similarity_components': similarity_result['components'],
                            'class_name': detection['class_name'],
                            'object_image': self._encode_image(object_roi),
                            'match_context': self._encode_image(frame)
                        }
                        matches_found.append(match_data)
                
                # Send progress updates
                if frame_count % 30 == 0:
                    progress = 30 + (frame_count / total_frames) * 60
                    await websocket.send_json({
                        'type': 'search_progress',
                        'progress': progress,
                        'frames_processed': frame_count,
                        'matches_found': len(matches_found),
                        'status': f'Processed {frame_count}/{total_frames} frames, found {len(matches_found)} matches'
                    })
                
                frame_count += 1
            
            cap.release()
            
            # Finalize results
            await websocket.send_json({
                'type': 'search_status',
                'status': 'Finalizing results...',
                'progress': 95
            })
            
            # Save results to database
            await self._save_search_results(search_id, target_media_path, source_video_path, matches_found)
            
            # Send final results
            await websocket.send_json({
                'type': 'search_completed',
                'search_id': search_id,
                'total_matches': len(matches_found),
                'matches': matches_found[:50],  # Limit to first 50 matches
                'total_frames_processed': frame_count,
                'search_duration': frame_count / fps
            })
            
        except Exception as e:
            print(f"Search error: {e}")
            await websocket.send_json({
                'type': 'search_error',
                'message': f'Search failed: {str(e)}'
            })
    
    async def _extract_target_features(self, target_path):
        """Extract features from target media (image or video)"""
        try:
            # Check if target is image or video
            if target_path.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')):
                # Target is an image
                image = cv2.imread(str(target_path))
                if image is None:
                    return None
                return self.feature_extractor.extract_features(image)
            else:
                # Target is a video - use first frame with objects
                cap = cv2.VideoCapture(str(target_path))
                detector = EnhancedObjectDetector()
                
                for _ in range(100):  # Check first 100 frames
                    ret, frame = cap.read()
                    if not ret:
                        break
                    
                    detections = detector.detect_objects(frame, 0)
                    if detections:
                        # Use the largest detection
                        largest_detection = max(detections, key=lambda d: d['area'])
                        x, y, w, h = [int(coord) for coord in largest_detection['bbox']]
                        object_roi = frame[y:y+h, x:x+w]
                        
                        if object_roi.size > 0:
                            cap.release()
                            return self.feature_extractor.extract_features(object_roi)
                
                cap.release()
                return None
                
        except Exception as e:
            print(f"Target feature extraction error: {e}")
            return None
    
    def _encode_image(self, image):
        """Encode image as base64"""
        try:
            _, buffer = cv2.imencode('.jpg', image, [cv2.IMWRITE_JPEG_QUALITY, 70])
            return base64.b64encode(buffer).decode('utf-8')
        except:
            return ""
    
    async def _save_search_results(self, search_id, target_path, source_path, matches):
        """Save search results to database"""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS search_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        search_id TEXT NOT NULL,
                        target_media_path TEXT NOT NULL,
                        source_video_path TEXT NOT NULL,
                        matches_data TEXT NOT NULL,
                        total_matches INTEGER NOT NULL,
                        search_timestamp TEXT DEFAULT (datetime('now'))
                    )
                """)
                
                await db.execute("""
                    INSERT INTO search_results 
                    (search_id, target_media_path, source_video_path, matches_data, total_matches)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    search_id, str(target_path), str(source_path), 
                    json.dumps(matches, default=str), len(matches)
                ))
                
                await db.commit()
        except Exception as e:
            print(f"Error saving search results: {e}")

class EnhancedObjectDetector:
    """Object detector for search system"""
    
    def __init__(self):
        self.back_sub = cv2.createBackgroundSubtractorMOG2(history=500, varThreshold=16, detectShadows=True)
        self.kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
        
    def detect_objects(self, frame, timestamp):
        """Detect objects in frame"""
        try:
            # Resize for processing efficiency
            height, width = frame.shape[:2]
            if width > 800:
                scale = 800 / width
                new_width = 800
                new_height = int(height * scale)
                frame_resized = cv2.resize(frame, (new_width, new_height))
            else:
                frame_resized = frame
                new_width, new_height = width, height
            
            # Background subtraction
            fg_mask = self.back_sub.apply(frame_resized)
            
            # Noise removal and enhancement
            fg_mask = cv2.morphologyEx(fg_mask, cv2.MORPH_OPEN, self.kernel)
            fg_mask = cv2.dilate(fg_mask, self.kernel, iterations=2)
            
            # Find contours
            contours, _ = cv2.findContours(fg_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            detections = []
            for contour in contours:
                area = cv2.contourArea(contour)
                if 500 < area < 50000:
                    x, y, w, h = cv2.boundingRect(contour)
                    
                    # Scale coordinates back to original frame size
                    if width != new_width:
                        scale_x = width / new_width
                        scale_y = height / new_height
                        x, y, w, h = int(x * scale_x), int(y * scale_y), int(w * scale_x), int(h * scale_y)
                    
                    # Classification
                    class_name, confidence = self._classify_object(w, h, area, contour)
                    
                    detections.append({
                        'bbox': (x, y, w, h),
                        'class_name': class_name,
                        'confidence': confidence,
                        'timestamp': timestamp,
                        'area': area
                    })
            
            return detections
            
        except Exception as e:
            print(f"Detection error: {e}")
            return []
    
    def _classify_object(self, w, h, area, contour):
        """Classify detected objects"""
        aspect_ratio = w / h if h > 0 else 1.0
        
        if aspect_ratio > 2.5:
            return 'vehicle', min(area / 15000, 1.0)
        elif aspect_ratio > 1.8:
            if area > 8000:
                return 'vehicle', min(area / 20000, 1.0)
            else:
                return 'small_object', min(area / 5000, 1.0)
        elif 0.7 < aspect_ratio < 1.8:
            if area > 5000:
                return 'person', min(area / 15000, 1.0)
            elif area > 1500:
                return 'person', min(area / 8000, 0.8)
            else:
                return 'small_object', min(area / 3000, 1.0)
        else:
            if area > 3000:
                return 'person', min(area / 10000, 0.7)
            else:
                return 'small_object', min(area / 2000, 1.0)

@app.route('/correlator')
async def corr_dashboard():
    """Main dashboard for object search"""
    return await render_template("Proof-Correllator-Concept.html")
      
@app.websocket('/ws/object-search')
async def object_search_websocket():
    """WebSocket for object search and matching"""
    await websocket.accept()
    print("Object Search WebSocket connected")
    
    search_engine = ObjectSearchEngine()
    current_search_task = None
    
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=300.0)
                
                if data.get('type') == 'start_search':
                    source_video_id = data.get('source_video_id')
                    target_media_id = data.get('target_media_id')
                    target_media_type = data.get('target_media_type')
                    
                    if source_video_id and target_media_id:
                        # Get file paths from database
                        async with aiosqlite.connect(DB_PATH) as db:
                            # Get source video path
                            cursor = await db.execute(
                                "SELECT file_path FROM search_videos WHERE id = ?", 
                                (source_video_id,)
                            )
                            source_video = await cursor.fetchone()
                            
                            # Get target media path
                            if target_media_type == 'image':
                                cursor = await db.execute(
                                    "SELECT file_path FROM search_images WHERE id = ?", 
                                    (target_media_id,)
                                )
                            else:
                                cursor = await db.execute(
                                    "SELECT file_path FROM search_videos WHERE id = ?", 
                                    (target_media_id,)
                                )
                            target_media = await cursor.fetchone()
                        
                        if source_video and target_media:
                            search_id = f"search_{int(time.time())}_{hashlib.md5(str(source_video_id).encode()).hexdigest()[:6]}"
                            
                            # Start search in background task
                            current_search_task = asyncio.create_task(
                                search_engine.search_objects(
                                    target_media[0], 
                                    source_video[0], 
                                    search_id, 
                                    websocket
                                )
                            )
                        else:
                            await websocket.send_json({
                                'type': 'search_error',
                                'message': 'Source video or target media not found'
                            })
                    
                elif data.get('type') == 'stop_search':
                    if current_search_task and not current_search_task.done():
                        current_search_task.cancel()
                        await websocket.send_json({
                            'type': 'search_stopped',
                            'message': 'Search stopped by user'
                        })
                    
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({'type': 'ping'})
                except:
                    break
            except Exception as e:
                print(f"WebSocket error: {e}")
                break
                
    except Exception as e:
        print(f"WebSocket connection error: {e}")
    finally:
        if current_search_task and not current_search_task.done():
            current_search_task.cancel()
        print("Object Search WebSocket disconnected")

@app.route('/api/object-search/upload-source', methods=['POST'])
async def upload_source_video():
    """Upload source video for search"""
    try:
        if 'video' not in (await request.files):
            return jsonify({'error': 'No video file provided'}), 400
        
        video_file = (await request.files)['video']
        if video_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not video_file.filename.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.webm')):
            return jsonify({'error': 'Please upload a video file'}), 400
        
        file_hash = hashlib.md5(f"{time.time()}_{video_file.filename}".encode()).hexdigest()[:8]
        filename = f"search_source_{file_hash}_{video_file.filename}"
        file_path = UPLOAD_FOLDER / filename
        
        UPLOAD_FOLDER.mkdir(exist_ok=True)
        await video_file.save(file_path)
        
        if not file_path.exists():
            return jsonify({'error': 'File save failed'}), 500
        
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS search_videos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    upload_time TEXT DEFAULT (datetime('now')),
                    media_type TEXT DEFAULT 'source'
                )
            """)
            
            cursor = await db.execute("""
                INSERT INTO search_videos (filename, file_path, file_size)
                VALUES (?, ?, ?)
            """, (filename, str(file_path), file_path.stat().st_size))
            
            await db.commit()
            
            cursor = await db.execute("SELECT last_insert_rowid()")
            result = await cursor.fetchone()
            video_id = result[0] if result else None
        
        if not video_id:
            return jsonify({'error': 'Failed to get video ID'}), 500
        
        return jsonify({
            'video_id': video_id,
            'filename': filename,
            'status': 'uploaded'
        })
        
    except Exception as e:
        print(f"Source video upload error: {e}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/object-search/upload-target', methods=['POST'])
async def upload_target_media():
    """Upload target media for search"""
    try:
        if 'media' not in (await request.files):
            return jsonify({'error': 'No media file provided'}), 400
        
        media_file = (await request.files)['media']
        media_type = (await request.form).get('media_type', 'image')
        
        if media_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type based on media type
        if media_type == 'image':
            if not media_file.filename.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')):
                return jsonify({'error': 'Please upload an image file'}), 400
        else:
            if not media_file.filename.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.webm')):
                return jsonify({'error': 'Please upload a video file'}), 400
        
        file_hash = hashlib.md5(f"{time.time()}_{media_file.filename}".encode()).hexdigest()[:8]
        
        if media_type == 'image':
            filename = f"search_target_{file_hash}_{media_file.filename}"
            table_name = "search_images"
        else:
            filename = f"search_target_{file_hash}_{media_file.filename}"
            table_name = "search_videos"
        
        file_path = UPLOAD_FOLDER / filename
        
        UPLOAD_FOLDER.mkdir(exist_ok=True)
        await media_file.save(file_path)
        
        if not file_path.exists():
            return jsonify({'error': 'File save failed'}), 500
        
        async with aiosqlite.connect(DB_PATH) as db:
            if media_type == 'image':
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS search_images (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        file_size INTEGER,
                        upload_time TEXT DEFAULT (datetime('now')),
                        media_type TEXT DEFAULT 'target_image'
                    )
                """)
            else:
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS search_videos (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        file_size INTEGER,
                        upload_time TEXT DEFAULT (datetime('now')),
                        media_type TEXT DEFAULT 'target_video'
                    )
                """)
            
            cursor = await db.execute(f"""
                INSERT INTO {table_name} (filename, file_path, file_size)
                VALUES (?, ?, ?)
            """, (filename, str(file_path), file_path.stat().st_size))
            
            await db.commit()
            
            cursor = await db.execute("SELECT last_insert_rowid()")
            result = await cursor.fetchone()
            media_id = result[0] if result else None
        
        if not media_id:
            return jsonify({'error': 'Failed to get media ID'}), 500
        
        return jsonify({
            'media_id': media_id,
            'filename': filename,
            'media_type': media_type,
            'status': 'uploaded'
        })
        
    except Exception as e:
        print(f"Target media upload error: {e}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/object-search/videos')
async def get_search_videos():
    """Get list of available source videos"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT id, filename, file_path, upload_time 
                FROM search_videos 
                WHERE media_type = 'source' OR media_type IS NULL
                ORDER BY upload_time DESC
            """)
            
            videos = await cursor.fetchall()
            
            result = []
            for video in videos:
                result.append({
                    'id': video[0],
                    'filename': video[1],
                    'file_path': video[2],
                    'upload_time': video[3]
                })
            
            return jsonify({'videos': result})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/object-search/statistics')
async def get_search_statistics():
    """Get search statistics"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            # Total searches
            cursor = await db.execute("SELECT COUNT(*) FROM search_results")
            total_searches = (await cursor.fetchone())[0] or 0
            
            # Successful searches (with matches)
            cursor = await db.execute("SELECT COUNT(*) FROM search_results WHERE total_matches > 0")
            successful_searches = (await cursor.fetchone())[0] or 0
            
            # Average matches
            cursor = await db.execute("SELECT AVG(total_matches) FROM search_results")
            avg_matches = (await cursor.fetchone())[0] or 0
            
            # Calculate success rate
            success_rate = (successful_searches / total_searches * 100) if total_searches > 0 else 0
            
            # Average duration (placeholder - would need actual timing data)
            avg_duration = 30.0  # Placeholder
            
            return jsonify({
                'total_searches': total_searches,
                'success_rate': round(success_rate, 1),
                'avg_matches': round(avg_matches, 1),
                'avg_duration': round(avg_duration, 1)
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/object-search/results/<search_id>')
async def get_search_results(search_id):
    """Get specific search results"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT matches_data, total_matches, search_timestamp
                FROM search_results 
                WHERE search_id = ?
            """, (search_id,))
            
            result = await cursor.fetchone()
            
            if result:
                matches_data = json.loads(result[0]) if result[0] else []
                return jsonify({
                    'search_id': search_id,
                    'matches': matches_data,
                    'total_matches': result[1],
                    'timestamp': result[2]
                })
            else:
                return jsonify({'error': 'Search results not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500










############################################# ################################ ########################################################
#############################################    EOF CORRELATION ######################################################################

    
    


##############################################################################################################################################
######################################################### ENHANCERS ULTIMATE ##################################################################


# -------------------------
class ForensicVideoEnhancer:
    def __init__(self):
        self.enhancement_types = {
            # Resolution & Quality
            "super_resolution": "2x-4x Resolution Upscaling",
            "frame_interpolation": "Frame Rate Increase (2x-4x)",
            "super_slow_motion": "Super Slow Motion (8x+)",
            
            # Noise & Artifact Removal
            "denoising": "Noise Reduction & Cleaning",
            "temporal_denoising": "Temporal Noise Reduction",
            "artifact_removal": "Compression Artifact Removal",
            "dehazing": "Haze & Fog Removal",
            
            # Motion & Stabilization
            "stabilization": "Video Stabilization",
            "deblurring": "Motion Deblurring",
            
            # Color & Grayscale
            "grayscale": "Convert to Grayscale for Forensic Analysis",
            "color_inversion": "Color Inversion (Negative Image)",
            "hsv_enhancement": "HSV Color Space Enhancement",
            "channel_separation": "RGB Channel Separation & Analysis",
            "skin_tone_enhancement": "Skin Tone Detection & Enhancement",
            "histogram_equalization": "Global Histogram Equalization",
            "adaptive_histogram": "Adaptive Histogram Equalization (CLAHE)",
            "binary_threshold": "Binary Thresholding for Text/Objects",
            "adaptive_threshold": "Adaptive Thresholding",
            "license_plate_enhancement": "License Plate Color Enhancement",
            "color_pop": "Selective Color Pop Effect",
            "infrared_simulation": "Infrared Color Simulation",
            "low_light_enhancement": "Low Light Enhancement",
            "contrast_enhancement": "Contrast & Brightness Adjustment",
            "color_correction": "Color Correction & White Balance",
            
            # Specialized Forensic
            "sharpening": "Image Sharpening",
            "depth_estimation": "3D Depth Estimation",
            "object_super_resolution": "Object-Specific Super Resolution"
        }
    
    async def log_trace(self, job_id: int, message: str, level: str = "info"):
        """Enhanced trace logging with terminal output"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [JOB-{job_id}] [{level.upper()}] {message}"
        
        # Terminal output
        print(log_message)
        
        # Database logging
        await db_insert("logs", {
            "job_id": job_id,
            "user_id": g.current_user['id'],
            "level": level,
            "message": message
        })
    
    async def enhance_video(self, job_id: int, input_video_path: str, enhancement_type: str, params: dict = None):
        """Apply various enhancement techniques to video with detailed trace logging"""
        start_time = time.time()
        
        await self.log_trace(job_id, f"🚀 Starting {enhancement_type} enhancement process")
        await self.log_trace(job_id, f"📁 Input video: {input_video_path}")
        
        cap = cv2.VideoCapture(input_video_path)
        if not cap.isOpened():
            error_msg = "❌ Could not open input video"
            await self.log_trace(job_id, error_msg, "error")
            raise ValueError(error_msg)
        
        fps = int(cap.get(cv2.CAP_PROP_FPS))
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        await self.log_trace(job_id, f"📊 Video info: {width}x{height} @ {fps}fps, {total_frames} frames")
        
        # Determine output parameters based on enhancement type
        output_fps = fps
        output_width, output_height = width, height
        
        if enhancement_type == "super_resolution":
            output_width, output_height = width * 2, height * 2
            await self.log_trace(job_id, f"🔍 Super resolution: {width}x{height} -> {output_width}x{output_height}")
        elif enhancement_type == "frame_interpolation":
            output_fps = fps * 2
            await self.log_trace(job_id, f"⏱️ Frame interpolation: {fps}fps -> {output_fps}fps")
        
        output_path = os.path.join(OUTPUT_DIR, f"enhanced_{enhancement_type}_{job_id}.mp4")
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(output_path, fourcc, output_fps, (output_width, output_height))
        
        await self.log_trace(job_id, f"🎬 Output video: {output_path}")
        
        frame_idx = 0
        prev_frame = None
        
        await self.log_trace(job_id, "🔄 Starting frame processing...")
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            progress = 10 + int((frame_idx / total_frames) * 85)
            if frame_idx % 50 == 0:  # Log every 50 frames to avoid spam
                await self.log_trace(job_id, f"📈 Progress: {progress}% - Processing frame {frame_idx}/{total_frames}")
            
            # Apply enhancement based on type
            enhanced_frame = await self._apply_enhancement(frame, enhancement_type, prev_frame, params)
            
            # Add enhancement info overlay
            cv2.putText(enhanced_frame, f"Enhanced: {enhancement_type}", (10, 30), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
            cv2.putText(enhanced_frame, f"Frame: {frame_idx}", (10, 60), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
            
            out.write(enhanced_frame)
            
            # For temporal enhancements, store previous frame
            if enhancement_type in ["temporal_denoising", "frame_interpolation", "stabilization"]:
                prev_frame = frame.copy()
            
            frame_idx += 1
            
            # Simulate processing time
            await asyncio.sleep(0.01)
        
        cap.release()
        out.release()
        
        await self.log_trace(job_id, "✅ Frame processing completed")
        
        thumbnail_path = await self._create_thumbnail(output_path, job_id)
        await self.log_trace(job_id, f"🖼️ Thumbnail created: {thumbnail_path}")
        
        processing_time = time.time() - start_time
        await self.log_trace(job_id, f"⏰ Total processing time: {processing_time:.2f} seconds")
        
        return output_path, thumbnail_path, processing_time
    
    async def _apply_enhancement(self, frame: np.ndarray, enhancement_type: str, prev_frame: np.ndarray = None, params: dict = None):
        """Apply specific enhancement algorithm to frame"""
        
        if enhancement_type == "super_resolution":
            enhanced = cv2.resize(frame, (frame.shape[1]*2, frame.shape[0]*2), interpolation=cv2.INTER_CUBIC)
            enhanced = cv2.GaussianBlur(enhanced, (3, 3), 0)
            
        elif enhancement_type == "denoising":
            enhanced = cv2.fastNlMeansDenoisingColored(frame, None, 10, 10, 7, 21)
            
        elif enhancement_type == "stabilization":
            if prev_frame is not None:
                prev_gray = cv2.cvtColor(prev_frame, cv2.COLOR_BGR2GRAY)
                curr_gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                flow = cv2.calcOpticalFlowFarneback(prev_gray, curr_gray, None, 0.5, 3, 15, 3, 5, 1.2, 0)
                dx, dy = np.median(flow[..., 0]), np.median(flow[..., 1])
                M = np.float32([[1, 0, -dx*0.5], [0, 1, -dy*0.5]])
                enhanced = cv2.warpAffine(frame, M, (frame.shape[1], frame.shape[0]))
            else:
                enhanced = frame
                
        elif enhancement_type == "deblurring":
            kernel = np.ones((5, 5), np.float32) / 25
            enhanced = cv2.filter2D(frame, -1, kernel)
            enhanced = cv2.addWeighted(frame, 1.5, enhanced, -0.5, 0)
            
        elif enhancement_type == "low_light_enhancement":
            lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
            l, a, b = cv2.split(lab)
            clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
            l = clahe.apply(l)
            enhanced = cv2.cvtColor(cv2.merge([l, a, b]), cv2.COLOR_LAB2BGR)
            enhanced = cv2.convertScaleAbs(enhanced, alpha=1.2, beta=10)
            
        elif enhancement_type == "frame_interpolation":
            enhanced = cv2.addWeighted(frame, 0.7, prev_frame, 0.3, 0) if prev_frame is not None else frame
            
        elif enhancement_type == "contrast_enhancement":
            lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
            l, a, b = cv2.split(lab)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            l = clahe.apply(l)
            enhanced = cv2.cvtColor(cv2.merge([l, a, b]), cv2.COLOR_LAB2BGR)
            
        elif enhancement_type == "color_correction":
            result = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
            avg_a = np.average(result[:, :, 1])
            avg_b = np.average(result[:, :, 2])
            result[:, :, 1] = result[:, :, 1] - ((avg_a - 128) * (result[:, :, 0] / 255.0) * 1.1)
            result[:, :, 2] = result[:, :, 2] - ((avg_b - 128) * (result[:, :, 0] / 255.0) * 1.1)
            enhanced = cv2.cvtColor(result, cv2.COLOR_LAB2BGR)
            
        elif enhancement_type == "temporal_denoising":
            if prev_frame is not None:
                enhanced = cv2.addWeighted(frame, 0.7, prev_frame, 0.3, 0)
            else:
                enhanced = frame
                
        elif enhancement_type == "sharpening":
            kernel = np.array([[-1, -1, -1],
                              [-1, 9, -1],
                              [-1, -1, -1]])
            enhanced = cv2.filter2D(frame, -1, kernel)
            
        elif enhancement_type == "artifact_removal":
            enhanced = cv2.medianBlur(frame, 3)
            enhanced = cv2.detailEnhance(enhanced, sigma_s=10, sigma_r=0.15)
            
        elif enhancement_type == "dehazing":
            enhanced = cv2.detailEnhance(frame, sigma_s=10, sigma_r=0.15)
            enhanced = cv2.addWeighted(enhanced, 1.2, enhanced, 0, 10)
            
        elif enhancement_type == "grayscale":
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            enhanced = cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)
            
        elif enhancement_type == "color_inversion":
            enhanced = cv2.bitwise_not(frame)
            
        elif enhancement_type == "hsv_enhancement":
            hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
            hsv[:, :, 1] = cv2.equalizeHist(hsv[:, :, 1])
            hsv[:, :, 2] = cv2.equalizeHist(hsv[:, :, 2])
            enhanced = cv2.cvtColor(hsv, cv2.COLOR_HSV2BGR)
            
        elif enhancement_type == "channel_separation":
            b, g, r = cv2.split(frame)
            zeros = np.zeros_like(b)
            red_channel = cv2.merge([zeros, zeros, r])
            green_channel = cv2.merge([zeros, g, zeros])
            blue_channel = cv2.merge([b, zeros, zeros])
            combined = np.hstack([red_channel, green_channel, blue_channel])
            if combined.shape[1] > 1920:
                scale = 1920 / combined.shape[1]
                new_width = 1920
                new_height = int(combined.shape[0] * scale)
                enhanced = cv2.resize(combined, (new_width, new_height))
            else:
                enhanced = combined
            
        elif enhancement_type == "skin_tone_enhancement":
            hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
            lower_skin = np.array([0, 20, 70], dtype=np.uint8)
            upper_skin = np.array([20, 255, 255], dtype=np.uint8)
            mask = cv2.inRange(hsv, lower_skin, upper_skin)
            skin = cv2.bitwise_and(frame, frame, mask=mask)
            enhanced = cv2.addWeighted(frame, 0.3, skin, 0.7, 0)
            
        elif enhancement_type == "histogram_equalization":
            yuv = cv2.cvtColor(frame, cv2.COLOR_BGR2YUV)
            yuv[:, :, 0] = cv2.equalizeHist(yuv[:, :, 0])
            enhanced = cv2.cvtColor(yuv, cv2.COLOR_YUV2BGR)
            
        elif enhancement_type == "adaptive_histogram":
            lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
            lab[:, :, 0] = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(lab[:, :, 0])
            enhanced = cv2.cvtColor(lab, cv2.COLOR_LAB2BGR)
            
        elif enhancement_type == "binary_threshold":
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            _, binary = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
            enhanced = cv2.cvtColor(binary, cv2.COLOR_GRAY2BGR)
            
        elif enhancement_type == "adaptive_threshold":
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            binary = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                         cv2.THRESH_BINARY, 11, 2)
            enhanced = cv2.cvtColor(binary, cv2.COLOR_GRAY2BGR)
            
        elif enhancement_type == "license_plate_enhancement":
            hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
            lower_white = np.array([0, 0, 200], dtype=np.uint8)
            upper_white = np.array([255, 30, 255], dtype=np.uint8)
            lower_yellow = np.array([20, 100, 100], dtype=np.uint8)
            upper_yellow = np.array([30, 255, 255], dtype=np.uint8)
            mask_white = cv2.inRange(hsv, lower_white, upper_white)
            mask_yellow = cv2.inRange(hsv, lower_yellow, upper_yellow)
            mask = cv2.bitwise_or(mask_white, mask_yellow)
            enhanced_color = cv2.bitwise_and(frame, frame, mask=mask)
            enhanced = cv2.addWeighted(frame, 0.3, enhanced_color, 0.7, 0)
            
        elif enhancement_type == "color_pop":
            b, g, r = cv2.split(frame)
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            enhanced = cv2.merge([gray, gray, r])
            
        elif enhancement_type == "infrared_simulation":
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            infrared = cv2.applyColorMap(gray, cv2.COLORMAP_JET)
            enhanced = cv2.addWeighted(frame, 0.5, infrared, 0.5, 0)
            
        else:
            enhanced = frame
            
        return enhanced
    
    async def _create_thumbnail(self, video_path: str, job_id: str) -> str:
        """Create thumbnail from video"""
        cap = cv2.VideoCapture(video_path)
        ret, frame = cap.read()
        cap.release()
        
        if ret:
            thumbnail_path = os.path.join(OUTPUT_DIR, f"thumb_{job_id}.jpg")
            cv2.imwrite(thumbnail_path, frame)
            return thumbnail_path
        return None

video_enhancer = ForensicVideoEnhancer()




# -------------------------
# Utility Functions
# -------------------------
# -------------------------
async def get_uploaded_files() -> List[Dict[str, Any]]:
    """Get list of uploaded files from database"""
    if not hasattr(g, 'current_user'):
        return []
    
    files = await db_query("""
        SELECT * FROM uploads 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    """, (g.current_user['user_id'],))
    
    return files


def allowed_file(filename: str) -> bool:
    allowed_extensions = {"mp4", "avi", "mov", "mkv", "webm"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions



# -------------------------
# File Management Routes
# -------------------------
@app.route('/files/uploaded')
@auth_required
async def get_uploaded_files_list():
    """Get list of uploaded video files from database"""
    files = await get_uploaded_files()
    return jsonify({"files": files})

# -------------------------
# Enhancement Routes
# -------------------------
@app.route('/enhance/video', methods=['POST'])
@auth_required
async def enhance_video():
    data = await request.get_json()
    upload_id = data.get('upload_id')
    enhancement_type = data.get('enhancement_type')
    params = data.get('params', {})
    
    if not upload_id:
        return jsonify({"error": "Upload ID is required"}), 400
    
    # Get upload details
    upload = await db_query_one("SELECT * FROM uploads WHERE id = ? AND user_id = ?", 
                               (upload_id, g.current_user['id']))
    if not upload:
        return jsonify({"error": "Upload not found"}), 404
    
    if not os.path.exists(upload['saved_path']):
        return jsonify({"error": "Video file not found on server"}), 404
    
    if enhancement_type not in video_enhancer.enhancement_types:
        return jsonify({"error": "Invalid enhancement type"}), 400
    
    if g.current_user['credits'] < 1:
        return jsonify({"error": "Insufficient credits"}), 402
    
    # Create enhancement job
    job_id = await db_insert("jobs", {
        "user_id": g.current_user['user_id'],
        "upload_id": upload_id,
        "source_url" : upload['saved_path'],  
        "source_type" : "File"  , 
        "object_filter" : "All" , 
        "confidence" : "NONE" , 
        "frame_skip" : "Default",
        "status": "started",
        "credits_cost": 1 , 
        "started_at":  datetime.utcnow().isoformat() ,
        "completed_at" : "404",
        "expires_at" : "Unknown" , 
        "process_id": "NULL" ,      
        "task_name": enhancement_type,
        "time_taken" : "NULL" , 
        "error_message": json.dumps(params),
        
    })
    
    # Deduct credits
    #await db_update("users", {"credits": g.current_user['credits'] - 1}, {"id": g.current_user['id']})
    
    # Log user activity
    await db_insert("user_activity", {
        "user_id": g.current_user['id'],
        "action": "enhancement_started",
        "details": json.dumps({
            "job_id": job_id,
            "enhancement_type": enhancement_type,
            "upload_id": upload_id
        }),
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get('User-Agent')
    })
    
    # Start enhancement task
    task = asyncio.create_task(_run_enhancement(job_id, upload['saved_path'], enhancement_type, params))
    job_tasks[job_id] = task
    
    return jsonify({"success": True, "job_id": job_id})

@app.route('/enhancement/types')
async def get_enhancement_types():
    return jsonify({
        "enhancement_types": video_enhancer.enhancement_types
    })

# -------------------------
# Enhancement Task Runner
# -------------------------
async def _run_enhancement(job_id: int, video_path: str, enhancement_type: str, params: dict):
    try:
        start_time = time.time()
        
        # Update job status to running
        await db_update("enhancement_jobs", {
            "status": "running",
            "started_at": datetime.utcnow().isoformat()
        }, {"id": job_id})
        
        # Run enhancement
        output_path, thumbnail_path, processing_time = await video_enhancer.enhance_video(
            job_id, video_path, enhancement_type, params
        )
        
        file_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
        
        # Update job completion
        await db_update("enhancement_jobs", {
            "status": "completed",
            "progress": 100,
            "output_video_path": output_path,
            "output_thumbnail_path": thumbnail_path,
            "completed_at": datetime.utcnow().isoformat(),
            "time_taken": processing_time
        }, {"id": job_id})
        
        # Log completion
        await video_enhancer.log_trace(job_id, "🎉 Enhancement job completed successfully!")
        
    except Exception as e:
        error_msg = f"❌ Enhancement failed: {str(e)}"
        await video_enhancer.log_trace(job_id, error_msg, "error")
        
        await db_update("enhancement_jobs", {
            "status": "failed",
            "error_message": str(e),
            "completed_at": datetime.utcnow().isoformat()
        }, {"id": job_id})
    finally:
        job_tasks.pop(job_id, None)

# -------------------------
# Job Management Routes
# -------------------------
@app.route('/jobs')
@auth_required
async def list_enhanced_jobs():
    jobs = await db_query("""
        SELECT ej.*, u.filename as upload_filename 
        FROM enhancement_jobs ej
        LEFT JOIN uploads u ON ej.upload_id = u.id
        WHERE ej.user_id = ? 
        ORDER BY ej.created_at DESC
    """, (g.current_user['id'],))
    
    return jsonify({"jobs": jobs})

@app.route('/enhancement/jobs/<int:job_id>')
@auth_required
async def get_enhanced_job(job_id):
    job = await db_query_one("""
        SELECT ej.*, u.filename as upload_filename 
        FROM enhancement_jobs ej
        LEFT JOIN uploads u ON ej.upload_id = u.id
        WHERE ej.id = ? AND ej.user_id = ?
    """, (job_id, g.current_user['id']))
    
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    # Get logs for this job
    logs = await db_query("""
        SELECT * FROM logs 
        WHERE job_id = ? 
        ORDER BY created_at ASC
    """, (job_id,))
    
    return jsonify({"job": job, "logs": logs})

@app.route('/enhancements')
@auth_required
async def list_enhancements():
    enhancements = await db_query("""
        SELECT ej.*, u.filename as original_filename
        FROM enhancement_jobs ej
        LEFT JOIN uploads u ON ej.upload_id = u.id
        WHERE ej.user_id = ? AND ej.status = 'completed'
        ORDER BY ej.created_at DESC
    """, (g.current_user['id'],))
    
    return jsonify({"enhancements": enhancements})

@app.route('/download/<int:job_id>')
@auth_required
async def download_enhancement(job_id):
    job = await db_query_one("""
        SELECT * FROM enhancement_jobs 
        WHERE id = ? AND user_id = ?
    """, (job_id, g.current_user['id']))
    
    if not job or not job.get('output_video_path') or not os.path.exists(job['output_video_path']):
        return jsonify({"error": "Enhanced video not found"}), 404
    
    return await send_file(
        job['output_video_path'],
        as_attachment=True,
        download_name=f"enhanced_{job_id}.mp4"
    )

# -------------------------
# WebSocket for Real-time Updates
# -------------------------
@app.websocket('/ws/<int:job_id>')
async def job_websocket(job_id):
    await websocket.accept()
    
    if job_id not in job_ws_clients:
        job_ws_clients[job_id] = []
    job_ws_clients[job_id].append(websocket)
    
    try:
        while True:
            data = await websocket.receive()
            if data == "ping":
                await websocket.send("pong")
    except Exception:
        pass
    finally:
        if job_id in job_ws_clients:
            job_ws_clients[job_id].remove(websocket)
            if not job_ws_clients[job_id]:
                del job_ws_clients[job_id]

# -------------------------
# -------------------------
# Main UI Route
# -------------------------
@app.route('/enhance')
@auth_required
async def enhancer():
    return await render_template("Enhancer-Protocol-Concept.html")







#####################################################################################################################################################
####################################################################  EOF  #########################################################################    
    
    
    
    
    
# HTML Templates
# Enhanced_Dashboard_Html Removed 


# Upload HTML Template



# Also add a simple test route to verify the database is working
@app.route('/test-db')
async def test_db():
    """Test database connection and tables"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("SELECT 1")
            return jsonify({'status': 'Database connected successfully'})
    except Exception as e:
        return jsonify({'error': f'Database connection failed: {str(e)}'}), 500


# Add missing route for the interactive dashboard
@app.route('/analytics')
@auth_required
async def analytics_dashboard():
    """Advanced analytics dashboard"""
    return await render_template_string("Interactive-Motion-Controller.html" , user = g.current_user )



# Add missing route for the interactive dashboard
@app.route('/account/billing/')
@auth_required
async def Billing():
    """Advanced analytics dashboard"""
    return await render_template("Billing-Profile-Concept.html" , user = g.current_user )




@app.route("/Frame/Extractor/")
@auth_required
async def extractor():
    return await render_template('Frame-Extractor-Concept.html' , user = g.current_user )
  
@app.route("/upload/frame/", methods=["POST"])
@auth_required
async def upload_frame():
    """
    Chunked async upload with file hashing:
    - Accepts multipart/form-data with 'file' field.
    - Streams the werkzeug.FileStorage.stream in sync reads (1MB) and writes via aiofiles.
    - Calculates SHA256 hash of the uploaded file
    """
    try:
        files = await request.files
        if "file" not in files:
            return jsonify({"error": "No file field in form"}), 400
        
        file = files["file"]
        filename = file.filename or f"upload_{int(datetime.utcnow().timestamp())}"
        
        if not allowed_file(filename):
            return jsonify({"error": f"File type not allowed. Allowed: {ALLOWED_EXTENSIONS}"}), 400
        
        safe_name = f"{int(datetime.utcnow().timestamp())}_{filename.replace(' ', '_')}"
        save_path = os.path.join(UPLOAD_DIR, safe_name)
        
        # Stream read from werkzeug FileStorage .stream (synchronous) in chunks and write via aiofiles
        with file.stream as src:
            async with aiofiles.open(save_path, "wb") as out:
                while True:
                    chunk = src.read(1024 * 1024)  # 1 MB
                    if not chunk:
                        break
                    await out.write(chunk)
        
        size = os.path.getsize(save_path)
        # Calculate file hash
        file_hash = await calculate_file_hash(save_path)
        
        upload_id = await db_insert("uploads", {
            "id": random.randrange(10000000000),
            "user_id" : g.current_user['user_id'],
            "filename": filename,
            "saved_path": save_path,
            "size_bytes": size,
            "file_hash": file_hash ,
            "upload_method": "file" ,
            "created_at" : datetime.utcnow().isoformat()
        })
        
        await log(upload_id, "info", f"Uploaded file {filename} saved as {save_path} (hash: {file_hash[:16]}...)")
        return jsonify({
            "upload_id": upload_id , 
            "filename": filename, 
            "saved_path": save_path,
            "file_hash": file_hash,
            "size_bytes": size
        })
        
    except Exception as e:
        await log(None, "error", f"Upload failed: {e}")
        return jsonify({"error": str(e)}), 500

# Add export functionality
@app.route('/api/export/json/<int:job_id>')
@auth_required
async def export_json(job_id):
    """Export analysis results as JSON"""
    
    user_id = g.current_user['user_id']
    
    results = await get_motion_results(job_id, user_id)
    
    if not results:
        return jsonify({'error': 'Job not found'}), 404
    
    return jsonify(results['analysis_summary'])

@app.route('/api/export/report/<int:job_id>')
@auth_required
async def export_report(job_id):
    """Generate PDF report (placeholder)"""
    return jsonify({'message': 'PDF report generation would be implemented here'})

# Add error handling middleware
@app.errorhandler(404)
@auth_required
async def not_found(error):
    return await render_template_string("""
        <div class="min-h-screen bg-gray-100 flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-800">404</h1>
                <p class="text-xl text-gray-600 mb-4">Page not found</p>
                <a href="/" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg">
                    Return to Dashboard
                </a>
            </div>
        </div>
    """), 404

@app.errorhandler(500)
async def internal_error(error):
    return await render_template_string("""
        <div class="min-h-screen bg-gray-100 flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-800">500</h1>
                <p class="text-xl text-gray-600 mb-4">Internal server error</p>
                <a href="/" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg">
                    Return to Dashboard
                </a>
            </div>
        </div>
    """), 500


# -------------------------
# Application Startup and Cleanup
# -------------------------
@app.before_serving
async def startup():
    """Initialize application"""
    await init_enhanced_db()
     # Start background cleanup task
    asyncio.create_task(cleanup_expired_task())
    print("[startup] Background cleanup task started")
    
    # Test Rust wallet connector
    try:
        connector = get_wallet_connector()
        if connector.health_check():
            print("✓ Rust wallet connector initialized successfully")
        else:
            print("⚠ Rust wallet connector health check failed")
    except Exception as e:
        print(f"⚠ Rust wallet connector not available: {e}")
    
    print("Forensic Video Analysis Platform started!")
    print("Access the application at: http://localhost:5000")
    print("Default admin credentials: admin/admin123")

@app.after_serving
async def cleanup():
    """Cleanup resources"""
    close_wallet_connector()


# Add health check endpoint
@app.route('/health/sys/')
async def health_check():
    """Health check endpoint for Docker and Render"""
    try:
        # Check database connection
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("SELECT 1")
        
        # System info
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "Forensic Video Analysis Platform",
            "version": "2.0.0",
            "system": {
                "memory_used": f"{memory.percent}%",
                "disk_used": f"{disk.percent}%",
                "python_version": os.environ.get('PYTHON_VERSION', '3.11.0')
            },
            "database": "connected",
            "endpoints": {
                "websocket": "active",
                "authentication": "active",
                "video_processing": "active"
            }
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

# Add this to ensure the app binds to the correct port
# Add this to the END of your master.py file
if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
