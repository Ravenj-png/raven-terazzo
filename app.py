# ==========================================
# TARAZO BACKEND - COMPLETE WITH REDIS + RATE LIMITING
# ==========================================

import os
import re
import json
import secrets
import logging
import smtplib
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_talisman import Talisman
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies
)
from flask_wtf.csrf import CSRFProtect
from marshmallow import Schema, fields, validate, ValidationError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet
import google.generativeai as genai
import cloudinary
import cloudinary.uploader
import requests
from dotenv import load_dotenv

# Redis and Rate Limiting imports
import redis
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables
load_dotenv()

# ==========================================
# APP CONFIGURATION
# ==========================================
app = Flask(__name__)

# Security configurations - ALL from env with fallbacks for dev only
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
app.config['JWT_COOKIE_SECURE'] = os.environ.get('JWT_COOKIE_SECURE', 'false').lower() == 'true'
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_CSRF_IN_COOKIES'] = True

# Session security
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# File upload limits
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['MAX_FORM_MEMORY_SIZE'] = 1024 * 1024

# Database - Hybrid (PostgreSQL or SQLite)
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    database_url = 'sqlite:///tarazo.db'
    print("ℹ️ Using SQLite database (no DATABASE_URL in env)")
elif database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
    print("✅ Using PostgreSQL database")
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CORS - ALL from env
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:5500,http://localhost:5000').split(',')

# In your Flask app.py, update CORS configuration:
CORS(app, 
     resources={r"/api/*": {
         "origins": ["https://ravenj-png.github.io", "http://localhost:5500", "http://localhost:5000"],
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Content-Type", "Authorization", "X-CSRFToken"],
         "supports_credentials": True,
         "expose_headers": ["Set-Cookie"]
     }})

# CSRF Protection
csrf = CSRFProtect()
csrf.init_app(app)

# ==========================================
# REDIS CONFIGURATION (optional - from env)
# ==========================================
REDIS_URL = os.environ.get('REDIS_URL')
redis_client = None

if REDIS_URL:
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
        print("✅ Redis connected")
    except Exception as e:
        print(f"⚠️ Redis not available: {e}")
        redis_client = None
else:
    print("ℹ️ No REDIS_URL, running without Redis")

# ==========================================
# RATE LIMITING (optional - from env)
# ==========================================
ENABLE_RATE_LIMIT = os.environ.get('ENABLE_RATE_LIMIT', 'false').lower() == 'true'
limiter = None

if ENABLE_RATE_LIMIT and redis_client:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour", "5 per minute"],
        storage_uri=REDIS_URL,
        strategy="fixed-window"
    )
    print("✅ Rate limiting enabled with Redis")
elif ENABLE_RATE_LIMIT:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour", "5 per minute"],
        storage_uri="memory://"
    )
    print("⚠️ Rate limiting with memory storage")
else:
    print("ℹ️ Rate limiting disabled")

# ==========================================
# SECURITY HEADERS (optional - from env)
# ==========================================
if os.environ.get('FLASK_ENV') == 'production':
    Talisman(
        app,
        force_https=True,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        referrer_policy='strict-origin-when-cross-origin',
        session_cookie_secure=True,
        session_cookie_http_only=True
    )
    print("✅ Talisman security enabled")

# ==========================================
# JWT SETUP
# ==========================================
jwt = JWTManager(app)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Argon2 Password Hashing
ph = PasswordHasher(time_cost=2, memory_cost=1024, parallelism=2)

# Token serializer for email verification
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Encryption for PII - ALL from env
encryption_key = os.environ.get('ENCRYPTION_KEY')
if encryption_key:
    cipher = Fernet(encryption_key.encode())
    print("✅ Encryption enabled")
else:
    cipher = Fernet(Fernet.generate_key())
    print("⚠️ No ENCRYPTION_KEY, using generated key")

# ==========================================
# GEMINI AI CONFIGURATION - ALL from env
# ==========================================
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    customer_model = genai.GenerativeModel('gemini-1.5-flash')
    agent_model = genai.GenerativeModel('gemini-1.5-flash')
    print("✅ Gemini AI enabled")
else:
    customer_model = None
    agent_model = None
    print("⚠️ No GEMINI_API_KEY, AI features disabled")

# AI Prompts
CUSTOMER_AI_PROMPT = """
You are Tarazo Assistant, a helpful AI for a terrazzo company in Uganda.
Answer questions about:
- Terrazzo prices (Floor: UGX 150,000/m², Wall: UGX 120,000/m², Countertop: UGX 280,000/m²)
- Delivery (2-5 days, free over UGX 500,000)
- Installation process (requires professional, takes 3-7 days)
- Products available (Floor, Wall, Countertop, Outdoor terrazzo)
- Payment methods (MTN Mobile Money, Airtel Money, Bank Card)

Be friendly, professional, and use local Ugandan English.
Keep responses short and helpful.
If you don't know something, say "Let me connect you to a live agent."
"""

AGENT_AI_PROMPT = """
You are Tarazo Agent Assistant, helping customer support agents.
Help agents:
- Draft professional replies to customer queries
- Answer technical questions about terrazzo installation and products
- Suggest next steps for order processing
- Provide product specifications when asked

Keep responses short, actionable, and professional.
"""

# ==========================================
# CLOUDINARY CONFIGURATION - ALL from env
# ==========================================
CLOUDINARY_CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME')
CLOUDINARY_API_KEY = os.environ.get('CLOUDINARY_API_KEY')
CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')

if CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET:
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET
    )
    print("✅ Cloudinary enabled")
else:
    print("⚠️ Cloudinary not configured")

# ==========================================
# FLUTTERWAVE CONFIGURATION - ALL from env
# ==========================================
FLUTTERWAVE_PUBLIC_KEY = os.environ.get('FLUTTERWAVE_PUBLIC_KEY')
FLUTTERWAVE_SECRET_KEY = os.environ.get('FLUTTERWAVE_SECRET_KEY')
FLUTTERWAVE_ENCRYPTION_KEY = os.environ.get('FLUTTERWAVE_ENCRYPTION_KEY')
FLUTTERWAVE_BASE_URL = 'https://api.flutterwave.com/v3'

if FLUTTERWAVE_PUBLIC_KEY and FLUTTERWAVE_SECRET_KEY:
    print("✅ Flutterwave enabled")
else:
    print("⚠️ Flutterwave not configured")

# ==========================================
# EMAIL CONFIGURATION - ALL from env
# ==========================================
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASS = os.environ.get('SMTP_PASS')

if SMTP_USER and SMTP_PASS:
    print("✅ Email service enabled")
else:
    print("⚠️ Email not configured")

# ==========================================
# DATABASE MODELS
# ==========================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    status = db.Column(db.String(20), default='online')
    address = db.Column(db.String(500))
    email_verified = db.Column(db.Boolean, default=False)
    email_verify_token = db.Column(db.String(255))
    reset_token = db.Column(db.String(255))
    reset_token_expires = db.Column(db.DateTime)
    force_password_change = db.Column(db.Boolean, default=False)
    last_password_change = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    install_images = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    items = db.Column(db.Text, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='paid')
    payment_method = db.Column(db.String(50))
    payment_ref = db.Column(db.String(100))
    payment_details = db.Column(db.Text)
    rider_name = db.Column(db.String(100))
    rider_phone = db.Column(db.String(20))
    rider_vehicle = db.Column(db.String(100))
    delivery_location = db.Column(db.String(500))
    delivery_notes = db.Column(db.Text)
    date = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Chat(db.Model):
    __tablename__ = 'chats'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    message = db.Column(db.Text, nullable=False)
    is_from_user = db.Column(db.Boolean, default=True)
    is_ai_generated = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(50), default='pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    type = db.Column(db.String(50))
    link = db.Column(db.String(500))
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==========================================
# AUTO-CREATE ADMIN & AGENTS FROM .env
# ==========================================

def create_default_accounts():
    """Create admin and agent accounts from environment variables"""
    
    # Create Admin from env
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    admin_name = os.environ.get('ADMIN_NAME', 'Administrator')
    admin_phone = os.environ.get('ADMIN_PHONE', '0771000000')
    
    if admin_email and admin_password:
        admin = User.query.filter_by(email=admin_email).first()
        if not admin:
            admin = User(
                name=admin_name,
                email=admin_email,
                phone=admin_phone,
                password_hash=ph.hash(admin_password),
                role='admin',
                status='online',
                email_verified=True
            )
            db.session.add(admin)
            print(f"✅ Admin account created: {admin_email}")
        else:
            print(f"ℹ️ Admin already exists: {admin_email}")
    else:
        print("ℹ️ No ADMIN_EMAIL/ADMIN_PASSWORD in env, skipping admin creation")
    
    # Create Agents from env (supports up to 10 agents)
    for i in range(1, 11):
        agent_email = os.environ.get(f'AGENT{i}_EMAIL')
        agent_password = os.environ.get(f'AGENT{i}_PASSWORD')
        
        if agent_email and agent_password:
            agent = User.query.filter_by(email=agent_email).first()
            if not agent:
                agent_name = os.environ.get(f'AGENT{i}_NAME', f'Agent {i}')
                agent_phone = os.environ.get(f'AGENT{i}_PHONE', f'077{i}00000')
                
                agent = User(
                    name=agent_name,
                    email=agent_email,
                    phone=agent_phone,
                    password_hash=ph.hash(agent_password),
                    role='agent',
                    status='online',
                    email_verified=True
                )
                db.session.add(agent)
                print(f"✅ Agent account created: {agent_email}")
            else:
                print(f"ℹ️ Agent already exists: {agent_email}")
    
    db.session.commit()

# ==========================================
# SECURITY UTILITIES
# ==========================================

failed_attempts = defaultdict(list)

def check_brute_force(ip):
    now = datetime.utcnow()
    failed_attempts[ip] = [t for t in failed_attempts[ip] if t > now - timedelta(hours=1)]
    return len(failed_attempts[ip]) < 10

def record_failed_attempt(ip):
    failed_attempts[ip].append(datetime.utcnow())

SQL_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)",
    r"(;\s*--|--\s*;|/\*|\*/)",
    r"('.*OR.*'.*=.*')",
    r"(\bOR\b.*=.*\bOR\b)",
]

def detect_sql_injection(data):
    input_str = str(data).lower()
    for pattern in SQL_PATTERNS:
        if re.search(pattern, input_str, re.IGNORECASE):
            return True
    return False

def sanitize_input(text, max_length=5000):
    if not text or not isinstance(text, str):
        return ""
    from markupsafe import escape
    text = escape(text)
    return text[:max_length]

def log_security_event(event_type, user_id, ip, details):
    app.logger.warning(f"SECURITY: {event_type} | User: {user_id} | IP: {ip} | {details}")
    if user_id:
        audit = AuditLog(
            user_id=user_id,
            action=event_type,
            details=details,
            ip_address=ip,
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.add(audit)
        db.session.commit()

def mask_email(email):
    if not email or '@' not in email:
        return email
    local, domain = email.split('@')
    if len(local) <= 2:
        return '*' * len(local) + '@' + domain
    return local[0] + '*' * (len(local)-2) + local[-1] + '@' + domain

ADMIN_IP_WHITELIST = os.environ.get('ADMIN_IP_WHITELIST', '').split(',')

def admin_ip_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if ADMIN_IP_WHITELIST and ADMIN_IP_WHITELIST[0]:
            if request.remote_addr not in ADMIN_IP_WHITELIST:
                log_security_event('UNAUTHORIZED_ADMIN_ACCESS', None, request.remote_addr, "IP not whitelisted")
                return jsonify({'error': 'Access denied'}), 403
        return f(*args, **kwargs)
    return decorated

def role_required(required_role):
    def wrapper(f):
        @wraps(f)
        @jwt_required()
        def decorated(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            if user.role != required_role and user.role != 'admin':
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return wrapper

def add_to_blacklist(jti):
    blacklist = TokenBlacklist(jti=jti)
    db.session.add(blacklist)
    db.session.commit()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token is not None

def rate_limit(limits):
    if limiter:
        return limiter.limit(limits)
    return lambda x: x

# ==========================================
# VALIDATION SCHEMAS
# ==========================================

class RegisterSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=2, max=100))
    email = fields.Email(required=True, validate=validate.Length(max=255))
    password = fields.Str(required=True, validate=validate.Length(min=8, max=128))
    phone = fields.Str(validate=validate.Regexp(r'^\+?[0-9]{9,15}$'))

class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)

# ==========================================
# EMAIL FUNCTIONS
# ==========================================

def send_email(to_email, subject, html_content):
    if not SMTP_USER or not SMTP_PASS:
        app.logger.warning("SMTP not configured")
        return False
    
    try:
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = to_email
        msg.attach(MIMEText(html_content, 'html'))
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        
        app.logger.info(f"Email sent to {mask_email(to_email)}")
        return True
    except Exception as e:
        app.logger.error(f"Email failed: {e}")
        return False

def send_verification_email(user):
    if not SMTP_USER:
        return False
    token = serializer.dumps(user.email, salt='email-verify')
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:5500')
    verification_url = f"{frontend_url}/verify-email/{token}"
    
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
        <h2>Welcome to Tarazo!</h2>
        <p>Please verify your email address by clicking the link below:</p>
        <a href="{verification_url}">Verify Email</a>
        <p>This link expires in 24 hours.</p>
        <p>Thank you for choosing Tarazo Premium Terrazzo!</p>
    </body>
    </html>
    """
    return send_email(user.email, "Verify Your Tarazo Account", html)

def send_password_reset_email(user):
    if not SMTP_USER:
        return False
    token = serializer.dumps(user.email, salt='password-reset')
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:5500')
    reset_url = f"{frontend_url}/reset-password/{token}"
    
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
        <h2>Password Reset Request</h2>
        <p>Click the link below to reset your password:</p>
        <a href="{reset_url}">Reset Password</a>
        <p>This link expires in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
    </body>
    </html>
    """
    return send_email(user.email, "Reset Your Tarazo Password", html)

def send_order_confirmation(order, user):
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
        <h2>Order Confirmation #{order.id}</h2>
        <p>Thank you for your order, {user.name}!</p>
        <p><strong>Total:</strong> UGX {order.total:,.0f}</p>
        <p><strong>Status:</strong> {order.status}</p>
        <p>We will notify you when your order is processed.</p>
        <p>Thank you for shopping with Tarazo!</p>
    </body>
    </html>
    """
    return send_email(user.email, f"Tarazo Order #{order.id} Confirmation", html)

# ==========================================
# CLOUDINARY IMAGE UPLOAD
# ==========================================

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_to_cloudinary(file, folder='tarazo'):
    if not CLOUDINARY_CLOUD_NAME:
        return None
    try:
        upload_result = cloudinary.uploader.upload(
            file,
            folder=folder,
            allowed_formats=['jpg', 'png', 'jpeg', 'webp'],
            transformation=[{'quality': 'auto', 'fetch_format': 'auto'}]
        )
        return upload_result['secure_url']
    except Exception as e:
        app.logger.error(f"Cloudinary upload failed: {e}")
        return None

# ==========================================
# FLUTTERWAVE PAYMENTS
# ==========================================

def initiate_flutterwave_payment(amount, email, phone, name, order_id):
    if not FLUTTERWAVE_SECRET_KEY:
        return None
    
    headers = {
        'Authorization': f'Bearer {FLUTTERWAVE_SECRET_KEY}',
        'Content-Type': 'application/json'
    }
    
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:5500')
    
    data = {
        'tx_ref': f'TX-{order_id}-{int(datetime.utcnow().timestamp())}',
        'amount': amount,
        'currency': 'UGX',
        'payment_options': 'card,mobilemoneyuganda',
        'redirect_url': f"{frontend_url}/payment-callback",
        'customer': {
            'email': email,
            'phonenumber': phone,
            'name': name
        },
        'customizations': {
            'title': 'Tarazo Premium Terrazzo',
            'description': f'Order #{order_id}',
            'logo': 'https://tarazo.com/logo.png'
        }
    }
    
    try:
        response = requests.post(f'{FLUTTERWAVE_BASE_URL}/payments', headers=headers, json=data, timeout=30)
        return response.json()
    except Exception as e:
        app.logger.error(f"Flutterwave error: {e}")
        return None

def verify_flutterwave_payment(tx_ref, transaction_id):
    if not FLUTTERWAVE_SECRET_KEY:
        return None
    
    headers = {
        'Authorization': f'Bearer {FLUTTERWAVE_SECRET_KEY}'
    }
    
    try:
        response = requests.get(f'{FLUTTERWAVE_BASE_URL}/transactions/{transaction_id}/verify', headers=headers, timeout=30)
        return response.json()
    except Exception as e:
        app.logger.error(f"Verification error: {e}")
        return None

# ==========================================
# GEMINI AI FUNCTIONS
# ==========================================

def get_ai_response(message, user_type='customer'):
    if not customer_model:
        return "AI features are currently disabled. Please contact support."
    
    try:
        if user_type == 'customer':
            prompt = f"{CUSTOMER_AI_PROMPT}\n\nCustomer: {message}\nAssistant:"
        else:
            prompt = f"{AGENT_AI_PROMPT}\n\nAgent ask: {message}\nAssistant:"
        
        response = customer_model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        app.logger.error(f"Gemini AI error: {e}")
        return "I'm having trouble connecting. Please try again or contact support."

# ==========================================
# MIDDLEWARE
# ==========================================

@app.before_request
def before_request():
    if request.is_json and request.get_json():
        if detect_sql_injection(request.get_json()):
            log_security_event('SQL_INJECTION_ATTEMPT', None, request.remote_addr, "Blocked JSON payload")
            return jsonify({'error': 'Invalid request'}), 400
    
    if request.endpoint == 'login':
        if not check_brute_force(request.remote_addr):
            return jsonify({'error': 'Too many attempts. Try again later.'}), 429

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ==========================================
# CSRF TOKEN ROUTE
# ==========================================

@app.route('/api/csrf-token', methods=['GET'])
@csrf.exempt
def get_csrf_token():
    """Return a CSRF token for the frontend"""
    from flask_wtf.csrf import generate_csrf
    return jsonify({'csrf_token': generate_csrf()})

# ==========================================
# AUTHENTICATION ROUTES
# ==========================================

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0',
        'rate_limiting_enabled': ENABLE_RATE_LIMIT,
        'redis_available': redis_client is not None
    })

@app.route('/api/register', methods=['POST'])
@csrf.exempt
@rate_limit("3 per minute")
def register():
    data = request.get_json()
    
    schema = RegisterSchema()
    try:
        validated = schema.load(data)
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    
    if User.query.filter_by(email=validated['email']).first():
        return jsonify({'error': 'Email already registered'}), 409
    
    password_hash = ph.hash(validated['password'])
    
    user = User(
        name=validated['name'],
        email=validated['email'],
        phone=validated.get('phone'),
        password_hash=password_hash,
        role='user'
    )
    
    db.session.add(user)
    db.session.commit()
    
    send_verification_email(user)
    
    log_security_event('USER_REGISTERED', user.id, request.remote_addr, f"Email: {mask_email(user.email)}")
    
    return jsonify({
        'success': True,
        'message': 'Registration successful. Please check your email for verification.'
    }), 201

@app.route('/api/verify-email/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=86400)
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.email_verified = True
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Email verified successfully'})
    except:
        return jsonify({'error': 'Invalid or expired token'}), 400

@app.route('/api/login', methods=['POST'])
@csrf.exempt
@rate_limit("5 per minute")
def login():
    data = request.get_json()
    
    schema = LoginSchema()
    try:
        validated = schema.load(data)
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    
    user = User.query.filter_by(email=validated['email']).first()
    
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({'error': 'Account locked. Try again later.'}), 403
    
    if not user:
        record_failed_attempt(request.remote_addr)
        return jsonify({'error': 'Invalid email or password'}), 401
    
    try:
        ph.verify(user.password_hash, validated['password'])
    except VerifyMismatchError:
        record_failed_attempt(request.remote_addr)
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 10:
            user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()
        return jsonify({'error': 'Invalid email or password'}), 401
    
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()
    
    if not user.email_verified:
        return jsonify({'error': 'Please verify your email first'}), 403
    
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    log_security_event('USER_LOGIN', user.id, request.remote_addr, f"Role: {user.role}")
    
    response = jsonify({
        'success': True,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'phone': user.phone,
            'address': user.address
        }
    })
    
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    
    return response

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=user_id)
    
    response = jsonify({'success': True})
    set_access_cookies(response, access_token)
    return response

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    add_to_blacklist(jti)
    
    response = jsonify({'success': True, 'message': 'Logged out successfully'})
    unset_jwt_cookies(response)
    return response

@app.route('/api/forgot-password', methods=['POST'])
@csrf.exempt
@rate_limit("3 per hour")
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    
    if user:
        send_password_reset_email(user)
        log_security_event('PASSWORD_RESET_REQUEST', user.id, request.remote_addr, "Reset requested")
    
    return jsonify({'message': 'If an account exists, a reset link has been sent'})

@app.route('/api/reset-password', methods=['POST'])
@rate_limit("3 per hour")
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('password')
    
    if not new_password or len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({'error': 'Invalid token'}), 400
        
        user.password_hash = ph.hash(new_password)
        user.force_password_change = False
        user.last_password_change = datetime.utcnow()
        db.session.commit()
        
        log_security_event('PASSWORD_RESET_SUCCESS', user.id, request.remote_addr, "Password changed")
        
        return jsonify({'success': True, 'message': 'Password reset successful'})
    except:
        return jsonify({'error': 'Invalid or expired token'}), 400

# ==========================================
# PRODUCT ROUTES
# ==========================================

@app.route('/api/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'type': p.type,
        'price': p.price,
        'stock': p.stock,
        'description': p.description,
        'image': p.image_url,
        'install': json.loads(p.install_images) if p.install_images else []
    } for p in products])

@app.route('/api/products', methods=['POST'])
@jwt_required()
@role_required('admin')
@rate_limit("10 per hour")
def create_product():
    data = request.form
    
    if not data.get('name') or not data.get('price'):
        return jsonify({'error': 'Name and price required'}), 400
    
    image_url = None
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            image_url = upload_to_cloudinary(file, 'tarazo/products')
    
    install_urls = []
    for i in range(1, 5):
        key = f'install_{i}'
        if key in request.files:
            file = request.files[key]
            if file and allowed_file(file.filename):
                url = upload_to_cloudinary(file, 'tarazo/installations')
                if url:
                    install_urls.append(url)
    
    product = Product(
        name=sanitize_input(data['name']),
        type=sanitize_input(data.get('type', 'General')),
        price=int(data['price']),
        stock=int(data.get('stock', 0)),
        description=sanitize_input(data.get('description', '')),
        image_url=image_url,
        install_images=json.dumps(install_urls)
    )
    
    db.session.add(product)
    db.session.commit()
    
    return jsonify({'success': True, 'product_id': product.id}), 201

# ==========================================
# AI CHAT ROUTES
# ==========================================

@app.route('/api/chat/customer', methods=['POST'])
@rate_limit("30 per minute")
def customer_chat():
    data = request.get_json()
    message = data.get('message', '')
    
    if not message:
        return jsonify({'error': 'Message required'}), 400
    
    ai_response = get_ai_response(sanitize_input(message), 'customer')
    
    user_id = None
    try:
        user_id = get_jwt_identity()
    except:
        pass
    
    if user_id:
        chat = Chat(
            user_id=user_id,
            message=sanitize_input(message),
            is_from_user=True
        )
        db.session.add(chat)
        
        chat = Chat(
            user_id=user_id,
            message=ai_response,
            is_from_user=False,
            is_ai_generated=True
        )
        db.session.add(chat)
        db.session.commit()
    
    return jsonify({'response': ai_response})

@app.route('/api/chat/agent', methods=['POST'])
@jwt_required()
@role_required('agent')
def agent_chat():
    data = request.get_json()
    message = data.get('message', '')
    
    if not message:
        return jsonify({'error': 'Message required'}), 400
    
    ai_response = get_ai_response(sanitize_input(message), 'agent')
    
    return jsonify({'response': ai_response})

@app.route('/api/chat/conversations', methods=['GET'])
@jwt_required()
def get_conversations():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role == 'admin':
        chats = Chat.query.order_by(Chat.timestamp.desc()).limit(100).all()
    elif user.role == 'agent':
        chats = Chat.query.filter(
            (Chat.agent_id == user_id) | (Chat.agent_id.is_(None))
        ).order_by(Chat.timestamp.desc()).limit(100).all()
    else:
        chats = Chat.query.filter_by(user_id=user_id).order_by(Chat.timestamp.desc()).all()
    
    return jsonify([{
        'id': c.id,
        'user_id': c.user_id,
        'message': c.message,
        'is_from_user': c.is_from_user,
        'timestamp': c.timestamp.isoformat()
    } for c in chats])

# ==========================================
# ORDER ROUTES
# ==========================================

@app.route('/api/orders', methods=['POST'])
@jwt_required()
@rate_limit("10 per hour")
def create_order():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    items = data.get('items', [])
    total = data.get('total', 0)
    payment_method = data.get('payment_method', 'MTN Mobile Money')
    
    order = Order(
        user_id=user_id,
        items=json.dumps(items),
        total=total,
        status='paid',
        payment_method=sanitize_input(payment_method),
        date=datetime.utcnow().strftime('%Y-%m-%d'),
        payment_ref=f'ORD-{int(datetime.utcnow().timestamp())}'
    )
    
    db.session.add(order)
    db.session.commit()
    
    admin = User.query.filter_by(role='admin').first()
    if admin:
        notif = Notification(
            user_id=admin.id,
            title='New Order',
            message=f'Order #{order.id} for UGX {total:,.0f}',
            type='order',
            link='adminOrders'
        )
        db.session.add(notif)
    
    available_agents = User.query.filter_by(role='agent', status='online').all()
    if available_agents:
        order_counts = {}
        for agent in available_agents:
            count = Order.query.filter_by(agent_id=agent.id).filter(Order.status.in_(['paid', 'processing'])).count()
            order_counts[agent.id] = count
        
        best_agent = min(available_agents, key=lambda a: order_counts.get(a.id, 0))
        order.agent_id = best_agent.id
        
        notif = Notification(
            user_id=best_agent.id,
            title='New Order Assigned',
            message=f'Order #{order.id} has been assigned to you',
            type='order',
            link='agentPanel'
        )
        db.session.add(notif)
    
    db.session.commit()
    
    user = User.query.get(user_id)
    send_order_confirmation(order, user)
    
    return jsonify({'success': True, 'order_id': order.id}), 201

@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role == 'admin':
        orders = Order.query.order_by(Order.created_at.desc()).all()
    elif user.role == 'agent':
        orders = Order.query.filter(
            (Order.agent_id == user_id) | (Order.agent_id.is_(None) & (Order.status == 'paid'))
        ).order_by(Order.created_at.desc()).all()
    else:
        orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
    
    return jsonify([{
        'id': o.id,
        'user_id': o.user_id,
        'items': json.loads(o.items),
        'total': o.total,
        'status': o.status,
        'payment_method': o.payment_method,
        'rider_name': o.rider_name,
        'rider_phone': o.rider_phone,
        'rider_vehicle': o.rider_vehicle,
        'delivery_location': o.delivery_location,
        'delivery_notes': o.delivery_notes,
        'date': o.date
    } for o in orders])

@app.route('/api/orders/<int:order_id>/assign', methods=['PUT'])
@jwt_required()
@role_required('agent')
def assign_rider(order_id):
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    
    order.rider_name = sanitize_input(data.get('rider_name', ''))
    order.rider_phone = sanitize_input(data.get('rider_phone', ''))
    order.rider_vehicle = sanitize_input(data.get('rider_vehicle', ''))
    order.delivery_location = sanitize_input(data.get('delivery_location', ''))
    order.delivery_notes = sanitize_input(data.get('delivery_notes', ''))
    
    if order.status == 'paid':
        order.status = 'processing'
    
    db.session.commit()
    
    notif = Notification(
        user_id=order.user_id,
        title='Rider Assigned',
        message=f'Your order #{order.id} has been assigned to {order.rider_name}',
        type='delivery',
        link='userOrders'
    )
    db.session.add(notif)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/orders/<int:order_id>/status', methods=['PUT'])
@jwt_required()
def update_order_status(order_id):
    data = request.get_json()
    new_status = data.get('status')
    order = Order.query.get_or_404(order_id)
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role != 'admin' and (user.role == 'agent' and order.agent_id != user_id):
        return jsonify({'error': 'Permission denied'}), 403
    
    order.status = new_status
    db.session.commit()
    
    if order.user_id:
        notif = Notification(
            user_id=order.user_id,
            title='Order Update',
            message=f'Your order #{order.id} is now {new_status}',
            type='order',
            link='userOrders'
        )
        db.session.add(notif)
        db.session.commit()
    
    return jsonify({'success': True})

# ==========================================
# NOTIFICATION ROUTES
# ==========================================

@app.route('/api/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(50).all()
    
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.type,
        'link': n.link,
        'read': n.read,
        'created_at': n.created_at.isoformat()
    } for n in notifications])

@app.route('/api/notifications/<int:notif_id>/read', methods=['PUT'])
@jwt_required()
def mark_notification_read(notif_id):
    user_id = get_jwt_identity()
    notif = Notification.query.get_or_404(notif_id)
    
    if notif.user_id != user_id:
        return jsonify({'error': 'Permission denied'}), 403
    
    notif.read = True
    db.session.commit()
    
    return jsonify({'success': True})

# ==========================================
# PAYMENT ROUTES
# ==========================================

@app.route('/api/payment/initiate', methods=['POST'])
@jwt_required()
@rate_limit("5 per hour")
def initiate_payment():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json()
    
    amount = data.get('amount')
    order_id = data.get('order_id')
    
    result = initiate_flutterwave_payment(
        amount=amount,
        email=user.email,
        phone=user.phone,
        name=user.name,
        order_id=order_id
    )
    
    if result and result.get('status') == 'success':
        return jsonify({
            'success': True,
            'payment_link': result['data']['link'],
            'transaction_ref': result['data']['tx_ref']
        })
    
    return jsonify({'error': 'Payment initiation failed'}), 400

@app.route('/api/payment/webhook', methods=['POST'])
def flutterwave_webhook():
    signature = request.headers.get('verif-hash')
    expected_signature = os.environ.get('FLUTTERWAVE_WEBHOOK_SECRET')
    
    if expected_signature and signature != expected_signature:
        log_security_event('INVALID_WEBHOOK', None, request.remote_addr, "Invalid signature")
        return jsonify({'error': 'Invalid signature'}), 401
    
    data = request.json
    
    if data.get('status') == 'successful':
        tx_ref = data.get('tx_ref')
        transaction_id = data.get('transaction_id')
        
        verification = verify_flutterwave_payment(tx_ref, transaction_id)
        
        if verification and verification.get('status') == 'success':
            order_id = int(tx_ref.split('-')[1])
            order = Order.query.get(order_id)
            
            if order:
                order.status = 'paid'
                order.payment_ref = transaction_id
                order.payment_details = json.dumps(data)
                db.session.commit()
                
                notif = Notification(
                    user_id=order.user_id,
                    title='Payment Successful',
                    message=f'Your payment for order #{order.id} has been confirmed',
                    type='order',
                    link='userOrders'
                )
                db.session.add(notif)
                db.session.commit()
    
    return jsonify({'status': 'ok'}), 200

# ==========================================
# ADMIN ROUTES
# ==========================================

@app.route('/api/admin/agents', methods=['GET'])
@jwt_required()
@role_required('admin')
@admin_ip_required
def get_agents():
    agents = User.query.filter_by(role='agent').all()
    
    return jsonify([{
        'id': a.id,
        'name': a.name,
        'email': a.email,
        'phone': a.phone,
        'status': a.status,
        'created_at': a.created_at.isoformat()
    } for a in agents])

@app.route('/api/admin/agents/<int:agent_id>/status', methods=['PUT'])
@jwt_required()
@role_required('admin')
@admin_ip_required
def update_agent_status(agent_id):
    data = request.get_json()
    new_status = data.get('status')
    
    agent = User.query.get_or_404(agent_id)
    agent.status = new_status
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/admin/stats', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_stats():
    today = datetime.utcnow().date()
    
    today_orders = Order.query.filter(
        db.func.date(Order.created_at) == today,
        Order.status != 'pending'
    ).all()
    today_sales = sum(o.total for o in today_orders)
    
    pending = Order.query.filter(Order.status.in_(['paid', 'processing'])).count()
    low_stock = Product.query.filter(Product.stock < 5).count()
    
    return jsonify({
        'today_sales': today_sales,
        'pending_orders': pending,
        'total_products': Product.query.count(),
        'low_stock': low_stock
    })

# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(429)
def rate_limit_exceeded(e):
    log_security_event('RATE_LIMIT', None, request.remote_addr, "Rate limit exceeded")
    return jsonify({'error': 'Too many requests. Please try again later.'}), 429

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ==========================================
# MAIN
# ==========================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_accounts()  # Auto-create admin/agents from .env
        print("✅ Database tables created")
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║                    TARAZO BACKEND                        ║
    ║                     Version 2.0.0                        ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Server running on: http://localhost:{port}              ║
    ║  Debug mode: {debug}                                       ║
    ║  Rate limiting: {'Enabled' if ENABLE_RATE_LIMIT else 'Disabled'}   ║
    ║  Redis: {'Connected' if redis_client else 'Not available'}        ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
