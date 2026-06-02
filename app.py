# WAMP BACKEND - VERSION 5 (FINAL)
# ================================================================

import os
import re
import json
import secrets
import logging
import hmac
import hashlib
import time
import base64
import csv
import io
import requests
import smtplib
from datetime import datetime, timedelta
from functools import wraps

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import func, text
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

# Cloudinary for image upload
import cloudinary
import cloudinary.uploader

# Redis for rate limiting
import redis

# Google Gemini AI
import google.generativeai as genai

load_dotenv()

# ==================== APP INITIALIZATION ====================
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app_start_time = datetime.utcnow()

# ==================== LOGGING ====================
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = re.sub(r'(077|078|076|079|075|074|070|073|071)\d{6}', '[PHONE]', record.msg)
            record.msg = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL]', record.msg)
        return True

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logger.addFilter(SensitiveDataFilter())

# ==================== CONFIGURATION ====================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key-change-in-production')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'fallback-jwt-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_IDENTITY_CLAIM'] = 'sub'

# Database
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    logger.error("❌ DATABASE_URL not set!")

if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 300,
    'pool_pre_ping': True,
}

# ==================== CLOUDINARY ====================
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME', ''),
    api_key=os.environ.get('CLOUDINARY_API_KEY', ''),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET', '')
)
CLOUDINARY_ENABLED = bool(os.environ.get('CLOUDINARY_API_KEY'))

# ==================== CORS ====================
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://ravenj-png.github.io,http://localhost:5500,http://localhost:5000,https://raven-terazzo.onrender.com').split(',')

CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
     expose_headers=["Content-Type", "Authorization"],
     max_age=3600)

# ==================== REDIS ====================
try:
    redis_url = os.environ.get('REDIS_URL')
    if redis_url:
        redis_client = redis.from_url(redis_url, socket_timeout=5, decode_responses=True)
        redis_client.ping()
        logger.info("✅ Redis connected")
    else:
        redis_client = None
except Exception as e:
    redis_client = None
    logger.warning(f"⚠️ Redis not available: {e}")

# ==================== GOOGLE GEMINI AI ====================
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
GEMINI_ENABLED = False

if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel('gemini-1.5-pro')
        GEMINI_ENABLED = True
        logger.info("✅ Google Gemini AI configured")
    except Exception as e:
        GEMINI_ENABLED = False
        logger.warning(f"⚠️ Gemini init failed: {e}")
else:
    logger.info("ℹ️ Gemini AI not configured")

# ==================== EXTENSIONS ====================
jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ph = PasswordHasher()
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ==================== BRUTE FORCE PROTECTION ====================
def record_failed_login(ip):
    if not redis_client: return
    try:
        key = f"login_attempts:{ip}"
        redis_client.lpush(key, time.time())
        redis_client.ltrim(key, 0, 9)
        redis_client.expire(key, 900)
    except:
        pass

def is_ip_blocked(ip):
    if not redis_client: return False
    try:
        key = f"login_attempts:{ip}"
        attempts = redis_client.lrange(key, 0, -1)
        recent = [float(a) for a in attempts if float(a) > time.time() - 900]
        return len(recent) >= 10
    except:
        return False

def reset_failed_attempts(ip):
    if not redis_client: return
    try:
        redis_client.delete(f"login_attempts:{ip}")
    except:
        pass

# ==================== DATABASE MODELS ====================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', index=True)
    status = db.Column(db.String(20), default='online')
    address = db.Column(db.String(500))
    email_verified = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False, index=True)
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)
    reserved_stock = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    image_data = db.Column(db.Text)
    image_type = db.Column(db.String(20), default='url')
    image_mime = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def available_stock(self):
        return self.stock - self.reserved_stock

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    items = db.Column(db.Text, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='pending', index=True)
    payment_method = db.Column(db.String(50))
    payment_status = db.Column(db.String(50), default='pending')
    transaction_id = db.Column(db.String(100), unique=True)
    stock_confirmed = db.Column(db.Boolean, default=False)
    stock_reserved_until = db.Column(db.DateTime, nullable=True)
    rider_name = db.Column(db.String(100))
    rider_phone = db.Column(db.String(20))
    delivery_location = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Rider(db.Model):
    __tablename__ = 'riders'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='available')  # available, busy
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Receipt(db.Model):
    __tablename__ = 'receipts'
    id = db.Column(db.Integer, primary_key=True)
    receipt_number = db.Column(db.String(100), unique=True, nullable=False, index=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    barcode_data = db.Column(db.String(500))
    barcode_image = db.Column(db.Text)
    pdf_url = db.Column(db.String(500))
    printed_count = db.Column(db.Integer, default=0)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    order = db.relationship('Order', backref='receipts', foreign_keys=[order_id])
    user = db.relationship('User', backref='receipts', foreign_keys=[user_id])

class CustomerChat(db.Model):
    __tablename__ = 'customer_chats'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(100), nullable=False, index=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    customer = db.relationship('User', foreign_keys=[customer_id])
    agent = db.relationship('User', foreign_keys=[agent_id])
    sender = db.relationship('User', foreign_keys=[sender_id])

class Wishlist(db.Model):
    __tablename__ = 'wishlist'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Review(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, index=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PaymentTransaction(db.Model):
    __tablename__ = 'payment_transactions'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'))
    tx_ref = db.Column(db.String(100), unique=True)
    transaction_id = db.Column(db.String(100), unique=True)
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(3), default='UGX')
    status = db.Column(db.String(50), default='pending')
    payment_method = db.Column(db.String(50))
    webhook_data = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Communication(db.Model):
    __tablename__ = 'communications'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AgentGroupMessage(db.Model):
    __tablename__ = 'agent_group_messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== JWT ERROR HANDLERS ====================
@jwt.unauthorized_loader
def custom_unauthorized_response(callback):
    return jsonify({'error': 'Authorization token missing'}), 401

@jwt.invalid_token_loader
def custom_invalid_token_response(error_string):
    return jsonify({'error': f'Invalid token: {error_string}'}), 422

@jwt.expired_token_loader
def custom_expired_token_response(jwt_header, jwt_payload):
    return jsonify({'error': 'Token expired', 'expired': True}), 401

@jwt.revoked_token_loader
def custom_revoked_token_response(jwt_header, jwt_payload):
    return jsonify({'error': 'Token revoked'}), 401

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return TokenBlacklist.query.filter_by(jti=jwt_payload['jti']).first() is not None

@jwt.user_identity_loader
def user_identity_lookup(user_id):
    return str(user_id)

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data.get("sub")
    if not identity: return None
    try:
        return User.query.get(int(identity))
    except:
        return None

# ==================== HELPER FUNCTIONS ====================
def log_audit(user_id, action, resource_type=None, resource_id=None):
    try:
        audit = AuditLog(
            user_id=user_id, action=action,
            resource_type=resource_type, resource_id=resource_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500]
        )
        db.session.add(audit)
        db.session.commit()
    except:
        pass

def send_notification(user_id, title, message):
    try:
        notif = Notification(user_id=user_id, title=title, message=message)
        db.session.add(notif)
        db.session.commit()
    except:
        pass

def get_least_busy_agent():
    agents = User.query.filter_by(role='agent', status='online').all()
    if not agents: return None
    loads = [(a, Order.query.filter(Order.agent_id == a.id, Order.status.in_(['paid', 'processing'])).count()) for a in agents]
    loads.sort(key=lambda x: (x[1], x[0].id))
    return loads[0][0]

def release_expired_reservations():
    expired = Order.query.filter(Order.stock_reserved_until < datetime.utcnow(), Order.stock_confirmed == False).all()
    for order in expired:
        items = json.loads(order.items) if order.items else []
        for item in items:
            product = Product.query.get(item['productId'])
            if product:
                product.reserved_stock -= item['quantity']
        order.stock_reserved_until = None
    db.session.commit()

def enrich_order(order):
    items = json.loads(order.items) if order.items else []
    enriched = []
    for item in items:
        p = Product.query.get(item.get('productId'))
        enriched.append({
            'name': p.name if p else 'Product',
            'price': p.price if p else 0,
            'quantity': item.get('quantity', 1),
            'product_id': item.get('productId')
        })
    return {
        'id': order.id, 'user_id': order.user_id, 'agent_id': order.agent_id,
        'total': order.total, 'status': order.status, 'payment_method': order.payment_method,
        'payment_status': order.payment_status, 'rider_name': order.rider_name,
        'rider_phone': order.rider_phone, 'delivery_location': order.delivery_location,
        'items': enriched, 'created_at': order.created_at.isoformat()
    }

def generate_receipt_number(order_id):
    return f"WAMP-{datetime.utcnow().year}-{order_id:06d}"

# ==================== DATABASE INIT ====================
def init_db():
    db.create_all()
    logger.info("✅ Tables created")
    release_expired_reservations()

    # Create agent group messages table if not exists
    try:
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS agent_group_messages (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER NOT NULL REFERENCES users(id),
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """))
        db.session.commit()
    except:
        db.session.rollback()

    # Admin account
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@wamp.com')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(
            name=os.environ.get('ADMIN_NAME', 'Admin'),
            email=admin_email,
            phone=os.environ.get('ADMIN_PHONE', '0771000000'),
            password_hash=ph.hash(admin_password),
            role='admin'
        )
        db.session.add(admin)
        logger.info(f"✅ Created admin: {admin_email}")
    else:
        admin.password_hash = ph.hash(admin_password)
        admin.role = 'admin'

    # Agents
    for i in range(1, 6):
        agent_email = os.environ.get(f'AGENT{i}_EMAIL')
        agent_password = os.environ.get(f'AGENT{i}_PASSWORD')
        if agent_email and agent_password:
            agent = User.query.filter_by(email=agent_email).first()
            if not agent:
                agent = User(
                    name=os.environ.get(f'AGENT{i}_NAME', f'Agent {i}'),
                    email=agent_email,
                    phone=os.environ.get(f'AGENT{i}_PHONE', f'077{i}000000'),
                    password_hash=ph.hash(agent_password),
                    role='agent'
                )
                db.session.add(agent)
                logger.info(f"✅ Created agent: {agent_email}")
            else:
                agent.password_hash = ph.hash(agent_password)
                agent.role = 'agent'

    db.session.commit()

with app.app_context():
    try:
        init_db()
    except Exception as e:
        logger.error(f"DB init failed: {e}")

# ==================== AUTH ROUTES ====================
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy', 'database': 'connected',
        'cloudinary': CLOUDINARY_ENABLED, 'gemini_ai': GEMINI_ENABLED,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    phone = data.get('phone', '').strip()

    if not name or not email or not password:
        return jsonify({'error': 'Missing fields'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email exists'}), 409

    user = User(name=name, email=email, phone=phone, password_hash=ph.hash(password), role='user')
    db.session.add(user)
    db.session.commit()
    log_audit(user.id, 'REGISTER')
    return jsonify({'success': True, 'message': 'Registration successful'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    client_ip = request.remote_addr
    if is_ip_blocked(client_ip):
        return jsonify({'error': 'Too many attempts'}), 429

    data = request.get_json()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()

    if not email or not password:
        return jsonify({'error': 'Credentials required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        record_failed_login(client_ip)
        return jsonify({'error': 'Invalid credentials'}), 401

    try:
        ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        record_failed_login(client_ip)
        return jsonify({'error': 'Invalid credentials'}), 401

    reset_failed_attempts(client_ip)
    remember_me = data.get('remember_me', False)
    if remember_me:
        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=30))
    else:
        access_token = create_access_token(identity=str(user.id))
        
    refresh_token = create_refresh_token(identity=str(user.id))
    log_audit(user.id, 'LOGIN')

    return jsonify({
        'success': True, 'access_token': access_token, 'refresh_token': refresh_token,
        'user': {'id': user.id, 'name': user.name, 'email': user.email, 'role': user.role, 'phone': user.phone, 'address': user.address}
    })

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip()
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': True, 'message': 'If email exists, reset link sent'})
    
    token = serializer.dumps(email, salt='password-reset-salt')
    reset_link = f"https://{request.host}/reset-password?token={token}"
    
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        smtp_user = os.environ.get('SMTP_USER')
        smtp_password = os.environ.get('SMTP_PASS', '').replace(' ', '')
        
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = email
        msg['Subject'] = 'Reset Your WAMP Password'
        msg.attach(MIMEText(f'Click link to reset: {reset_link}', 'html'))
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        
        return jsonify({'success': True, 'message': 'Reset link sent'})
    except Exception as e:
        return jsonify({'success': True, 'message': 'If email exists, reset link sent'})
        
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token', '')
    new_password = data.get('password', '').strip()
    
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return jsonify({'error': 'Invalid or expired token'}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.password_hash = ph.hash(new_password)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Password reset successful'})
    

@app.route('/api/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user:
        return jsonify({'valid': False}), 401
    return jsonify({'valid': True, 'user': {'id': user.id, 'email': user.email, 'role': user.role}})

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    return jsonify({'success': True, 'access_token': create_access_token(identity=str(get_jwt_identity()))})

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    db.session.add(TokenBlacklist(jti=get_jwt()['jti'], user_id=int(get_jwt_identity())))
    db.session.commit()
    return jsonify({'success': True})

# ==================== WHATSAPP CONTACTS ENDPOINT ====================
@app.route('/api/whatsapp/contacts', methods=['GET'])
def get_whatsapp_contacts():
    return jsonify({
        'manager': {
            'name': 'Manager',
            'number': os.environ.get('MANAGER_WHATSAPP', '256741227707'),
            'icon': '👑',
            'message': 'Hello Manager, I need assistance with WAMP Enterprises!'
        },
        'assistant': {
            'name': 'Support Assistant',
            'number': os.environ.get('ASSISTANT_WHATSAPP', '256741333544'),
            'icon': '🤖',
            'message': 'Hello Support, I need help with my order!'
        }
    })

# ==================== USER ROUTES ====================
@app.route('/api/user/profile', methods=['GET', 'PUT'])
@jwt_required()
def user_profile():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if request.method == 'GET':
        return jsonify({'id': user.id, 'name': user.name, 'email': user.email, 'phone': user.phone, 'address': user.address, 'role': user.role})
    data = request.get_json()
    user.name = data.get('name', user.name)
    user.phone = data.get('phone', user.phone)
    user.address = data.get('address', user.address)
    db.session.commit()
    return jsonify({'success': True, 'user': {'name': user.name, 'phone': user.phone, 'address': user.address}})

@app.route('/api/user/stats', methods=['GET'])
@jwt_required()
def user_stats():
    user_id = int(get_jwt_identity())
    total = Order.query.filter_by(user_id=user_id).count()
    pending = Order.query.filter_by(user_id=user_id, status='pending').count()
    delivered = Order.query.filter_by(user_id=user_id, status='delivered').count()
    spent = db.session.query(func.sum(Order.total)).filter_by(user_id=user_id, status='delivered').scalar() or 0
    return jsonify({'total_orders': total, 'pending_orders': pending, 'delivered_orders': delivered, 'total_spent': spent})

@app.route('/api/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = int(get_jwt_identity())
    notifs = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(50).all()
    unread = sum(1 for n in notifs if not n.is_read)
    return jsonify({
        'notifications': [{'id': n.id, 'title': n.title, 'message': n.message, 'is_read': n.is_read, 'date': n.created_at.isoformat()} for n in notifs],
        'unread_count': unread
    })

@app.route('/api/notifications/<int:nid>/read', methods=['POST'])
@jwt_required()
def mark_notification_read(nid):
    user_id = int(get_jwt_identity())
    n = Notification.query.get_or_404(nid)
    if n.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    n.is_read = True
    db.session.commit()
    return jsonify({'success': True})

# ==================== PRODUCT ROUTES ====================
@app.route('/api/products', methods=['GET'])
def get_products():
    release_expired_reservations()
    products = Product.query.all()
    result = []
    for p in products:
        data = {
            'id': p.id, 'name': p.name, 'category': p.category, 'price': p.price,
            'stock': p.available_stock, 'description': p.description or '', 'image_type': p.image_type
        }
        if p.image_type == 'cloudinary' and p.image_url:
            data['image_url'] = p.image_url
        elif p.image_type == 'db' and p.image_data:
            data['image_data'] = p.image_data
            data['image_mime'] = p.image_mime
        else:
            data['image_url'] = p.image_url or ''
        result.append(data)
    return jsonify(result)

@app.route('/api/products/search', methods=['GET'])
def search_products():
    query = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()
    qs = Product.query
    if query:
        qs = qs.filter(Product.name.ilike(f'%{query}%') | Product.description.ilike(f'%{query}%'))
    if category and category != 'all':
        qs = qs.filter(Product.category == category)
    products = qs.all()
    return jsonify([{'id': p.id, 'name': p.name, 'category': p.category, 'price': p.price, 'stock': p.available_stock} for p in products])

@app.route('/api/products/categories', methods=['GET'])
def get_categories():
    return jsonify(['Terrazzo', 'Plumbing', 'General'])

@app.route('/api/admin/products', methods=['POST'])
@jwt_required()
def create_product():
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    data = request.get_json()
    category = data.get('category', '').strip()
    if category not in ['Terrazzo', 'Plumbing', 'General']:
        return jsonify({'error': 'Invalid category'}), 400
    p = Product(name=data['name'], category=category, price=data['price'], stock=data.get('stock', 0), description=data.get('description', ''))
    db.session.add(p)
    db.session.commit()
    return jsonify({'success': True, 'id': p.id}), 201

@app.route('/api/admin/products/upload', methods=['POST'])
@jwt_required()
def upload_product_image():
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    if 'image' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['image']
    pid = request.form.get('product_id')
    if not pid:
        return jsonify({'error': 'Product ID required'}), 400
    product = Product.query.get(pid)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    file.seek(0, 2)
    if file.tell() > 5 * 1024 * 1024:
        return jsonify({'error': 'Image too large'}), 400
    file.seek(0)
    
    # Try DB storage first (primary)
    db_success = False
    try:
        content = file.read()
        product.image_data = base64.b64encode(content).decode('utf-8')
        product.image_mime = file.mimetype
        product.image_type = 'db'
        db.session.commit()
        db_success = True
        logger.info(f"✅ Image saved to DB for product {pid}")
        return jsonify({'success': True, 'stored_in_db': True})
    except Exception as e:
        logger.error(f"❌ DB storage failed: {e}")
        db.session.rollback()
    
    # If DB fails (full/error), fallback to Cloudinary
    if not db_success and CLOUDINARY_ENABLED:
        try:
            file.seek(0)
            result = cloudinary.uploader.upload(file, folder='wamp_products')
            product.image_url = result['secure_url']
            product.image_type = 'cloudinary'
            product.image_data = None
            db.session.commit()
            logger.info(f"✅ Fallback to Cloudinary for product {pid}")
            return jsonify({'success': True, 'cloudinary_fallback': True})
        except Exception as e:
            logger.error(f"❌ Cloudinary also failed: {e}")
            return jsonify({'error': 'Both DB and Cloudinary storage failed'}), 500
    
    return jsonify({'error': 'Storage failed'}), 500

@app.route('/api/admin/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    p = Product.query.get_or_404(pid)
    data = request.get_json()
    p.name = data.get('name', p.name)
    cat = data.get('category', '').strip()
    if cat in ['Terrazzo', 'Plumbing', 'General']:
        p.category = cat
    p.price = data.get('price', p.price)
    p.stock = data.get('stock', p.stock)
    p.description = data.get('description', p.description)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/admin/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    db.session.delete(Product.query.get_or_404(pid))
    db.session.commit()
    return jsonify({'success': True})

# ==================== CART ROUTES ====================
@app.route('/api/cart', methods=['GET'])
@jwt_required()
def get_cart():
    uid = int(get_jwt_identity())
    items = CartItem.query.filter_by(user_id=uid).all()
    return jsonify([{'id': i.id, 'product_id': i.product_id, 'quantity': i.quantity} for i in items])

@app.route('/api/cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    uid = int(get_jwt_identity())
    data = request.get_json()
    pid = data['product_id']
    qty = data.get('quantity', 1)
    p = Product.query.get(pid)
    if not p or p.available_stock < qty:
        return jsonify({'error': 'Stock issue'}), 400
    item = CartItem.query.filter_by(user_id=uid, product_id=pid).first()
    if item:
        item.quantity += qty
    else:
        db.session.add(CartItem(user_id=uid, product_id=pid, quantity=qty))
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/api/cart/<int:cid>', methods=['DELETE'])
@jwt_required()
def remove_cart(cid):
    uid = int(get_jwt_identity())
    item = CartItem.query.filter_by(id=cid, user_id=uid).first()
    if item:
        db.session.delete(item)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/cart/clear', methods=['DELETE'])
@jwt_required()
def clear_cart():
    CartItem.query.filter_by(user_id=int(get_jwt_identity())).delete()
    db.session.commit()
    return jsonify({'success': True})

# ==================== WISHLIST & REVIEWS ====================
@app.route('/api/wishlist', methods=['GET'])
@jwt_required()
def get_wishlist():
    uid = int(get_jwt_identity())
    items = Wishlist.query.filter_by(user_id=uid).all()
    result = []
    for i in items:
        p = Product.query.get(i.product_id)
        if p:
            result.append({'id': i.id, 'product_id': i.product_id, 'name': p.name, 'price': p.price})
    return jsonify(result)

@app.route('/api/wishlist', methods=['POST'])
@jwt_required()
def toggle_wishlist():
    uid = int(get_jwt_identity())
    pid = request.get_json()['product_id']
    existing = Wishlist.query.filter_by(user_id=uid, product_id=pid).first()
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(Wishlist(user_id=uid, product_id=pid))
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/reviews', methods=['POST'])
@jwt_required()
def submit_review():
    uid = int(get_jwt_identity())
    data = request.get_json()
    pid = data['product_id']
    rating = data['rating']
    comment = data.get('comment', '')
    if not (1 <= rating <= 5):
        return jsonify({'error': 'Invalid rating'}), 400
    existing = Review.query.filter_by(user_id=uid, product_id=pid).first()
    if existing:
        existing.rating, existing.comment = rating, comment
    else:
        db.session.add(Review(user_id=uid, product_id=pid, rating=rating, comment=comment))
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/reviews/user', methods=['GET'])
@jwt_required()
def get_user_reviews():
    uid = int(get_jwt_identity())
    reviews = Review.query.filter_by(user_id=uid).all()
    return jsonify([{'id': r.id, 'product_id': r.product_id, 'rating': r.rating, 'comment': r.comment, 'created_at': r.created_at.isoformat()} for r in reviews])

@app.route('/api/reviews/product/<int:pid>', methods=['GET'])
def get_product_reviews(pid):
    reviews = db.session.execute(text("""
        SELECT r.rating, r.comment, r.created_at, u.name
        FROM reviews r JOIN users u ON r.user_id = u.id
        WHERE r.product_id = :pid ORDER BY r.created_at DESC
    """), {'pid': pid}).fetchall()
    return jsonify([{'rating': r[0], 'comment': r[1], 'created_at': r[2].isoformat() if r[2] else None, 'user_name': r[3]} for r in reviews])

# ==================== ORDER ROUTES ====================
@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role == 'admin':
        orders = Order.query.order_by(Order.created_at.desc()).all()
    elif user.role == 'agent':
        orders = Order.query.filter_by(agent_id=uid).order_by(Order.created_at.desc()).all()
    else:
        orders = Order.query.filter_by(user_id=uid).order_by(Order.created_at.desc()).all()
    return jsonify([enrich_order(o) for o in orders])

@app.route('/api/orders', methods=['POST'])
@jwt_required()
def create_order():
    uid = int(get_jwt_identity())
    data = request.get_json()
    items = data.get('items', [])
    if not items:
        return jsonify({'error': 'No items'}), 400
    validated, total = [], 0
    for it in items:
        p = Product.query.with_for_update().get(it['productId'])
        if not p or p.available_stock < it['quantity']:
            return jsonify({'error': 'Stock issue'}), 400
        total += p.price * it['quantity']
        validated.append({'productId': p.id, 'quantity': it['quantity']})
        p.reserved_stock += it['quantity']
    order = Order(user_id=uid, items=json.dumps(validated), total=total, payment_method=data.get('payment_method', 'MTN'), delivery_location=data.get('delivery_location', ''), stock_reserved_until=datetime.utcnow() + timedelta(hours=1))
    db.session.add(order)
    db.session.commit()
    
    # Create receipt for the order
    receipt = Receipt(
        receipt_number=generate_receipt_number(order.id),
        order_id=order.id,
        user_id=uid,
        barcode_data=f"TEL:0741227707,0741333544",
        printed_count=0
    )
    db.session.add(receipt)
    
    CartItem.query.filter_by(user_id=uid).delete()
    agent = get_least_busy_agent()
    if agent:
        order.agent_id = agent.id
    db.session.commit()
    
    send_notification(uid, 'Order Created', f'Order #{order.id} created')
    if agent:
        send_notification(agent.id, 'New Order', f'Order #{order.id} assigned to you')
    
    return jsonify({'success': True, 'order_id': order.id, 'receipt': {'id': receipt.id, 'receipt_number': receipt.receipt_number}}), 201

@app.route('/api/orders/<int:oid>/status', methods=['PUT'])
@jwt_required()
def update_order_status(oid):
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    order = Order.query.get_or_404(oid)
    if user.role != 'admin' and (user.role == 'agent' and order.agent_id != uid):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.get_json()
    order.status = data.get('status', order.status)
    if order.status == 'delivered':
        order.stock_confirmed = True
    db.session.commit()
    send_notification(order.user_id, 'Order Updated', f'Order #{oid} is now {order.status}')
    return jsonify({'success': True})

@app.route('/api/orders/<int:oid>/track', methods=['GET'])
@jwt_required()
def track_order(oid):
    uid = int(get_jwt_identity())
    order = Order.query.get_or_404(oid)
    user = User.query.get(uid)
    if order.user_id != uid and user.role not in ['admin', 'agent']:
        return jsonify({'error': 'Permission denied'}), 403
    steps = {'pending': {'step': 1, 'message': 'Order received', 'icon': '📝'}, 'processing': {'step': 2, 'message': 'Processing', 'icon': '✅'}, 'shipped': {'step': 3, 'message': 'Out for delivery', 'icon': '🚚'}, 'delivered': {'step': 4, 'message': 'Delivered', 'icon': '🏠'}}
    return jsonify({
        'order_id': oid, 'status': order.status, 'current_step': steps.get(order.status, steps['pending']),
        'rider': {'name': order.rider_name, 'phone': order.rider_phone} if order.rider_name else None,
        'delivery_address': order.delivery_location, 'created_at': order.created_at.isoformat(),
        'estimated_delivery': (order.created_at + timedelta(days=2)).isoformat()
    })

# ==================== RIDER ROUTES (NEW) ====================
@app.route('/api/riders', methods=['GET'])
@jwt_required()
def get_riders():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role not in ['admin', 'agent']:
        return jsonify({'error': 'Permission denied'}), 403
    
    riders = Rider.query.all()
    return jsonify([{'id': r.id, 'name': r.name, 'phone': r.phone, 'status': r.status} for r in riders])

@app.route('/api/riders', methods=['POST'])
@jwt_required()
def create_rider():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role not in ['admin', 'agent']:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    name = data.get('name', '').strip()
    phone = data.get('phone', '').strip()
    
    if not name or not phone:
        return jsonify({'error': 'Name and phone required'}), 400
    
    rider = Rider(name=name, phone=phone, status='available', created_by=uid)
    db.session.add(rider)
    db.session.commit()
    
    return jsonify({'success': True, 'id': rider.id})

@app.route('/api/riders/<int:rid>/status', methods=['PUT'])
@jwt_required()
def update_rider_status(rid):
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role not in ['admin', 'agent']:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    status = data.get('status')
    if status not in ['available', 'busy']:
        return jsonify({'error': 'Invalid status'}), 400
    
    rider = Rider.query.get_or_404(rid)
    rider.status = status
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/orders/<int:oid>/assign-rider', methods=['PUT'])
@jwt_required()
def assign_rider_to_order(oid):
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role not in ['admin', 'agent']:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    rider_id = data.get('rider_id')
    rider_name = data.get('rider_name')
    rider_phone = data.get('rider_phone')
    
    order = Order.query.get_or_404(oid)
    
    if rider_id:
        rider = Rider.query.get(rider_id)
        if rider:
            order.rider_name = rider.name
            order.rider_phone = rider.phone
            rider.status = 'busy'
    elif rider_name and rider_phone:
        order.rider_name = rider_name
        order.rider_phone = rider_phone
    
    order.status = 'shipped'
    db.session.commit()
    
    send_notification(order.user_id, 'Rider Assigned', f'Rider {order.rider_name} assigned to order #{oid}')
    return jsonify({'success': True})

# ==================== RECEIPT ROUTES ====================
@app.route('/api/receipts', methods=['GET'])
@jwt_required()
def get_user_receipts():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    
    if user.role == 'admin':
        receipts = Receipt.query.order_by(Receipt.issued_at.desc()).all()
    elif user.role == 'agent':
        # Agent sees receipts for orders they are assigned to
        agent_orders = Order.query.filter_by(agent_id=uid).all()
        order_ids = [o.id for o in agent_orders]
        receipts = Receipt.query.filter(Receipt.order_id.in_(order_ids)).order_by(Receipt.issued_at.desc()).all()
    else:
        # Customer sees their own receipts
        receipts = Receipt.query.filter_by(user_id=uid).order_by(Receipt.issued_at.desc()).all()
    
    return jsonify([{
        'id': r.id,
        'receipt_number': r.receipt_number,
        'order_id': r.order_id,
        'barcode_data': r.barcode_data,
        'printed_count': r.printed_count,
        'issued_at': r.issued_at.isoformat()
    } for r in receipts])

@app.route('/api/receipts/<int:receipt_id>', methods=['GET'])
@jwt_required()
def get_receipt(receipt_id):
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    receipt = Receipt.query.get_or_404(receipt_id)
    
    # Check permission
    if receipt.user_id != uid and user.role not in ['admin', 'agent']:
        return jsonify({'error': 'Permission denied'}), 403
    
    if user.role == 'agent':
        # Check if agent is assigned to this order
        order = Order.query.get(receipt.order_id)
        if order.agent_id != uid:
            return jsonify({'error': 'Permission denied'}), 403
    
    order = Order.query.get(receipt.order_id)
    items = json.loads(order.items) if order.items else []
    enriched_items = []
    for item in items:
        p = Product.query.get(item.get('productId'))
        enriched_items.append({
            'name': p.name if p else 'Product',
            'price': p.price if p else 0,
            'quantity': item.get('quantity', 1)
        })
    
    return jsonify({
        'id': receipt.id,
        'receipt_number': receipt.receipt_number,
        'order_id': receipt.order_id,
        'order': {
            'id': order.id,
            'total': order.total,
            'status': order.status,
            'payment_method': order.payment_method,
            'delivery_location': order.delivery_location,
            'created_at': order.created_at.isoformat(),
            'items': enriched_items
        },
        'barcode_data': receipt.barcode_data,
        'printed_count': receipt.printed_count,
        'issued_at': receipt.issued_at.isoformat()
    })

@app.route('/api/receipts/<int:receipt_id>/print', methods=['POST'])
@jwt_required()
def increment_receipt_print(receipt_id):
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    receipt = Receipt.query.get_or_404(receipt_id)
    
    if receipt.user_id != uid and user.role not in ['admin', 'agent']:
        return jsonify({'error': 'Permission denied'}), 403
    
    receipt.printed_count += 1
    db.session.commit()
    return jsonify({'success': True, 'printed_count': receipt.printed_count})

# ==================== CUSTOMER-AGENT CHAT ROUTES ====================
@app.route('/api/customer/chats', methods=['GET'])
@jwt_required()
def get_customer_chats():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    
    if user.role == 'admin':
        conversations = db.session.query(
            CustomerChat.conversation_id,
            CustomerChat.customer_id,
            func.max(CustomerChat.created_at).label('last_message_time')
        ).group_by(CustomerChat.conversation_id, CustomerChat.customer_id).all()
        
        result = []
        for conv in conversations:
            customer = User.query.get(conv.customer_id)
            last_msg = CustomerChat.query.filter_by(conversation_id=conv.conversation_id).order_by(CustomerChat.created_at.desc()).first()
            unread = CustomerChat.query.filter_by(conversation_id=conv.conversation_id, is_read=False).filter(CustomerChat.sender_id != uid).count()
            result.append({
                'conversation_id': conv.conversation_id,
                'customer_id': conv.customer_id,
                'customer_name': customer.name if customer else f'Customer #{conv.customer_id}',
                'last_message': last_msg.message if last_msg else '',
                'last_message_time': conv.last_message_time.isoformat() if conv.last_message_time else None,
                'unread_count': unread
            })
        return jsonify(result)
    
    elif user.role == 'agent':
        conversations = db.session.query(
            CustomerChat.conversation_id,
            CustomerChat.customer_id,
            func.max(CustomerChat.created_at).label('last_message_time')
        ).filter(CustomerChat.agent_id == uid).group_by(CustomerChat.conversation_id, CustomerChat.customer_id).all()
        
        result = []
        for conv in conversations:
            customer = User.query.get(conv.customer_id)
            last_msg = CustomerChat.query.filter_by(conversation_id=conv.conversation_id).order_by(CustomerChat.created_at.desc()).first()
            unread = CustomerChat.query.filter_by(conversation_id=conv.conversation_id, is_read=False).filter(CustomerChat.sender_id != uid).count()
            result.append({
                'conversation_id': conv.conversation_id,
                'customer_id': conv.customer_id,
                'customer_name': customer.name if customer else f'Customer #{conv.customer_id}',
                'last_message': last_msg.message if last_msg else '',
                'last_message_time': conv.last_message_time.isoformat() if conv.last_message_time else None,
                'unread_count': unread
            })
        return jsonify(result)
    
    else:
        conversations = db.session.query(
            CustomerChat.conversation_id,
            CustomerChat.agent_id,
            func.max(CustomerChat.created_at).label('last_message_time')
        ).filter(CustomerChat.customer_id == uid).group_by(CustomerChat.conversation_id, CustomerChat.agent_id).all()
        
        result = []
        for conv in conversations:
            agent = User.query.get(conv.agent_id)
            last_msg = CustomerChat.query.filter_by(conversation_id=conv.conversation_id).order_by(CustomerChat.created_at.desc()).first()
            unread = CustomerChat.query.filter_by(conversation_id=conv.conversation_id, is_read=False).filter(CustomerChat.sender_id != uid).count()
            result.append({
                'conversation_id': conv.conversation_id,
                'agent_id': conv.agent_id,
                'agent_name': agent.name if agent else 'Agent',
                'last_message': last_msg.message if last_msg else '',
                'last_message_time': conv.last_message_time.isoformat() if conv.last_message_time else None,
                'unread_count': unread
            })
        return jsonify(result)

@app.route('/api/customer/chats/<conversation_id>', methods=['GET'])
@jwt_required()
def get_chat_messages(conversation_id):
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    
    chat_record = CustomerChat.query.filter_by(conversation_id=conversation_id).first()
    if not chat_record:
        return jsonify([])
    
    if user.role == 'admin':
        pass
    elif user.role == 'agent':
        if chat_record.agent_id != uid:
            return jsonify({'error': 'Permission denied'}), 403
    else:
        if chat_record.customer_id != uid:
            return jsonify({'error': 'Permission denied'}), 403
    
    messages = CustomerChat.query.filter_by(conversation_id=conversation_id).order_by(CustomerChat.created_at.asc()).all()
    
    for msg in messages:
        if msg.sender_id != uid and not msg.is_read:
            msg.is_read = True
    db.session.commit()
    
    return jsonify([{
        'id': m.id,
        'sender_id': m.sender_id,
        'sender_name': m.sender_name,
        'message': m.message,
        'is_read': m.is_read,
        'created_at': m.created_at.isoformat()
    } for m in messages])

@app.route('/api/customer/chats', methods=['POST'])
@jwt_required()
def send_chat_message():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    data = request.get_json()
    
    customer_id = data.get('customer_id')
    agent_id = data.get('agent_id')
    message = data.get('message', '').strip()
    
    if not message:
        return jsonify({'error': 'Message required'}), 400
    
    if user.role == 'agent':
        actual_customer_id = customer_id
        actual_agent_id = uid
        conversation_id = f"cust_{actual_customer_id}_agent_{actual_agent_id}"
        
        chat = CustomerChat(
            conversation_id=conversation_id,
            customer_id=actual_customer_id,
            agent_id=actual_agent_id,
            sender_id=uid,
            sender_name=user.name,
            message=message
        )
        db.session.add(chat)
        db.session.commit()
        
        send_notification(actual_customer_id, f'Message from Agent {user.name}', message[:100])
        return jsonify({'success': True, 'conversation_id': conversation_id})
    
    elif user.role == 'admin':
        actual_customer_id = customer_id
        actual_agent_id = agent_id or user.id
        conversation_id = f"cust_{actual_customer_id}_agent_{actual_agent_id}"
        
        chat = CustomerChat(
            conversation_id=conversation_id,
            customer_id=actual_customer_id,
            agent_id=actual_agent_id,
            sender_id=uid,
            sender_name=user.name,
            message=message
        )
        db.session.add(chat)
        db.session.commit()
        
        if actual_customer_id:
            send_notification(actual_customer_id, f'Message from Admin', message[:100])
        if actual_agent_id and actual_agent_id != uid:
            send_notification(actual_agent_id, f'Message from Admin regarding customer', message[:100])
        
        return jsonify({'success': True, 'conversation_id': conversation_id})
    
    else:
        actual_customer_id = uid
        order = Order.query.filter_by(user_id=uid).order_by(Order.created_at.desc()).first()
        actual_agent_id = order.agent_id if order and order.agent_id else None
        
        if not actual_agent_id:
            agent = get_least_busy_agent()
            actual_agent_id = agent.id if agent else 1
        
        conversation_id = f"cust_{actual_customer_id}_agent_{actual_agent_id}"
        
        chat = CustomerChat(
            conversation_id=conversation_id,
            customer_id=actual_customer_id,
            agent_id=actual_agent_id,
            sender_id=uid,
            sender_name=user.name,
            message=message
        )
        db.session.add(chat)
        db.session.commit()
        
        send_notification(actual_agent_id, f'New message from {user.name}', message[:100])
        return jsonify({'success': True, 'conversation_id': conversation_id})

# ==================== ADMIN ROUTES ====================
@app.route('/api/admin/stats', methods=['GET'])
@jwt_required()
def admin_stats():
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    today = datetime.utcnow().replace(hour=0, minute=0, second=0)
    return jsonify({
        'today_sales': db.session.query(func.sum(Order.total)).filter(Order.created_at >= today, Order.status.in_(['delivered', 'completed'])).scalar() or 0,
        'pending_orders': Order.query.filter(Order.status.in_(['pending', 'paid'])).count(),
        'total_products': Product.query.count(),
        'low_stock': Product.query.filter(Product.stock < 5).count(),
        'total_users': User.query.filter_by(role='user').count(),
        'total_agents': User.query.filter_by(role='agent').count()
    })

@app.route('/api/admin/orders/export', methods=['GET'])
@jwt_required()
def export_orders():
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'User ID', 'Agent ID', 'Total', 'Status', 'Payment', 'Rider', 'Created'])
    for o in Order.query.all():
        writer.writerow([o.id, o.user_id, o.agent_id or '', o.total, o.status, o.payment_method, o.rider_name or '', o.created_at.isoformat()])
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename=orders.csv'
    return resp

# ==================== ADMIN CHAT ENDPOINTS ====================
@app.route('/api/admin/conversations', methods=['GET'])
@jwt_required()
def get_admin_conversations():
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    agents = User.query.filter_by(role='agent').all()
    result = []
    for a in agents:
        last = Communication.query.filter(((Communication.sender_id == user.id) & (Communication.receiver_id == a.id)) | ((Communication.sender_id == a.id) & (Communication.receiver_id == user.id))).order_by(Communication.created_at.desc()).first()
        unread = Communication.query.filter(Communication.sender_id == a.id, Communication.receiver_id == user.id, Communication.is_read == False).count()
        result.append({'agent_id': a.id, 'agent_name': a.name, 'last_message': last.content if last else None, 'unread_count': unread})
    return jsonify(result)

@app.route('/api/admin/conversations/<int:aid>', methods=['GET'])
@jwt_required()
def get_conversation_with_agent(aid):
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    messages = Communication.query.filter(((Communication.sender_id == user.id) & (Communication.receiver_id == aid)) | ((Communication.sender_id == aid) & (Communication.receiver_id == user.id))).order_by(Communication.created_at.asc()).all()
    for m in messages:
        if m.sender_id == aid and m.receiver_id == user.id:
            m.is_read = True
    db.session.commit()
    return jsonify([{'id': m.id, 'sender_id': m.sender_id, 'sender_name': User.query.get(m.sender_id).name, 'content': m.content, 'created_at': m.created_at.isoformat()} for m in messages])

@app.route('/api/admin/send-message', methods=['POST'])
@jwt_required()
def admin_send_message():
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    data = request.get_json()
    aid = data.get('agent_id')
    content = data.get('content')
    if not aid or not content:
        return jsonify({'error': 'Agent ID and content required'}), 400
    msg = Communication(sender_id=user.id, receiver_id=aid, content=content)
    db.session.add(msg)
    db.session.commit()
    send_notification(aid, 'New Message', f'Message from {user.name}')
    return jsonify({'success': True})

@app.route('/api/admin/broadcast', methods=['POST'])
@jwt_required()
def admin_broadcast():
    user = User.query.get(int(get_jwt_identity()))
    if user.role != 'admin':
        return jsonify({'error': 'Admin required'}), 403
    data = request.get_json()
    message = data.get('message')
    if not message:
        return jsonify({'error': 'Message required'}), 400
    agents = User.query.filter_by(role='agent').all()
    for a in agents:
        send_notification(a.id, 'Admin Broadcast', message)
    return jsonify({'success': True, 'sent_to': len(agents)})

# ==================== AGENT ROUTES ====================
@app.route('/api/agent/panel', methods=['GET'])
@jwt_required()
def agent_panel():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role not in ['agent', 'admin']:
        return jsonify({'error': 'Agent required'}), 403
    if user.role == 'admin':
        assigned = Order.query.filter(Order.agent_id.isnot(None)).order_by(Order.created_at.desc()).all()
        available = Order.query.filter(Order.agent_id.is_(None), Order.status == 'pending').all()
    else:
        assigned = Order.query.filter_by(agent_id=uid).order_by(Order.created_at.desc()).all()
        available = Order.query.filter(Order.agent_id.is_(None), Order.status == 'pending').all()
    return jsonify({
        'assigned': [enrich_order(o) for o in assigned],
        'available': [enrich_order(o) for o in available],
        'stats': {'assigned': len([o for o in assigned if o.status in ['pending', 'processing']]), 'completed': len([o for o in assigned if o.status in ['delivered', 'completed']])}
    })

@app.route('/api/agent/orders/<int:oid>/claim', methods=['POST'])
@jwt_required()
def claim_order(oid):
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role not in ['agent', 'admin']:
        return jsonify({'error': 'Agent required'}), 403
    order = Order.query.get_or_404(oid)
    if order.agent_id:
        return jsonify({'error': 'Already claimed'}), 409
    order.agent_id = uid
    order.status = 'processing'
    db.session.commit()
    send_notification(uid, 'Order Claimed', f'You claimed order #{oid}')
    send_notification(order.user_id, 'Order Claimed', f'Order #{oid} is now being processed')
    return jsonify({'success': True})

@app.route('/api/agent/orders/<int:oid>/update', methods=['POST'])
@jwt_required()
def agent_update_order(oid):
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    order = Order.query.get_or_404(oid)
    if order.agent_id != uid and user.role != 'admin':
        return jsonify({'error': 'Not assigned'}), 403
    data = request.get_json()
    new_status = data.get('status')
    message = data.get('customer_message', '')
    if new_status not in ['pending', 'processing', 'shipped', 'delivered', 'cancelled']:
        return jsonify({'error': 'Invalid status'}), 400
    order.status = new_status
    db.session.commit()
    if message:
        send_notification(order.user_id, f'Order #{oid} Update', message)
    return jsonify({'success': True})

@app.route('/api/agent/send-notification', methods=['POST'])
@jwt_required()
def agent_send_notification():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    data = request.get_json()
    oid = data.get('order_id')
    message = data.get('message')
    if not oid or not message:
        return jsonify({'error': 'Order ID and message required'}), 400
    order = Order.query.get_or_404(oid)
    if order.agent_id != uid and user.role != 'admin':
        return jsonify({'error': 'Not assigned'}), 403
    send_notification(order.user_id, data.get('title', 'Order Update'), f'Order #{oid}: {message}')
    return jsonify({'success': True})

@app.route('/api/agent/customers', methods=['GET'])
@jwt_required()
def get_agent_customers():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role not in ['agent', 'admin']:
        return jsonify({'error': 'Agent required'}), 403
    
    if user.role == 'admin':
        orders = Order.query.all()
    else:
        orders = Order.query.filter_by(agent_id=uid).all()
    
    customer_ids = set()
    for order in orders:
        customer_ids.add(order.user_id)
    
    customers = []
    for cid in customer_ids:
        customer = User.query.get(cid)
        if customer:
            customers.append({
                'id': customer.id,
                'name': customer.name,
                'phone': customer.phone,
                'email': customer.email,
                'address': customer.address
            })
    
    return jsonify(customers)

# ==================== AGENT GROUP CHAT ====================
@app.route('/api/agent/group-messages', methods=['GET'])
@jwt_required()
def get_group_messages():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role not in ['agent', 'admin']:
        return jsonify({'error': 'Agent required'}), 403
    msgs = AgentGroupMessage.query.order_by(AgentGroupMessage.created_at.asc()).limit(100).all()
    return jsonify([{'id': m.id, 'sender_id': m.sender_id, 'sender_name': User.query.get(m.sender_id).name, 'sender_role': User.query.get(m.sender_id).role, 'message': m.message, 'created_at': m.created_at.isoformat()} for m in msgs])

@app.route('/api/agent/group-messages', methods=['POST'])
@jwt_required()
def send_group_message():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if user.role not in ['agent', 'admin']:
        return jsonify({'error': 'Agent required'}), 403
    data = request.get_json()
    message = data.get('message', '').strip()
    if not message:
        return jsonify({'error': 'Message required'}), 400
    msg = AgentGroupMessage(sender_id=uid, message=message)
    db.session.add(msg)
    db.session.commit()
    others = User.query.filter(User.role == 'agent', User.id != uid).all()
    for o in others:
        send_notification(o.id, 'Group Chat', f'{user.name}: {message[:50]}...')
    return jsonify({'success': True})

# ==================== COMMUNICATIONS ====================
@app.route('/api/communications', methods=['GET'])
@jwt_required()
def get_comms():
    uid = int(get_jwt_identity())
    msgs = Communication.query.filter((Communication.sender_id == uid) | (Communication.receiver_id == uid)).order_by(Communication.created_at.desc()).limit(50).all()
    return jsonify([{'id': m.id, 'sender_id': m.sender_id, 'sender_name': User.query.get(m.sender_id).name, 'content': m.content, 'created_at': m.created_at.isoformat()} for m in msgs])

@app.route('/api/communications', methods=['POST'])
@jwt_required()
def send_comms():
    uid = int(get_jwt_identity())
    data = request.get_json()
    rid = data.get('receiver_id')
    content = data.get('content')
    if not rid or not content:
        return jsonify({'error': 'Receiver and content required'}), 400
    msg = Communication(sender_id=uid, receiver_id=rid, content=content)
    db.session.add(msg)
    db.session.commit()
    send_notification(rid, 'New Message', f'Message from {User.query.get(uid).name}')
    return jsonify({'success': True})

# ==================== AI CHAT BOT ====================
@app.route('/api/chat/customer', methods=['POST'])
def customer_chat():
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400

    data = request.get_json()
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'error': 'Message required'}), 400

    if GEMINI_ENABLED:
        try:
            prompt = f"""You are a customer service assistant for WAMP Enterprises.

Company info:
- Sells Terrazzo flooring (UGX 250,000 - 500,000)
- Sells Plumbing supplies (UGX 45,000 - 150,000)
- Sells General merchandise (UGX 10,000 - 200,000)
- Free delivery on orders over UGX 500,000
- Delivery takes 2-5 days
- Accepts MTN, Airtel, Card, and Cash on Delivery
- Support numbers: 0741227707 and 0741333544

Customer question: {message}

Answer concisely and helpfully in 1-2 sentences. Be friendly but professional."""

            response = gemini_model.generate_content(prompt)
            ai_response = response.text if response.text else "I'm here to help! What would you like to know?"
            return jsonify({'response': ai_response, 'ai_used': True})
        except Exception as e:
            print(f"❌ Gemini error: {e}")

    msg_lower = message.lower()

    if any(word in msg_lower for word in ['price', 'cost', 'how much']):
        resp = "💰 Prices: Terrazzo UGX 250k-500k | Plumbing UGX 45k-150k | General UGX 10k-200k"
    elif any(word in msg_lower for word in ['delivery', 'shipping']):
        resp = "🚚 Free delivery on orders > UGX 500k. Takes 2-5 days."
    elif any(word in msg_lower for word in ['payment', 'pay', 'mtn', 'airtel']):
        resp = "💳 We accept MTN, Airtel, Card, and Cash on Delivery!"
    elif any(word in msg_lower for word in ['contact', 'support', 'help', 'call']):
        resp = "📞 Contact support: 0741227707 or 0741333544"
    elif 'terrazzo' in msg_lower:
        resp = "🏛️ Terrazzo flooring: prices start at UGX 250,000"
    elif 'plumbing' in msg_lower:
        resp = "🔧 Plumbing supplies: copper pipes, fittings from UGX 45,000"
    else:
        resp = "Welcome to WAMP! Ask about prices, delivery, payments, or contact support at 0741227707 / 0741333544."

    return jsonify({'response': resp, 'ai_used': False})

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(429)
def rate_limit(e):
    return jsonify({'error': 'Too many requests'}), 429

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal error'}), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    print(f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    WAMP BACKEND - VERSION 5 (FINAL) ✅                         ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  NEW FEATURES ADDED:                                                          ║
║  ✅ Riders table + CRUD endpoints                                             ║
║  ✅ Assign rider to order                                                     ║
║  ✅ Receipts: Admin & Agent can print (NO user receipts)                      ║
║  ✅ Customer-Agent shielded chat (CustomerChat table)                         ║
║  ✅ Receipt auto-generation on order placement                                ║
║  ✅ Image upload: DB primary → Cloudinary fallback                            ║
║  ✅ WhatsApp numbers: 0741227707 & 0741333544                                 ║
║  ✅ Redesigned AI chat (bigger, better)                                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Port:        {port}                                                          ║
║  Cloudinary:  {'✅' if CLOUDINARY_ENABLED else '❌'}                            ║
║  Gemini AI:   {'✅' if GEMINI_ENABLED else '❌'}                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=port, debug=False)
