# ==========================================
# TARAZO BACKEND - FULLY ENV-DRIVEN
# No hardcoded credentials - All from .env
# ==========================================

import os
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv

load_dotenv()

# ==================== APP INITIALIZATION ====================
app = Flask(__name__)

# ==================== CONFIGURATION - ALL FROM ENV ====================
# Required secrets - will use defaults only if not provided
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# Database - from env or fallback to SQLite
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    database_url = 'sqlite:///tarazo.db'
    print("📦 Using SQLite database (no DATABASE_URL in env)")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ==================== CORS ====================
FRONTEND_URL = os.environ.get('FRONTEND_URL', '*')
CORS(app, origins="*", supports_credentials=False, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# ==================== EXTENSIONS ====================
jwt = JWTManager(app)
db = SQLAlchemy(app)
ph = PasswordHasher()

# ==================== MODELS ====================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    address = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    agent_id = db.Column(db.Integer, nullable=True)
    items = db.Column(db.Text, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='pending')
    payment_method = db.Column(db.String(50))
    rider_name = db.Column(db.String(100))
    rider_phone = db.Column(db.String(20))
    rider_vehicle = db.Column(db.String(100))
    delivery_location = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== JWT BLACKLIST ====================
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token is not None

# ==================== CREATE DEFAULT DATA - ALL FROM ENV ====================
def create_default_data():
    try:
        # Create Admin from ENV (NO HARDCODED VALUES!)
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
                    role='admin'
                )
                db.session.add(admin)
                print(f"✅ Admin created from ENV: {admin_email}")
            else:
                print(f"ℹ️ Admin already exists: {admin_email}")
        else:
            print("⚠️ No ADMIN_EMAIL/ADMIN_PASSWORD in .env - skipping admin creation")

        # Create Agents from ENV (supports up to 5 agents)
        for i in range(1, 6):
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
                        role='agent'
                    )
                    db.session.add(agent)
                    print(f"✅ Agent created from ENV: {agent_email}")
                else:
                    print(f"ℹ️ Agent already exists: {agent_email}")

        # Create sample products (only if none exist)
        if Product.query.count() == 0:
            products = [
                Product(name='Classic Floor Terrazzo', type='Floor', price=150000, stock=100, description='Premium floor terrazzo'),
                Product(name='Modern Wall Terrazzo', type='Wall', price=120000, stock=50, description='Beautiful wall terrazzo'),
                Product(name='Premium Countertop', type='Countertop', price=280000, stock=30, description='High-end countertop'),
            ]
            for p in products:
                db.session.add(p)
            print("✅ Sample products created")

        db.session.commit()
    except Exception as e:
        print(f"Error creating data: {e}")
        db.session.rollback()

# ==================== ROLE DECORATORS ====================
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

def user_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return f(*args, **kwargs)
    return decorated

# ==================== PUBLIC ROUTES ====================
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'message': 'Backend is running!'
    })

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data.get('name') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        user = User(
            name=data['name'],
            email=data['email'],
            phone=data.get('phone', ''),
            password_hash=ph.hash(data['password']),
            role='user'
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        try:
            ph.verify(user.password_hash, data['password'])
        except VerifyMismatchError:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        response = jsonify({
            'success': True,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'phone': user.phone,
                'address': user.address
            }
        })
        
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=user_id)
    return jsonify({'success': True, 'access_token': access_token})

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    blacklist = TokenBlacklist(jti=jti)
    db.session.add(blacklist)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{
        'id': p.id, 'name': p.name, 'type': p.type, 'price': p.price,
        'stock': p.stock, 'description': p.description or '', 'image_url': p.image_url or ''
    } for p in products])

# ==================== CART ROUTES ====================
@app.route('/api/cart', methods=['GET'])
@user_required
def get_cart():
    user_id = get_jwt_identity()
    cart = CartItem.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': c.id, 'product_id': c.product_id, 'quantity': c.quantity
    } for c in cart])

@app.route('/api/cart', methods=['POST'])
@user_required
def add_to_cart():
    user_id = get_jwt_identity()
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)
    
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    if product.stock < quantity:
        return jsonify({'error': f'Insufficient stock. Only {product.stock} available'}), 400
    
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
    
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/api/cart/<int:product_id>', methods=['DELETE'])
@user_required
def remove_from_cart(product_id):
    user_id = get_jwt_identity()
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
    return jsonify({'success': True})

# ==================== ORDER ROUTES ====================
@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role == 'admin':
        orders = Order.query.order_by(Order.created_at.desc()).all()
    else:
        orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
    
    return jsonify([{
        'id': o.id, 'user_id': o.user_id, 'items': json.loads(o.items) if o.items else [],
        'total': o.total, 'status': o.status, 'payment_method': o.payment_method,
        'rider_name': o.rider_name, 'rider_phone': o.rider_phone,
        'rider_vehicle': o.rider_vehicle, 'delivery_location': o.delivery_location,
        'created_at': o.created_at.isoformat()
    } for o in orders])

@app.route('/api/orders', methods=['POST'])
@user_required
def create_order():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    items_data = data.get('items', [])
    if not items_data:
        return jsonify({'error': 'No items'}), 400
    
    total = 0
    validated_items = []
    
    for item in items_data:
        product_id = item.get('productId')
        quantity = item.get('quantity', 1)
        
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': f'Product not found'}), 404
        
        if product.stock < quantity:
            return jsonify({'error': f'Insufficient stock for {product.name}'}), 400
        
        total += product.price * quantity
        validated_items.append({
            'productId': product.id,
            'productName': product.name,
            'quantity': quantity,
            'price': product.price
        })
        
        product.stock -= quantity
    
    order = Order(
        user_id=user_id,
        items=json.dumps(validated_items),
        total=total,
        status='paid',
        payment_method=data.get('payment_method', 'MTN Mobile Money')
    )
    
    db.session.add(order)
    db.session.commit()
    
    CartItem.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    
    return jsonify({'success': True, 'order_id': order.id}), 201

@app.route('/api/orders/<int:order_id>/status', methods=['PUT'])
@jwt_required()
def update_order_status(order_id):
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    order.status = data.get('status', order.status)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/orders/<int:order_id>/assign', methods=['PUT'])
@jwt_required()
def assign_rider(order_id):
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    order.rider_name = data.get('rider_name')
    order.rider_phone = data.get('rider_phone')
    order.rider_vehicle = data.get('rider_vehicle')
    order.delivery_location = data.get('delivery_location')
    db.session.commit()
    return jsonify({'success': True})

# ==================== ADMIN ROUTES ====================
@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    from sqlalchemy import func
    today = datetime.utcnow().date()
    today_orders = Order.query.filter(func.date(Order.created_at) == today).all()
    today_sales = sum(o.total for o in today_orders)
    pending = Order.query.filter(Order.status == 'pending').count()
    low_stock = Product.query.filter(Product.stock < 5).count()
    
    return jsonify({
        'today_sales': today_sales,
        'pending_orders': pending,
        'total_products': Product.query.count(),
        'low_stock': low_stock
    })

@app.route('/api/admin/orders', methods=['GET'])
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return jsonify([{
        'id': o.id, 'user_id': o.user_id, 'total': o.total,
        'status': o.status, 'created_at': o.created_at.isoformat()
    } for o in orders])

# ==================== AGENT ROUTES ====================
@app.route('/api/agent/orders', methods=['GET'])
@jwt_required()
def agent_orders():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role != 'agent' and user.role != 'admin':
        return jsonify({'error': 'Agent access required'}), 403
    
    orders = Order.query.filter_by(agent_id=user_id).order_by(Order.created_at.desc()).all()
    return jsonify([{
        'id': o.id, 'user_id': o.user_id,
        'items': json.loads(o.items) if o.items else [],
        'total': o.total, 'status': o.status,
        'delivery_location': o.delivery_location,
        'created_at': o.created_at.isoformat()
    } for o in orders])

# ==================== CHAT ROUTE ====================
@app.route('/api/chat/customer', methods=['POST'])
def customer_chat():
    data = request.get_json()
    message = data.get('message', '').lower()
    
    if 'price' in message:
        response = "💰 Prices: Floor UGX 150,000/m², Wall UGX 120,000/m², Countertop UGX 280,000/m²"
    elif 'delivery' in message:
        response = "🚚 Delivery takes 2-5 days. Free delivery on orders over UGX 500,000!"
    elif 'hello' in message or 'hi' in message:
        response = "Hello! Welcome to Tarazo! How can I help you today? 😊"
    elif 'payment' in message:
        response = "💳 We accept MTN Mobile Money, Airtel Money, and Bank Cards."
    elif 'install' in message:
        response = "🛠️ Professional installation recommended. Takes 3-7 days."
    else:
        response = "I can help you with prices, delivery, and products! What would you like to know?"
    
    return jsonify({'response': response})

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    print(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_data()
        print("✅ Database initialized")
    
    port = int(os.environ.get('PORT', 5000))
    
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║                    TARAZO BACKEND - RUNNING ✅                    ║
╠══════════════════════════════════════════════════════════════════╣
║  Port: {port}                                                     ║
║  Status: RUNNING                                                  ║
║  Database: {'PostgreSQL' if 'postgres' in database_url else 'SQLite'}                               ║
╠══════════════════════════════════════════════════════════════════╣
║  📌 ALL CREDENTIALS COME FROM .env FILE                          ║
║  📌 NO HARDCODED ADMIN/AGENT PASSWORDS                           ║
╠══════════════════════════════════════════════════════════════════╣
║  To create admin/agents, add to .env:                            ║
║  ADMIN_EMAIL=admin@tarazo.com                                    ║
║  ADMIN_PASSWORD=your_secure_password                             ║
║  AGENT1_EMAIL=agent1@tarazo.com                                  ║
║  AGENT1_PASSWORD=agent123                                        ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    app.run(host='0.0.0.0', port=port, debug=False)
