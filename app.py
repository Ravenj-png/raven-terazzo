# ==========================================
# TARAZO BACKEND - MATCHES FRONTEND PERFECTLY
# No CSRF, Simple JWT in Headers, SQLite/PostgreSQL
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

app = Flask(__name__)

# ==================== CONFIGURATION ====================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# Database - SQLite by default, PostgreSQL if DATABASE_URL provided
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    database_url = 'sqlite:///tarazo.db'
    print("📦 Using SQLite database")
else:
    print(f"📦 Using database: {database_url[:50]}...")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ==================== CORS - ALLOW EVERYTHING ====================
CORS(app, 
     origins="*",
     supports_credentials=False,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
     expose_headers=["Content-Type", "Authorization"])

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

# ==================== CREATE DEFAULT DATA ====================
def create_default_data():
    try:
        # Admin
        admin = User.query.filter_by(email='admin@tarazo.com').first()
        if not admin:
            admin = User(
                name='Administrator',
                email='admin@tarazo.com',
                phone='0771000000',
                password_hash=ph.hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
            print("✅ Admin: admin@tarazo.com / admin123")

        # Agents (1-5)
        for i in range(1, 6):
            agent = User.query.filter_by(email=f'agent{i}@tarazo.com').first()
            if not agent:
                agent = User(
                    name=f'Agent {i}',
                    email=f'agent{i}@tarazo.com',
                    phone=f'077{i}00000',
                    password_hash=ph.hash('agent123'),
                    role='agent'
                )
                db.session.add(agent)
                print(f"✅ Agent: agent{i}@tarazo.com / agent123")

        # Sample Products
        if Product.query.count() == 0:
            products = [
                Product(name='Classic Floor Terrazzo', type='Floor', price=150000, stock=100, description='Premium floor terrazzo for living rooms'),
                Product(name='Modern Wall Terrazzo', type='Wall', price=120000, stock=50, description='Beautiful wall terrazzo tiles'),
                Product(name='Premium Countertop', type='Countertop', price=280000, stock=30, description='High-end countertop terrazzo'),
                Product(name='Outdoor Terrazzo', type='Outdoor', price=180000, stock=75, description='Weather-resistant outdoor terrazzo'),
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

# ==================== ROUTES ====================
@app.route('/api/health', methods=['GET', 'OPTIONS'])
def health():
    if request.method == 'OPTIONS':
        return '', 200
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        phone = data.get('phone', '')
        
        if not name or not email or not password:
            return jsonify({'error': 'Name, email and password required'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 409
        
        user = User(
            name=name,
            email=email,
            phone=phone,
            password_hash=ph.hash(password),
            role='user'
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        try:
            ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return jsonify({
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
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/refresh', methods=['POST', 'OPTIONS'])
@jwt_required(refresh=True)
def refresh():
    if request.method == 'OPTIONS':
        return '', 200
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=user_id)
    return jsonify({'success': True, 'access_token': access_token})

@app.route('/api/logout', methods=['POST', 'OPTIONS'])
@jwt_required()
def logout():
    if request.method == 'OPTIONS':
        return '', 200
    jti = get_jwt()['jti']
    blacklist = TokenBlacklist(jti=jti)
    db.session.add(blacklist)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/products', methods=['GET', 'OPTIONS'])
def get_products():
    if request.method == 'OPTIONS':
        return '', 200
    products = Product.query.all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'type': p.type,
        'price': p.price,
        'stock': p.stock,
        'description': p.description or '',
        'image_url': p.image_url or ''
    } for p in products])

@app.route('/api/cart', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_cart():
    if request.method == 'OPTIONS':
        return '', 200
    user_id = get_jwt_identity()
    cart = CartItem.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': c.id,
        'product_id': c.product_id,
        'quantity': c.quantity
    } for c in cart])

@app.route('/api/cart', methods=['POST', 'OPTIONS'])
@jwt_required()
def add_to_cart():
    if request.method == 'OPTIONS':
        return '', 200
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
    return jsonify({'success': True, 'message': 'Added to cart'}), 201

@app.route('/api/cart/<int:item_id>', methods=['DELETE', 'OPTIONS'])
@jwt_required()
def remove_from_cart(item_id):
    if request.method == 'OPTIONS':
        return '', 200
    user_id = get_jwt_identity()
    cart_item = CartItem.query.filter_by(id=item_id, user_id=user_id).first()
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
    return jsonify({'success': True, 'message': 'Removed from cart'})

@app.route('/api/orders', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_orders():
    if request.method == 'OPTIONS':
        return '', 200
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role == 'admin':
        orders = Order.query.order_by(Order.created_at.desc()).all()
    elif user.role == 'agent':
        orders = Order.query.filter_by(agent_id=user_id).order_by(Order.created_at.desc()).all()
    else:
        orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
    
    return jsonify([{
        'id': o.id,
        'user_id': o.user_id,
        'items': json.loads(o.items) if o.items else [],
        'total': o.total,
        'status': o.status,
        'payment_method': o.payment_method,
        'rider_name': o.rider_name,
        'rider_phone': o.rider_phone,
        'rider_vehicle': o.rider_vehicle,
        'delivery_location': o.delivery_location,
        'created_at': o.created_at.isoformat()
    } for o in orders])

@app.route('/api/orders', methods=['POST', 'OPTIONS'])
@jwt_required()
def create_order():
    if request.method == 'OPTIONS':
        return '', 200
    user_id = get_jwt_identity()
    data = request.get_json()
    
    items_data = data.get('items', [])
    if not items_data:
        return jsonify({'error': 'No items in order'}), 400
    
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
    
    # Clear cart after order
    CartItem.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    
    return jsonify({'success': True, 'order_id': order.id}), 201

@app.route('/api/orders/<int:order_id>/status', methods=['PUT', 'OPTIONS'])
@jwt_required()
def update_order_status(order_id):
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    order.status = data.get('status', order.status)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/orders/<int:order_id>/assign', methods=['PUT', 'OPTIONS'])
@jwt_required()
def assign_rider(order_id):
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    order.rider_name = data.get('rider_name')
    order.rider_phone = data.get('rider_phone')
    order.rider_vehicle = data.get('rider_vehicle')
    order.delivery_location = data.get('delivery_location')
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/admin/stats', methods=['GET', 'OPTIONS'])
@admin_required
def admin_stats():
    if request.method == 'OPTIONS':
        return '', 200
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

@app.route('/api/admin/orders', methods=['GET', 'OPTIONS'])
@admin_required
def admin_orders():
    if request.method == 'OPTIONS':
        return '', 200
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return jsonify([{
        'id': o.id,
        'user_id': o.user_id,
        'total': o.total,
        'status': o.status,
        'created_at': o.created_at.isoformat()
    } for o in orders])

@app.route('/api/chat/customer', methods=['POST', 'OPTIONS'])
def customer_chat():
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json()
    message = data.get('message', '').lower()
    
    if 'price' in message or 'cost' in message:
        response = "💰 Tarazo Prices:\n• Floor: UGX 150,000/m²\n• Wall: UGX 120,000/m²\n• Countertop: UGX 280,000/m²"
    elif 'delivery' in message:
        response = "🚚 Delivery takes 2-5 days. Free delivery on orders over UGX 500,000!"
    elif 'hello' in message or 'hi' in message:
        response = "Hello! Welcome to Tarazo! How can I help you today? 😊"
    elif 'payment' in message:
        response = "💳 We accept MTN Mobile Money, Airtel Money, and Bank Cards."
    elif 'install' in message:
        response = "🛠️ Professional installation recommended. Takes 3-7 days."
    else:
        response = "I can help you with prices, delivery, installation, and payments! What would you like to know?"
    
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
║  CORS: All origins allowed                                       ║
║  Auth: JWT in headers (Bearer token)                             ║
║  CSRF: DISABLED (not needed)                                     ║
╠══════════════════════════════════════════════════════════════════╣
║  Test Credentials:                                                ║
║  👑 Admin:  admin@tarazo.com / admin123                           ║
║  👤 Agent:  agent1@tarazo.com / agent123                          ║
║  👤 Agent:  agent2@tarazo.com / agent123                          ║
║  👤 Agent:  agent3@tarazo.com / agent123                          ║
║  👤 Agent:  agent4@tarazo.com / agent123                          ║
║  👤 Agent:  agent5@tarazo.com / agent123                          ║
║  👤 User:   Register new account                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  API Endpoints:                                                   ║
║  POST   /api/login        - Login (returns token)                ║
║  POST   /api/register     - Register user                        ║
║  GET    /api/products     - Get all products                     ║
║  GET    /api/cart         - Get user cart                        ║
║  POST   /api/cart         - Add to cart                          ║
║  POST   /api/orders       - Create order                         ║
║  GET    /api/admin/stats  - Admin statistics                     ║
║  POST   /api/chat/customer - AI chat                             ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    app.run(host='0.0.0.0', port=port, debug=False)
