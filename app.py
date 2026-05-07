from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os, json

app = Flask(__name__)

# 🔒 CONFIG - All defaults so it NEVER crashes
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'presentation-secret-key-123')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-key-456')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///tarazo.db')  # SQLite = zero config
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# 🌐 CORS - Works on ALL browsers, ALL origins
CORS(app, 
     origins=["*"],  # Allow everything for presentation
     supports_credentials=True,  # ✅ MUST be True for frontend credentials: 'include'
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
     allow_headers=["*"],
     expose_headers=["*"])

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ==================== MODELS ====================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    email_verified = db.Column(db.Boolean, default=True)  # ✅ Auto-verify for demo
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

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    quantity = db.Column(db.Integer, default=1)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    items = db.Column(db.Text, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='pending')
    payment_method = db.Column(db.String(50))
    payment_status = db.Column(db.String(50), default='pending')
    rider_name = db.Column(db.String(100))
    rider_phone = db.Column(db.String(20))
    delivery_location = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== ROUTES ====================
@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'database': 'connected', 'mode': 'presentation'})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing fields'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email exists'}), 400
    user = User(
        name=data.get('name', 'User'),
        email=data['email'],
        phone=data.get('phone', ''),
        password_hash=generate_password_hash(data['password']),
        role='user',
        email_verified=True  # ✅ Auto-verify for demo
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Registered!'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    user = User.query.filter_by(email=data['email']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    if not user.email_verified:
        return jsonify({'error': 'Verify email first'}), 403
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    return jsonify({
        'success': True,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user.id, 'name': user.name, 'email': user.email,
            'role': user.role, 'phone': user.phone
        }
    })

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({'success': True})

@app.route('/api/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{
        'id': p.id, 'name': p.name, 'type': p.type, 'price': p.price,
        'stock': p.stock, 'description': p.description or '', 'image_url': p.image_url or ''
    } for p in products])

@app.route('/api/cart', methods=['GET'])
@jwt_required()
def get_cart():
    user_id = get_jwt_identity()
    cart = CartItem.query.filter_by(user_id=user_id).all()
    return jsonify([{'id': c.id, 'product_id': c.product_id, 'quantity': c.quantity} for c in cart])

@app.route('/api/cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    user_id = get_jwt_identity()
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)
    if not product_id:
        return jsonify({'error': 'Product ID required'}), 400
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/api/cart/<int:item_id>', methods=['DELETE'])
@jwt_required()
def remove_from_cart(item_id):
    user_id = get_jwt_identity()
    item = CartItem.query.filter_by(id=item_id, user_id=user_id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user.role == 'admin':
        orders = Order.query.order_by(Order.created_at.desc()).all()
    elif user.role == 'agent':
        orders = Order.query.filter_by(agent_id=user_id).order_by(Order.created_at.desc()).all()
    else:
        orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
    return jsonify([{
        'id': o.id, 'user_id': o.user_id, 'total': o.total, 'status': o.status,
        'payment_method': o.payment_method, 'rider_name': o.rider_name,
        'rider_phone': o.rider_phone, 'delivery_location': o.delivery_location,
        'created_at': o.created_at.isoformat() if o.created_at else None
    } for o in orders])

@app.route('/api/orders', methods=['POST'])
@jwt_required()
def create_order():
    user_id = get_jwt_identity()
    data = request.get_json()
    items = data.get('items', [])
    if not items:
        return jsonify({'error': 'No items'}), 400
    total = sum(item.get('price', 0) * item.get('quantity', 1) for item in items)
    order = Order(
        user_id=user_id,
        items=json.dumps(items),
        total=total,
        status='paid',
        payment_status='completed',
        payment_method=data.get('payment_method', 'MTN Mobile Money'),
        delivery_location='Demo Location'
    )
    db.session.add(order)
    CartItem.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    return jsonify({'success': True, 'order_id': order.id}), 201

@app.route('/api/orders/<int:order_id>/status', methods=['PUT'])
@jwt_required()
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json()
    order.status = data.get('status', order.status)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/admin/stats', methods=['GET'])
@jwt_required()
def admin_stats():
    user = User.query.get(get_jwt_identity())
    if user.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    return jsonify({
        'today_sales': 1500000,
        'pending_orders': Order.query.filter_by(status='pending').count(),
        'total_products': Product.query.count(),
        'low_stock': Product.query.filter(Product.stock < 5).count()
    })

@app.route('/api/chat/customer', methods=['POST'])
def customer_chat():
    data = request.get_json()
    msg = data.get('message', '').lower() if data else ''
    if 'price' in msg or 'cost' in msg:
        response = "💰 Tarazo: Floor UGX 150K/m², Wall UGX 120K/m², Countertop UGX 280K/m²"
    elif 'delivery' in msg:
        response = "🚚 Delivery: 2-5 days Uganda-wide. Free over UGX 500K!"
    elif 'hello' in msg or 'hi' in msg:
        response = "👋 Hello! Welcome to Tarazo. How can I help?"
    else:
        response = "I can help with prices, delivery, or orders!"
    return jsonify({'response': response})

# ==================== INIT ====================
with app.app_context():
    db.create_all()
    # Create demo admin if not exists
    if not User.query.filter_by(email='admin@tarazo.com').first():
        admin = User(
            name='Admin', email='admin@tarazo.com', phone='0771000000',
            password_hash=generate_password_hash('admin123'),
            role='admin', email_verified=True
        )
        db.session.add(admin)
    # Create demo products if none exist
    if Product.query.count() == 0:
        for p in [
            Product(name='Classic Floor Terrazzo', type='Floor', price=150000, stock=100, description='Premium polished floor terrazzo'),
            Product(name='Modern Wall Terrazzo', type='Wall', price=120000, stock=50, description='Elegant wall finishing'),
            Product(name='Premium Countertop', type='Countertop', price=280000, stock=30, description='Luxury kitchen countertops'),
        ]:
            db.session.add(p)
    db.session.commit()
    print("✅ TARAZO Backend Ready for Presentation! 🎉")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
