// ======================== APP STATE ========================
const AppState = {
    user: null,
    products: [],
    cart: [],
    orders: [],
    chatOpen: false,
    pollInterval: null,
    currentPage: '',
    loading: false,
    loadingCount: 0
};

// Loading state management
function setLoading(isLoading) {
    if (isLoading) {
        AppState.loadingCount++;
    } else {
        AppState.loadingCount = Math.max(0, AppState.loadingCount - 1);
    }
    AppState.loading = AppState.loadingCount > 0;

    const buttons = document.querySelectorAll('button:not(.no-disable)');
    buttons.forEach(btn => {
        if (AppState.loading) {
            btn.disabled = true;
            btn.style.opacity = '0.6';
        } else {
            btn.disabled = false;
            btn.style.opacity = '1';
        }
    });
}

// ======================== API CONSTANTS ========================
const API_BASE_URL = 'https://raven-terazzo.onrender.com/api';
const MAX_RETRIES = 2;
const RETRY_DELAY = 1000;

// ======================== TOKEN MANAGEMENT ========================
function getAccessToken() {
    return localStorage.getItem('access_token');
}

function setAccessToken(token) {
    if (token) {
        localStorage.setItem('access_token', token);
    } else {
        localStorage.removeItem('access_token');
    }
}

function getRefreshToken() {
    return localStorage.getItem('refresh_token');
}

function setRefreshToken(token) {
    if (token) {
        localStorage.setItem('refresh_token', token);
    } else {
        localStorage.removeItem('refresh_token');
    }
}

function clearTokens() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
}

// ======================== API CALLER (NO CSRF) ========================
let isRefreshing = false;
let failedQueue = [];

function processQueue(error, token = null) {
    failedQueue.forEach(prom => {
        if (error) {
            prom.reject(error);
        } else {
            prom.resolve(token);
        }
    });
    failedQueue = [];
}

async function refreshToken() {
    const refreshTokenValue = getRefreshToken();
    if (!refreshTokenValue) return false;
    
    if (isRefreshing) {
        return new Promise((resolve, reject) => {
            failedQueue.push({ resolve, reject });
        });
    }
    
    isRefreshing = true;
    
    try {
        const response = await fetch(`${API_BASE_URL}/refresh`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${refreshTokenValue}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.access_token) {
                setAccessToken(data.access_token);
                processQueue(null, data.access_token);
                return true;
            }
        }
        processQueue(new Error('Refresh failed'), null);
        return false;
    } catch (error) {
        processQueue(error, null);
        return false;
    } finally {
        isRefreshing = false;
    }
}

async function apiCall(endpoint, options = {}, retryCount = 0) {
    const token = getAccessToken();
    
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    try {
        setLoading(true);

        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            ...options,
            headers,
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 401) {
            const refreshed = await refreshToken();
            if (refreshed && retryCount < MAX_RETRIES) {
                return apiCall(endpoint, options, retryCount + 1);
            } else {
                clearTokens();
                AppState.user = null;
                document.getElementById('appContainer').classList.add('hidden');
                document.getElementById('loginPage').classList.remove('hidden');
                showToast('Session expired. Please login again.', true);
                throw new Error('Session expired');
            }
        }

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage;
            try {
                const errorJson = JSON.parse(errorText);
                errorMessage = errorJson.error || errorJson.message || `HTTP ${response.status}`;
            } catch {
                errorMessage = errorText || `HTTP ${response.status}`;
            }
            throw new Error(errorMessage);
        }

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }

        return { success: true };

    } catch (error) {
        clearTimeout(timeoutId);
        
        if (error.name === 'AbortError') {
            showToast('Request timeout. Please try again.', true);
            throw new Error('Request timeout');
        }
        
        if (retryCount < MAX_RETRIES && (!options.method || options.method === 'GET')) {
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
            return apiCall(endpoint, options, retryCount + 1);
        }
        
        throw error;
    } finally {
        setLoading(false);
    }
}

// ======================== HELPER FUNCTIONS ========================
function escapeHtml(text) {
    if(!text) return '';
    return String(text).replace(/[&<>]/g, function(m) {
        if(m === '&') return '&amp;';
        if(m === '<') return '&lt;';
        if(m === '>') return '&gt;';
        return m;
    });
}

function safeJsonParse(data, defaultValue = []) {
    try {
        return JSON.parse(data || "[]");
    } catch(e) {
        return defaultValue;
    }
}

function showToast(msg, isError = false) {
    var toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.style.background = isError ? '#e74c3c' : '#154360';
    toast.classList.add('show');
    setTimeout(function(){ toast.classList.remove('show'); }, 3000);
}

function showModal(title, html){
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalOverlay').classList.remove('hidden');
}

function hideModal(){
    document.getElementById('modalOverlay').classList.add('hidden');
}

function closeModal(e){
    if(e.target === document.getElementById('modalOverlay')) hideModal();
}

function detectNetwork(phone){ 
    let p = String(phone).replace(/\D/g,''); 
    if(/^(077|078|076|079|039)/.test(p)) return 'MTN'; 
    if(/^(075|074|070|073|071|041)/.test(p)) return 'Airtel'; 
    return null; 
}

function validateUgPhone(phone){ 
    let p = String(phone).replace(/\D/g,''); 
    return p.length >= 9 && p.length <= 12; 
}

// ======================== PRODUCT FUNCTIONS ========================
function renderProductCard(product) {
    var stockClass = ((product.stock || 0) < 5) ? 'low' : '';
    var imageUrl = escapeHtml(product.image_url || 'https://placehold.co/600x400/1a5276/white?text=TARAZO');

    return '<div class="product-card" onclick="showProductDetail(' + (product.id || 0) + ')">' +
        '<img src="' + imageUrl + '" alt="' + escapeHtml(product.name) + '" loading="lazy">' +
        '<div class="product-info">' +
            '<div class="product-name">' + escapeHtml(product.name) + '</div>' +
            '<div class="product-type">' + escapeHtml(product.type) + '</div>' +
            '<div class="product-price">UGX ' + (product.price || 0).toLocaleString() + '</div>' +
            '<div class="product-stock ' + stockClass + '">' + (product.stock || 0) + ' in stock</div>' +
            '<button class="btn-sm btn-green no-disable" style="margin-top:8px;" onclick="event.stopPropagation();addToCart(' + (product.id || 0) + ')">🛒 Add to Cart</button>' +
        '</div>' +
    '</div>';
}

// ======================== AUTHENTICATION ========================
async function handleLogin() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const remember = document.getElementById('rememberMe').checked;

    if (!email || !password) {
        showToast('❌ Please enter email and password', true);
        return;
    }

    try {
        showToast('🔄 Logging in...');

        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email.trim(), password: password })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            if (data.access_token) setAccessToken(data.access_token);
            if (data.refresh_token) setRefreshToken(data.refresh_token);
            
            AppState.user = data.user;
            if (remember) localStorage.setItem('tarazo_email', email);
            else localStorage.removeItem('tarazo_email');

            showToast('✅ Login successful!');
            await loadProducts();
            await loadCart();
            await loadOrders();
            enterApp();
        } else {
            showToast(data.error || '❌ Login failed', true);
        }
    } catch (error) {
        console.error('Login error:', error);
        showToast(error.message || '❌ Login failed', true);
    }
}

async function handleRegister() {
    const name = document.getElementById('regName').value;
    const phone = document.getElementById('regPhone').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;
    const confirmPassword = document.getElementById('regConfirmPassword').value;

    if (!name || !email || !password) {
        showToast('Please fill all fields', true);
        return;
    }
    if (password !== confirmPassword) {
        showToast('Passwords do not match', true);
        return;
    }

    try {
        showToast('🔄 Creating account...');

        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, phone, password })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showToast('✅ Registration successful! Please login.');
            toggleAuth();
            document.getElementById('loginEmail').value = email;
        } else {
            showToast(data.error || '❌ Registration failed', true);
        }
    } catch (error) {
        showToast(error.message || '❌ Network error', true);
    }
}

async function logout() {
    try {
        const token = getAccessToken();
        if (token) {
            await fetch(`${API_BASE_URL}/logout`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
        }
    } catch(e) {}
    
    clearTokens();
    AppState.user = null;
    AppState.cart = [];
    AppState.orders = [];
    AppState.products = [];

    localStorage.removeItem('tarazo_email');
    document.getElementById('appContainer').classList.add('hidden');
    document.getElementById('loginPage').classList.remove('hidden');
    document.getElementById('loginEmail').value = '';
    document.getElementById('loginPassword').value = '';
    showToast('👋 Logged out');
    if (AppState.pollInterval) clearInterval(AppState.pollInterval);
}

function toggleAuth(){
    var a=document.getElementById('loginForm'), b=document.getElementById('registerForm'), c=document.getElementById('forgotForm');
    if(!a.classList.contains('hidden')){ a.classList.add('hidden'); b.classList.remove('hidden'); c.classList.add('hidden'); }
    else{ a.classList.remove('hidden'); b.classList.add('hidden'); c.classList.add('hidden'); }
}

function showForgotPassword(){
    document.getElementById('loginForm').classList.add('hidden');
    document.getElementById('registerForm').classList.add('hidden');
    document.getElementById('forgotForm').classList.remove('hidden');
}

function showLoginForm(){
    document.getElementById('loginForm').classList.remove('hidden');
    document.getElementById('registerForm').classList.add('hidden');
    document.getElementById('forgotForm').classList.add('hidden');
}

// ======================== DATA LOADING ========================
async function loadProducts() {
    try {
        const response = await fetch(`${API_BASE_URL}/products`);
        if (response.ok) {
            AppState.products = await response.json();
            renderShop();
        }
    } catch(e) {
        console.error('Error loading products:', e);
        AppState.products = [];
    }
}

async function loadCart() {
    if (!AppState.user) return;
    try {
        const token = getAccessToken();
        const response = await fetch(`${API_BASE_URL}/cart`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
            AppState.cart = await response.json();
            updateCartBadge();
            if (AppState.currentPage === 'userCart') renderCart();
        }
    } catch(e) {
        AppState.cart = [];
    }
}

async function loadOrders() {
    if (!AppState.user) return;
    try {
        const token = getAccessToken();
        const response = await fetch(`${API_BASE_URL}/orders`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
            AppState.orders = await response.json();
            if (AppState.currentPage === 'userOrders') renderUserOrders();
        }
    } catch(e) {
        AppState.orders = [];
    }
}

// ======================== SHOP FUNCTIONS ========================
async function renderShop(filter = 'all') {
    let products = AppState.products;
    if (filter !== 'all') {
        products = AppState.products.filter(p => p.type && p.type.toLowerCase().includes(filter.toLowerCase()));
    }
    
    var html = '';
    for(var j = 0; j < products.length; j++) {
        html += renderProductCard(products[j]);
    }
    document.getElementById('shopGrid').innerHTML = html || '<div class="empty-state">No products available</div>';
}

function searchProducts(query){
    if(!query){ renderShop(); return; }
    var filtered = AppState.products.filter(function(p){ 
        return p.name.toLowerCase().indexOf(query.toLowerCase()) !== -1; 
    });
    var html = '';
    for(var j = 0; j < filtered.length; j++){
        html += renderProductCard(filtered[j]);
    }
    document.getElementById('shopGrid').innerHTML = html;
}

function filterProducts(type, btn){
    var btns = document.querySelectorAll('.filter-btn');
    for(var i = 0; i < btns.length; i++){ btns[i].classList.remove('active'); }
    if(btn) btn.classList.add('active');
    renderShop(type);
}

async function showProductDetail(id){
    try {
        var p = AppState.products.find(function(pr){ return pr.id === id; });
        if(!p) return;
        
        var stockColor = ((p.stock || 0) < 5) ? 'var(--red)' : 'var(--green)';
        var stockMsg = ((p.stock || 0) < 5) ? '⚠️ Only ' + (p.stock || 0) + ' left!' : '✅ In Stock (' + (p.stock || 0) + ')';

        document.getElementById('detailContent').innerHTML = 
            '<img src="' + escapeHtml(p.image_url || 'https://placehold.co/600x400/1a5276/white?text=TARAZO') + '" class="detail-hero">' +
            '<div class="card">' +
                '<div class="product-name" style="font-size:22px;">' + escapeHtml(p.name) + '</div>' +
                '<div class="product-type" style="font-size:14px;margin:8px 0;">' + escapeHtml(p.type) + '</div>' +
                '<div class="product-price" style="font-size:28px;">UGX ' + (p.price || 0).toLocaleString() + '</div>' +
                '<div style="color:' + stockColor + ';font-weight:700;margin:15px 0;">' + stockMsg + '</div>' +
                '<p>' + escapeHtml(p.description || 'No description') + '</p>' +
                '<button class="btn btn-green no-disable" style="margin-top:20px;" onclick="addToCart(' + p.id + ')">🛒 Add to Cart</button>' +
                '<button class="btn btn-outline no-disable" style="margin-top:10px;" onclick="navigateTo(\'userShop\')">⬅️ Back</button>' +
            '</div>';
        navigateTo('productDetail');
    } catch(error) {
        showToast('Failed to load product details', true);
    }
}

// ======================== CART FUNCTIONS ========================
async function addToCart(productId) {
    if (!AppState.user) { showToast('Please login first', true); return; }

    try {
        const token = getAccessToken();
        const response = await fetch(`${API_BASE_URL}/cart`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ product_id: productId, quantity: 1 })
        });
        
        if (response.ok) {
            await loadCart();
            showToast('✅ Added to cart!');
        } else {
            showToast('❌ Failed to add to cart', true);
        }
    } catch(error) {
        showToast(error.message || '❌ Failed to add to cart', true);
    }
}

async function removeFromCart(cartItemId) {
    try {
        const token = getAccessToken();
        const response = await fetch(`${API_BASE_URL}/cart/${cartItemId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (response.ok) {
            await loadCart();
            renderCart();
            showToast('✅ Removed from cart');
        }
    } catch(error) {
        showToast(error.message || '❌ Failed to remove', true);
    }
}

async function renderCart() {
    if (!AppState.user) return;
    
    if(!AppState.cart || AppState.cart.length === 0){
        document.getElementById('cartItems').innerHTML = '<div class="empty-state"><div class="icon">🛒</div>Your cart is empty</div>';
        document.getElementById('cartSummary').classList.add('hidden');
        return;
    }
    
    var total = 0, html = '';
    for(var i = 0; i < AppState.cart.length; i++){
        var c = AppState.cart[i];
        var p = AppState.products.find(function(pr){ return pr.id === c.product_id; });
        if(p){
            var itemTotal = (p.price || 0) * (c.quantity || 0);
            total += itemTotal;
            html += '<div class="list-item">' +
                        '<div class="list-info">' +
                            '<h4>' + escapeHtml(p.name) + '</h4>' +
                            '<p>UGX ' + (p.price || 0).toLocaleString() + ' x ' + (c.quantity || 0) + ' = UGX ' + itemTotal.toLocaleString() + '</p>' +
                        '</div>' +
                        '<button class="btn-sm btn-red no-disable" onclick="removeFromCart(' + (c.id || 0) + ')">Remove</button>' +
                    '</div>';
        }
    }
    document.getElementById('cartItems').innerHTML = html;
    document.getElementById('cartTotal').textContent = 'UGX ' + total.toLocaleString();
    document.getElementById('cartSummary').classList.remove('hidden');
}

function showCart(){ navigateTo('userCart'); }

function showCheckout(){
    if(!AppState.cart || AppState.cart.length === 0){
        showToast('Your cart is empty', true);
        return;
    }
    var total = AppState.cart.reduce(function(s,c){ 
        var p = AppState.products.find(function(pr){ return pr.id === c.product_id; }); 
        return s + (p ? (p.price || 0) * (c.quantity || 0) : 0); 
    }, 0);
    document.getElementById('checkoutTotal').textContent = 'UGX ' + total.toLocaleString();
    navigateTo('checkoutPage');
}

function updateCartBadge(){
    var total = (AppState.cart || []).reduce(function(s,c){ return s + (c.quantity || 0); }, 0);
    var badge = document.getElementById('cartBadge');
    if(total > 0){ badge.textContent = total; badge.classList.remove('hidden'); }
    else{ badge.classList.add('hidden'); }
}

// ======================== ORDER FUNCTIONS ========================
let isSubmittingOrder = false;

async function processPayment() {
    if (isSubmittingOrder) {
        showToast('Order already processing...', false);
        return;
    }
    
    var method = document.querySelector('input[name="payMethod"]:checked').value;
    var phone = document.getElementById('payPhone').value;

    if(method !== 'card'){
        if(!phone || !validateUgPhone(phone)){ showToast('❌ Enter valid phone number', true); return; }
        var network = detectNetwork(phone);
        if(method === 'mtn' && network !== 'MTN'){ showToast('❌ Enter MTN number', true); return; }
        if(method === 'airtel' && network !== 'Airtel'){ showToast('❌ Enter Airtel number', true); return; }
    }

    if(!AppState.cart || AppState.cart.length === 0){
        showToast('Your cart is empty', true);
        return;
    }

    var total = 0;
    var items = [];
    for(var i = 0; i < AppState.cart.length; i++){ 
        var p = AppState.products.find(function(pr){ return pr.id === AppState.cart[i].product_id; }); 
        if(p){
            total += (p.price || 0) * (AppState.cart[i].quantity || 0);
            items.push({ productId: AppState.cart[i].product_id, quantity: AppState.cart[i].quantity || 1 });
        }
    }

    try {
        isSubmittingOrder = true;
        showToast('🔄 Processing order...');

        const token = getAccessToken();
        const response = await fetch(`${API_BASE_URL}/orders`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ 
                items: items, 
                total: total, 
                payment_method: method === 'mtn' ? 'MTN Mobile Money' : (method === 'airtel' ? 'Airtel Money' : 'Bank Card')
            })
        });

        const data = await response.json();

        if(response.ok && data.success){
            showToast('✅ Order placed successfully!');
            await loadCart();
            await loadOrders();
            navigateTo('userOrders');
            renderUserOrders();
            showModal('✅ Payment Successful', 
                '<div style="text-align:center;">' +
                    '<div style="font-size:48px;">✅</div>' +
                    '<div style="font-size:20px;font-weight:800;">Order Placed!</div>' +
                    '<div>Your order will be processed shortly.</div>' +
                    '<button class="btn btn-green no-disable" style="margin-top:15px;" onclick="hideModal();navigateTo(\'userOrders\')">View Orders</button>' +
                '</div>');
        } else {
            showToast(data.error || '❌ Order failed', true);
        }
    } catch(error) {
        showToast(error.message || '❌ Network error', true);
    } finally {
        setTimeout(() => {
            isSubmittingOrder = false;
        }, 3000);
    }
}

async function renderUserOrders() {
    if (!AppState.user) return;

    var myOrders = (AppState.orders || []).filter(function(o){ return o.user_id === AppState.user.id; });
    
    var html = '';
    if(myOrders.length === 0) {
        html = '<div class="empty-state">📦 No orders yet</div>';
    } else {
        for(var i = 0; i < myOrders.length; i++){
            var o = myOrders[i];
            var itemsArray = safeJsonParse(o.items);

            html += '<div class="card">' +
                        '<div style="display:flex; justify-content:space-between;">' +
                            '<div><strong>📦 Order #' + (o.id || 0) + '</strong></div>' +
                            '<div class="status-badge status-' + escapeHtml(o.status || 'pending') + '">' + escapeHtml(o.status || 'pending') + '</div>' +
                        '</div>' +
                        '<div>' + new Date(o.created_at).toLocaleDateString() + ' - ' + itemsArray.length + ' item(s)</div>' +
                        '<div style="font-size:18px;font-weight:800;margin:10px 0;">UGX ' + ((o.total || 0).toLocaleString()) + '</div>' +
                        '<div style="background:#e8f5e9;padding:12px;border-radius:12px;">' +
                            '<div style="font-weight:700;">🚚 DELIVERY</div>' +
                            '<div><strong>Rider:</strong> ' + escapeHtml(o.rider_name || 'Not assigned') + '</div>' +
                            '<div><strong>Phone:</strong> ' + escapeHtml(o.rider_phone || 'N/A') + '</div>' +
                            '<div><strong>Location:</strong> ' + escapeHtml(o.delivery_location || 'Being assigned') + '</div>' +
                        '</div>' +
                    '</div>';
        }
    }
    document.getElementById('userOrderList').innerHTML = html;
}

// ======================== PROFILE FUNCTIONS ========================
function renderUserDashboard(){
    if(!AppState.user) return;
    document.getElementById('userNameDisplay').textContent = AppState.user.name;
    document.getElementById('userEmailDisplay').textContent = AppState.user.email;
    document.getElementById('profileName').value = AppState.user.name || '';
    document.getElementById('profileEmail').value = AppState.user.email || '';
    document.getElementById('profilePhone').value = AppState.user.phone || '';
    document.getElementById('profileAddress').value = AppState.user.address || '';

    var myOrders = (AppState.orders || []).filter(function(o){ return o.user_id === AppState.user.id; });
    var pending = myOrders.filter(function(o){ return o.status === 'paid' || o.status === 'processing'; }).length;
    document.getElementById('userTotalOrders').textContent = myOrders.length;
    document.getElementById('userPendingOrders').textContent = pending;
}

function saveUserProfile(){
    showToast('Profile update coming soon');
}

// ======================== ADMIN FUNCTIONS ========================
async function renderAdminDashboard() {
    if (!AppState.user || AppState.user.role !== 'admin') return;

    try {
        const token = getAccessToken();
        const response = await fetch(`${API_BASE_URL}/admin/stats`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
            const stats = await response.json();
            document.getElementById('adminTodaySales').textContent = 'UGX ' + (stats.today_sales || 0).toLocaleString();
            document.getElementById('adminPendingOrders').textContent = stats.pending_orders || 0;
            document.getElementById('adminTotalProducts').textContent = stats.total_products || 0;
            document.getElementById('adminLowStock').textContent = stats.low_stock || 0;
        }
    } catch(error) {
        console.error('Error loading admin stats:', error);
    }
}

async function renderAdminOrders() {
    if (!AppState.user || AppState.user.role !== 'admin') return;

    try {
        const token = getAccessToken();
        const response = await fetch(`${API_BASE_URL}/admin/orders`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
            const orders = await response.json();
            var html = '';
            for(var i = 0; i < orders.length; i++){
                var o = orders[i];
                html += '<div class="list-item" onclick="viewTransactionDetails(' + (o.id || 0) + ')">' +
                            '<div class="list-info">' +
                                '<h4>📦 Transaction #' + (o.id || 0) + '</h4>' +
                                '<p>UGX ' + ((o.total || 0).toLocaleString()) + ' - ' + escapeHtml(o.status || 'pending') + '</p>' +
                            '</div>' +
                            '<div class="status-badge status-' + escapeHtml(o.status || 'pending') + '">' + escapeHtml(o.status || 'pending') + '</div>' +
                        '</div>';
            }
            document.getElementById('adminOrdersList').innerHTML = html || '<div class="empty-state">No orders found</div>';
        }
    } catch(e) {
        document.getElementById('adminOrdersList').innerHTML = '<div class="empty-state">No orders found</div>';
    }
}

function viewTransactionDetails(orderId){
    var order = (AppState.orders || []).find(function(o){ return o.id === orderId; });
    if(order){
        showModal('Order Details', 
            '<div><strong>Order #' + order.id + '</strong><br>' +
            '<strong>Total:</strong> UGX ' + ((order.total || 0).toLocaleString()) + '<br>' +
            '<strong>Status:</strong> ' + escapeHtml(order.status) + '<br>' +
            '<strong>Date:</strong> ' + new Date(order.created_at).toLocaleDateString() + '</div>');
    }
}

async function renderAdminProducts() {
    var html = '';
    for(var i = 0; i < (AppState.products || []).length; i++){
        var p = AppState.products[i];
        html += '<div class="list-item">' +
                    '<div class="list-info">' +
                        '<h4>' + escapeHtml(p.name) + '</h4>' +
                        '<p>' + escapeHtml(p.type) + ' - Stock: ' + (p.stock || 0) + '</p>' +
                        '<p>UGX ' + (p.price || 0).toLocaleString() + '</p>' +
                    '</div>' +
                    '<button class="btn-sm btn-red no-disable" onclick="deleteProductItem(' + p.id + ')">Delete</button>' +
                '</div>';
    }
    document.getElementById('adminProductList').innerHTML = html || '<div class="empty-state">No products</div>';
}

// ======================== AGENT FUNCTIONS ========================
async function renderAgentPanel() {
    if (!AppState.user || AppState.user.role !== 'agent') return;
    await loadOrders();
    
    var myOrders = (AppState.orders || []).filter(function(o) { 
        return o.agent_id === AppState.user.id && o.status !== 'delivered'; 
    });
    var html = '';
    for(var i = 0; i < myOrders.length; i++){
        var o = myOrders[i];
        html += '<div class="card">' +
                    '<div style="display:flex;justify-content:space-between;">' +
                        '<h4>📦 Order #' + (o.id || 0) + '</h4>' +
                        '<select onchange="updateOrderStatus(' + (o.id || 0) + ', this.value)" class="status-badge status-' + escapeHtml(o.status || 'pending') + '">' +
                            '<option value="paid" ' + (o.status === 'paid' ? 'selected' : '') + '>💰 Paid</option>' +
                            '<option value="processing" ' + (o.status === 'processing' ? 'selected' : '') + '>⚙️ Processing</option>' +
                            '<option value="shipped" ' + (o.status === 'shipped' ? 'selected' : '') + '>🚚 Shipped</option>' +
                            '<option value="delivered" ' + (o.status === 'delivered' ? 'selected' : '') + '>✅ Delivered</option>' +
                        '</select>' +
                    '</div>' +
                    '<p>Total: UGX ' + ((o.total || 0).toLocaleString()) + '</p>' +
                    '<button class="btn-sm btn-primary no-disable" onclick="viewTransactionDetails(' + (o.id || 0) + ')">👁️ Details</button>' +
                '</div>';
    }
    document.getElementById('agentAssignedOrders').innerHTML = html || '<div class="empty-state">No assigned orders</div>';
}

async function updateOrderStatus(orderId, newStatus){
    try {
        const token = getAccessToken();
        await fetch(`${API_BASE_URL}/orders/${orderId}/status`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ status: newStatus })
        });
        showToast('✅ Order #' + orderId + ' status: ' + newStatus);
        await loadOrders();
        renderAgentPanel();
    } catch(error) {
        showToast(error.message || '❌ Failed to update status', true);
    }
}

// ======================== CHAT FUNCTIONS ========================
async function sendChat() {
    var input = document.getElementById('chatInput');
    var text = input.value.trim();
    if(!text) return;

    addChatMessage('user', text);
    input.value = '';

    try {
        const response = await fetch(`${API_BASE_URL}/chat/customer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: text })
        });
        const data = await response.json();
        addChatMessage('bot', data.response || 'Sorry, could not process.');
    } catch(error) {
        addChatMessage('bot', 'Chat service unavailable. Please try again.');
    }
}

function addChatMessage(sender, text){
    var container = document.getElementById('chatMessages');
    var div = document.createElement('div');
    div.className = 'chat-msg ' + sender;
    div.textContent = text;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function toggleChat(){
    AppState.chatOpen = !AppState.chatOpen;
    var box = document.getElementById('chatBox');
    if(AppState.chatOpen){
        box.classList.remove('hidden');
        if(document.getElementById('chatMessages').children.length === 0){
            addChatMessage('bot', '👋 Welcome! Ask me about prices, delivery, or products!');
        }
    } else {
        box.classList.add('hidden');
    }
}

// ======================== NAVIGATION ========================
function navigateTo(pageId){
    var pages = document.querySelectorAll('.page');
    for(var i = 0; i < pages.length; i++){ pages[i].classList.add('hidden'); }
    document.getElementById(pageId).classList.remove('hidden');
    AppState.currentPage = pageId;

    if(pageId === 'userShop') renderShop();
    if(pageId === 'userCart') renderCart();
    if(pageId === 'userOrders') renderUserOrders();
    if(pageId === 'userDashboard') renderUserDashboard();
    if(pageId === 'adminDashboard') renderAdminDashboard();
    if(pageId === 'adminOrders') renderAdminOrders();
    if(pageId === 'adminProducts') renderAdminProducts();
    if(pageId === 'agentPanel') renderAgentPanel();
}

function setupNav(){
    var nav = document.getElementById('bottomNav');
    var html = '';
    if(AppState.user && AppState.user.role === 'admin'){
        html = '<div class="nav-item" onclick="navigateTo(\'adminDashboard\')">📊 Dashboard</div>' +
               '<div class="nav-item" onclick="navigateTo(\'adminProducts\')">📦 Products</div>' +
               '<div class="nav-item" onclick="navigateTo(\'adminOrders\')">📋 Orders</div>' +
               '<div class="nav-item" onclick="logout()">🚪 Exit</div>';
    } else if(AppState.user && AppState.user.role === 'agent'){
        html = '<div class="nav-item" onclick="navigateTo(\'agentPanel\')">📦 Orders</div>' +
               '<div class="nav-item" onclick="logout()">🚪 Exit</div>';
    } else if(AppState.user && AppState.user.role === 'user'){
        html = '<div class="nav-item" onclick="navigateTo(\'userShop\')">🏪 Shop</div>' +
               '<div class="nav-item" onclick="navigateTo(\'userOrders\')">📦 Orders</div>' +
               '<div class="nav-item" onclick="navigateTo(\'userCart\')">🛒 Cart</div>' +
               '<div class="nav-item" onclick="navigateTo(\'userDashboard\')">👤 Profile</div>';
    }
    nav.innerHTML = html;

    var chatWidget = document.getElementById('chatWidgetContainer');
    var whatsappWidget = document.getElementById('whatsappWidget');
    if(AppState.user && AppState.user.role === 'user'){
        if(chatWidget) chatWidget.classList.remove('hidden');
        if(whatsappWidget) whatsappWidget.classList.remove('hidden');
    } else {
        if(chatWidget) chatWidget.classList.add('hidden');
        if(whatsappWidget) whatsappWidget.classList.add('hidden');
    }
}

function setupPaymentMethodListener(){
    var radios = document.querySelectorAll('input[name="payMethod"]');
    for(var i = 0; i < radios.length; i++){
        radios[i].addEventListener('change', function(){
            var method = document.querySelector('input[name="payMethod"]:checked').value;
            var cardFields = document.getElementById('cardFields');
            if(method === 'card'){ 
                if(cardFields) cardFields.classList.remove('hidden'); 
            } else { 
                if(cardFields) cardFields.classList.add('hidden'); 
            }
        });
    }
    var payPhone = document.getElementById('payPhone');
    if(payPhone){
        payPhone.addEventListener('input', function(){
            var net = detectNetwork(payPhone.value);
            var badge = document.getElementById('networkBadge');
            if(badge){ 
                if(net){ 
                    badge.innerHTML = net; 
                    badge.classList.remove('hidden'); 
                } else { 
                    badge.classList.add('hidden'); 
                } 
            }
        });
    }
}

// ======================== STUB FUNCTIONS ========================
function searchTransactionByPhone(){ showToast('Search feature coming soon'); }
function resetTransactionSearch(){ renderAdminOrders(); }
function exportTransactionsCSV(){ showToast('CSV export coming soon'); }
function showSalesDetail(){ showModal('Sales Details', 'Today\'s sales data'); }
function showPendingDetail(){ showModal('Pending Orders', 'List of pending orders'); }
function showProductsDetail(){ showModal('Products', 'Total products: ' + (AppState.products || []).length); }
function showLowStockDetail(){ showModal('Low Stock Alert', 'Products with low stock'); }
function editProduct(id){ showToast('Edit product coming soon'); }
function deleteProductItem(id){ showToast('Delete product coming soon'); }
function resetProductForm(){ showToast('Reset form'); }
function handleImageUpload(input){ showToast('Image upload coming soon'); }
function saveProduct(){ showToast('Save product coming soon'); }
function renderAdminBooks(){ showToast('Books feature coming soon'); }
function changeBookPeriod(){}
function renderAdminMonitor(){ document.getElementById('monitorFeed').innerHTML = '<div class="empty-state">Agent monitoring coming soon</div>'; }
function renderAdminChats(){ document.getElementById('allChatsList').innerHTML = '<div class="empty-state">Chat monitoring coming soon</div>'; }
function renderAdminTeam(){ document.getElementById('teamList').innerHTML = '<div class="empty-state">Team management coming soon</div>'; }
function renderAdminDelivery(){ document.getElementById('adminDeliveryList').innerHTML = '<div class="empty-state">Delivery management coming soon</div>'; }
function renderManagerMessages(){ document.getElementById('managerMsgList').innerHTML = '<div class="empty-state">Messages coming soon</div>'; }
function claimOrderManually(orderId){ showToast('Contact admin to assign orders'); }
function showAssignRiderForm(orderId){ showToast('Assign rider - coming soon'); }
function saveRiderAssignment(orderId){ showToast('Save rider - coming soon'); }
function renderAgentConversations(){ document.getElementById('agentChatList').innerHTML = '<div class="empty-state">No conversations yet</div>'; }
function openAgentToManagerChat(){ showToast('Message manager coming soon'); }
function showAddRiderModal(){ showToast('Add rider coming soon'); }
function showAdminMenu(){ showModal('Admin Menu', '<div class="empty-state">Tools coming soon</div>'); }
function startPolling(){
    if(AppState.pollInterval) clearInterval(AppState.pollInterval);
    AppState.pollInterval = setInterval(function(){
        if(AppState.user && AppState.user.role === 'agent') renderAgentConversations();
    }, 30000);
}

// ======================== APP INITIALIZATION ========================
async function enterApp(){
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('appContainer').classList.remove('hidden');
    document.getElementById('headerGreeting').textContent = 'Hi, ' + ((AppState.user?.name || 'User').split(' ')[0] || 'User');

    setupNav();
    startPolling();
    await loadProducts();
    await loadCart();
    await loadOrders();

    if(AppState.user.role === 'admin'){
        navigateTo('adminDashboard');
        renderAdminDashboard();
        renderAdminOrders();
    } else if(AppState.user.role === 'agent'){
        navigateTo('agentPanel');
        renderAgentPanel();
    } else {
        navigateTo('userShop');
        renderShop();
    }
}

async function initApp(){
    setupPaymentMethodListener();
    
    // Check for existing token and try to restore session
    const token = getAccessToken();
    if (token) {
        try {
            await loadProducts();
            showToast('Welcome back!', false);
        } catch(e) {
            clearTokens();
        }
    }

    var splash = document.getElementById('splashPage');
    setTimeout(function(){
        splash.style.opacity = '0';
        setTimeout(function(){
            splash.classList.add('hidden');
            document.getElementById('loginPage').classList.remove('hidden');
        }, 600);
    }, 2000);
}

window.onload = initApp;
