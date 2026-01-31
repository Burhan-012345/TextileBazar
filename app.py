from flask import Flask, render_template, request, redirect, url_for, flash, send_file, make_response, jsonify, session, send_from_directory
import sqlite3
from datetime import datetime, timedelta
import io
import os
import shutil
import json
import re
from urllib.parse import quote
import hashlib
import secrets
from functools import wraps
from werkzeug.utils import secure_filename
import socket
import csv

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import A4, letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.fonts import addMapping
from reportlab.lib.utils import ImageReader
from reportlab.lib.colors import HexColor, Color
from reportlab.graphics.shapes import Drawing, Line
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics import renderPDF
import base64

app = Flask(__name__)
app.secret_key = 'textile-bazar-2024-blue-theme'
app.config['UPLOAD_FOLDER'] = 'static/temp'
app.config['QR_FOLDER'] = 'static/qr_codes'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

DATABASE = 'textile_bazar.db'

# ============================================================================
# SERVER DETECTION FUNCTIONS
# ============================================================================

def get_server_base_url():
    """Auto-detect server environment and return appropriate base URL"""
    if 'PYTHONANYWHERE_DOMAIN' in os.environ:
        username = os.environ.get('USER', 'tile10')
        return f"https://{username}.pythonanywhere.com"
    
    hostname = socket.gethostname()
    
    if 'pythonanywhere' in hostname.lower():
        return f"https://tile10.pythonanywhere.com"
    
    is_debug = app.debug or os.environ.get('FLASK_DEBUG') == '1'
    is_production_env = os.environ.get('FLASK_ENV') == 'production'
    
    if is_production_env or not is_debug:
        try:
            if request and hasattr(request, 'host'):
                return f"https://{request.host}"
        except:
            pass
        return f"https://tile10.pythonanywhere.com"
    else:
        return "http://127.0.0.1:5000"

def is_production():
    """Check if running in production environment"""
    if 'PYTHONANYWHERE_DOMAIN' in os.environ:
        return True
    
    hostname = socket.gethostname()
    if 'pythonanywhere' in hostname.lower():
        return True
    
    if os.environ.get('FLASK_ENV') == 'production':
        return True
    
    if not app.debug and os.environ.get('FLASK_DEBUG') != '1':
        return True
    
    return False

def get_pdf_download_url(filename):
    """Generate complete PDF download URL based on server environment"""
    base_url = get_server_base_url()
    return f"{base_url}{url_for('download_pdf', filename=filename)}"

# ============================================================================
# DECORATORS
# ============================================================================

def login_required(f):
    """Decorator to require login for specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'danger')
            return redirect(url_for('auth_login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'danger')
            return redirect(url_for('auth_login'))
        if session.get('role') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def get_db_connection():
    """Create and return a database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize the SQLite database with required tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            customer_name TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            item_name TEXT NOT NULL,
            price REAL NOT NULL,
            quantity INTEGER NOT NULL,
            total REAL NOT NULL,
            bill_sent INTEGER DEFAULT 0,
            bill_sent_date TEXT,
            pdf_generated INTEGER DEFAULT 0,
            pdf_filename TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL UNIQUE,
            total_purchases REAL DEFAULT 0,
            last_purchase_date TEXT,
            created_date TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            default_qr_id INTEGER
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clothing_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_code TEXT UNIQUE NOT NULL,
            item_name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            color TEXT,
            size TEXT,
            cost_price REAL NOT NULL,
            selling_price REAL NOT NULL,
            current_stock INTEGER DEFAULT 0,
            minimum_stock INTEGER DEFAULT 5,
            unit TEXT DEFAULT 'pcs',
            is_active INTEGER DEFAULT 1,
            created_date TEXT NOT NULL,
            last_updated TEXT,
            last_restock_date TEXT,
            total_sold INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stock_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            previous_stock INTEGER NOT NULL,
            new_stock INTEGER NOT NULL,
            reference_id TEXT,
            notes TEXT,
            created_by TEXT,
            created_date TEXT NOT NULL,
            FOREIGN KEY (item_id) REFERENCES clothing_items (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_name TEXT UNIQUE NOT NULL,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_date TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_qr_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            qr_type TEXT NOT NULL,
            qr_image BLOB,
            qr_url TEXT,
            upi_id TEXT,
            display_name TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # NEW: QR Payment History Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS qr_payment_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            qr_code_id INTEGER,
            transaction_id TEXT UNIQUE NOT NULL,
            customer_name TEXT NOT NULL,
            customer_phone TEXT NOT NULL,
            amount REAL NOT NULL,
            payment_method TEXT NOT NULL,
            status TEXT NOT NULL,
            notes TEXT,
            bill_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (qr_code_id) REFERENCES user_qr_codes (id),
            FOREIGN KEY (bill_id) REFERENCES items (id)
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_date ON items (date)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_item_name ON items (item_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_customer_name ON items (customer_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_phone ON items (phone_number)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_customer_phone ON customers (phone)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clothing_items_name ON clothing_items (item_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clothing_items_code ON clothing_items (item_code)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clothing_items_category ON clothing_items (category)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_stock_history_item ON stock_history (item_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_stock_history_date ON stock_history (created_date)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_qr_codes_user ON user_qr_codes (user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_qr_codes_type ON user_qr_codes (qr_type)')
    
    # NEW: Indexes for payment history
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_qr_payment_user ON qr_payment_history (user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_qr_payment_date ON qr_payment_history (created_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_qr_payment_status ON qr_payment_history (status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_qr_payment_customer ON qr_payment_history (customer_phone)')
    
    # Check for missing columns in existing tables
    cursor.execute("PRAGMA table_info(items)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'pdf_generated' not in columns:
        cursor.execute("ALTER TABLE items ADD COLUMN pdf_generated INTEGER DEFAULT 0")
        print("✓ Added missing pdf_generated column to items table")
    
    if 'pdf_filename' not in columns:
        cursor.execute("ALTER TABLE items ADD COLUMN pdf_filename TEXT")
        print("✓ Added missing pdf_filename column to items table")
    
    cursor.execute("PRAGMA table_info(users)")
    user_columns = [column[1] for column in cursor.fetchall()]
    if 'default_qr_id' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN default_qr_id INTEGER")
        print("✓ Added missing default_qr_id column to users table")
    
    # Insert default categories
    default_categories = [
        ('Shirts', 'Men\'s and Women\'s Shirts'),
        ('Pants', 'Trousers and Jeans'),
        ('T-Shirts', 'Casual T-Shirts'),
        ('Sarees', 'Traditional Sarees'),
        ('Kurtas', 'Traditional Kurtas'),
        ('Dresses', 'Women\'s Dresses'),
        ('Jackets', 'Winter Wear'),
        ('Accessories', 'Belts, Scarves, etc.')
    ]
    
    for category_name, description in default_categories:
        cursor.execute('SELECT id FROM categories WHERE category_name = ?', (category_name,))
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO categories (category_name, description, created_date)
                VALUES (?, ?, ?)
            ''', (category_name, description, datetime.now().isoformat()))
    
    # Create default admin user if not exists
    cursor.execute("SELECT COUNT(*) as count FROM users WHERE username = 'admin'")
    admin_exists = cursor.fetchone()[0]
    
    if admin_exists == 0:
        password_hash = hash_password('admin123')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@textilebazar.com', password_hash, 'Administrator', 'admin', datetime.now().isoformat()))
        print("✓ Created default admin user (username: admin, password: admin123)")
    
    conn.commit()
    conn.close()

# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

def hash_password(password):
    """Hash password using SHA-256 with salt"""
    salt = "textile-bazar-2024"
    return hashlib.sha256((password + salt).encode()).hexdigest()

def verify_password(password, hashed):
    """Verify password against hash"""
    return hash_password(password) == hashed

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate phone number (Indian format)"""
    pattern = r'^[6-9]\d{9}$'
    return re.match(pattern, phone) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter"
    
    return True, "Password is valid"

def is_account_locked(user):
    """Check if account is locked due to too many failed attempts"""
    if not user:
        return False, None
    
    if hasattr(user, '__getitem__'):
        locked_until = user.get('locked_until') if hasattr(user, 'get') else user['locked_until'] if 'locked_until' in user else None
    else:
        return False, None
    
    if locked_until:
        try:
            locked_until_dt = datetime.fromisoformat(locked_until)
            if datetime.now() < locked_until_dt:
                return True, f"Account is locked until {locked_until_dt.strftime('%Y-%m-%d %H:%M:%S')}"
        except (ValueError, TypeError, AttributeError) as e:
            app.logger.error(f"Error parsing locked_until date: {e}")
            pass
    
    return False, None

def ensure_temp_directory():
    """Ensure the temp directory exists and is clean"""
    temp_dir = os.path.join('static', 'temp')
    
    if os.path.exists(temp_dir) and not os.path.isdir(temp_dir):
        try:
            os.remove(temp_dir)
            print(f"Removed file 'temp' to create directory")
        except Exception as e:
            print(f"Error removing file 'temp': {e}")
    
    try:
        os.makedirs(temp_dir, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating temp directory: {e}")
        return False

# ============================================================================
# INVENTORY MANAGEMENT FUNCTIONS
# ============================================================================

def update_inventory_on_sale(item_name, quantity_sold, sale_id=None):
    """Update inventory when a sale is made"""
    conn = get_db_connection()
    try:
        item = conn.execute('''
            SELECT * FROM clothing_items 
            WHERE LOWER(item_name) = LOWER(?) AND is_active = 1
        ''', (item_name,)).fetchone()
        
        if not item:
            item = conn.execute('''
                SELECT * FROM clothing_items 
                WHERE item_name LIKE ? AND is_active = 1
                LIMIT 1
            ''', (f'%{item_name}%',)).fetchone()
        
        if item:
            current_stock = item['current_stock']
            new_stock = current_stock - quantity_sold
            
            if new_stock < 0:
                app.logger.warning(f"Insufficient stock for {item_name}. Current: {current_stock}, Requested: {quantity_sold}")
                conn.close()
                return False, f"Insufficient stock. Only {current_stock} available."
            
            conn.execute('''
                UPDATE clothing_items 
                SET current_stock = ?,
                    total_sold = total_sold + ?,
                    last_updated = ?
                WHERE id = ?
            ''', (new_stock, quantity_sold, datetime.now().isoformat(), item['id']))
            
            conn.execute('''
                INSERT INTO stock_history 
                (item_id, item_name, transaction_type, quantity, previous_stock, 
                 new_stock, reference_id, notes, created_by, created_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                item['id'], item['item_name'], 'sale', quantity_sold, 
                current_stock, new_stock, sale_id, 
                f'Sale of {quantity_sold} units', 
                session.get('username', 'system'), 
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            return True, f"Inventory updated: {item_name} stock reduced by {quantity_sold}"
        else:
            conn.close()
            return False, f"Item '{item_name}' not found in inventory"
            
    except Exception as e:
        conn.close()
        app.logger.error(f"Error updating inventory: {str(e)}")
        return False, f"Error updating inventory: {str(e)}"

def get_low_stock_items(threshold=None):
    """Get items with stock below minimum threshold"""
    conn = get_db_connection()
    
    if threshold:
        items = conn.execute('''
            SELECT * FROM clothing_items 
            WHERE current_stock <= ? AND is_active = 1
            ORDER BY current_stock ASC
        ''', (threshold,)).fetchall()
    else:
        items = conn.execute('''
            SELECT * FROM clothing_items 
            WHERE current_stock <= minimum_stock AND is_active = 1
            ORDER BY current_stock ASC
        ''').fetchall()
    
    conn.close()
    return items

def add_new_clothing_item(item_data):
    """Add a new clothing item to inventory"""
    conn = get_db_connection()
    
    try:
        if not item_data.get('item_code'):
            category_prefix = item_data['category'][:2].upper()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) as count FROM clothing_items 
                WHERE category = ?
            ''', (item_data['category'],))
            count = cursor.fetchone()['count']
            item_code = f"{category_prefix}{count+1:03d}"
            item_data['item_code'] = item_code
        
        cursor.execute('''
            INSERT INTO clothing_items 
            (item_code, item_name, category, description, color, size,
             cost_price, selling_price, current_stock, minimum_stock, unit,
             created_date, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            item_data['item_code'],
            item_data['item_name'],
            item_data['category'],
            item_data.get('description', ''),
            item_data.get('color', ''),
            item_data.get('size', ''),
            float(item_data['cost_price']),
            float(item_data['selling_price']),
            int(item_data.get('current_stock', 0)),
            int(item_data.get('minimum_stock', 5)),
            item_data.get('unit', 'pcs'),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        item_id = cursor.lastrowid
        
        if item_data.get('current_stock', 0) > 0:
            cursor.execute('''
                INSERT INTO stock_history 
                (item_id, item_name, transaction_type, quantity, previous_stock, 
                 new_stock, reference_id, notes, created_by, created_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                item_id, item_data['item_name'], 'purchase', 
                int(item_data.get('current_stock', 0)), 
                0, int(item_data.get('current_stock', 0)),
                None, 'Initial stock', 
                session.get('username', 'system'), 
                datetime.now().isoformat()
            ))
        
        conn.commit()
        conn.close()
        return True, f"Item '{item_data['item_name']}' added successfully"
        
    except sqlite3.IntegrityError as e:
        conn.close()
        return False, f"Item code or name already exists: {str(e)}"
    except Exception as e:
        conn.close()
        return False, f"Error adding item: {str(e)}"

def update_clothing_item(item_id, item_data):
    """Update an existing clothing item"""
    conn = get_db_connection()
    
    try:
        conn.execute('''
            UPDATE clothing_items 
            SET item_name = ?, category = ?, description = ?, color = ?, size = ?,
                cost_price = ?, selling_price = ?, minimum_stock = ?, unit = ?,
                last_updated = ?
            WHERE id = ?
        ''', (
            item_data['item_name'],
            item_data['category'],
            item_data.get('description', ''),
            item_data.get('color', ''),
            item_data.get('size', ''),
            float(item_data['cost_price']),
            float(item_data['selling_price']),
            int(item_data.get('minimum_stock', 5)),
            item_data.get('unit', 'pcs'),
            datetime.now().isoformat(),
            item_id
        ))
        
        conn.commit()
        conn.close()
        return True, f"Item updated successfully"
        
    except Exception as e:
        conn.close()
        return False, f"Error updating item: {str(e)}"

def restock_item(item_id, quantity, notes=None):
    """Add stock to an existing item"""
    conn = get_db_connection()
    
    try:
        item = conn.execute('SELECT * FROM clothing_items WHERE id = ?', (item_id,)).fetchone()
        
        if not item:
            conn.close()
            return False, "Item not found"
        
        current_stock = item['current_stock']
        new_stock = current_stock + quantity
        
        conn.execute('''
            UPDATE clothing_items 
            SET current_stock = ?,
                last_restock_date = ?,
                last_updated = ?
            WHERE id = ?
        ''', (new_stock, datetime.now().isoformat(), datetime.now().isoformat(), item_id))
        
        conn.execute('''
            INSERT INTO stock_history 
            (item_id, item_name, transaction_type, quantity, previous_stock, 
             new_stock, reference_id, notes, created_by, created_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            item_id, item['item_name'], 'purchase', quantity, 
            current_stock, new_stock, None, 
            notes or f'Restocked {quantity} units', 
            session.get('username', 'system'), 
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        return True, f"Restocked {item['item_name']} with {quantity} units"
        
    except Exception as e:
        conn.close()
        return False, f"Error restocking item: {str(e)}"

def restock_item_by_name(item_name, quantity, notes=None):
    """Add stock back to inventory by item name"""
    conn = get_db_connection()
    
    try:
        item = conn.execute('''
            SELECT * FROM clothing_items 
            WHERE LOWER(item_name) = LOWER(?) AND is_active = 1
        ''', (item_name,)).fetchone()
        
        if not item:
            item = conn.execute('''
                SELECT * FROM clothing_items 
                WHERE item_name LIKE ? AND is_active = 1
                LIMIT 1
            ''', (f'%{item_name}%',)).fetchone()
        
        if item:
            current_stock = item['current_stock']
            new_stock = current_stock + quantity
            
            conn.execute('''
                UPDATE clothing_items 
                SET current_stock = ?,
                    last_updated = ?
                WHERE id = ?
            ''', (new_stock, datetime.now().isoformat(), item['id']))
            
            conn.execute('''
                INSERT INTO stock_history 
                (item_id, item_name, transaction_type, quantity, previous_stock, 
                 new_stock, reference_id, notes, created_by, created_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                item['id'], item['item_name'], 'return', quantity, 
                current_stock, new_stock, None, 
                notes or f'Returned {quantity} units', 
                session.get('username', 'system'), 
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            return True, f"Inventory updated: {item_name} stock increased by {quantity}"
        else:
            conn.close()
            return False, f"Item '{item_name}' not found in inventory"
            
    except Exception as e:
        conn.close()
        app.logger.error(f"Error restocking inventory: {str(e)}")
        return False, f"Error restocking inventory: {str(e)}"

def get_inventory_stats():
    """Get inventory statistics"""
    conn = get_db_connection()
    
    stats = conn.execute('''
        SELECT 
            COUNT(*) as total_items,
            SUM(current_stock) as total_stock,
            SUM(CASE WHEN current_stock <= minimum_stock THEN 1 ELSE 0 END) as low_stock_count,
            SUM(current_stock * cost_price) as total_inventory_value,
            SUM(current_stock * selling_price) as total_potential_value,
            SUM(total_sold) as total_items_sold,
            SUM(total_sold * selling_price) as total_sales_value
        FROM clothing_items 
        WHERE is_active = 1
    ''').fetchone()
    
    categories = conn.execute('''
        SELECT category, COUNT(*) as item_count, SUM(current_stock) as stock_count
        FROM clothing_items 
        WHERE is_active = 1
        GROUP BY category
        ORDER BY item_count DESC
    ''').fetchall()
    
    recent_movements = conn.execute('''
        SELECT sh.*, ci.item_code
        FROM stock_history sh
        JOIN clothing_items ci ON sh.item_id = ci.id
        ORDER BY sh.created_date DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    return {
        'stats': stats,
        'categories': categories,
        'recent_movements': recent_movements
    }

# ============================================================================
# QR CODE HELPER FUNCTIONS
# ============================================================================

def allowed_file(filename):
    """Check if file extension is allowed"""
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def validate_upi_id(upi_id):
    """Validate UPI ID format"""
    pattern = r'^[a-zA-Z0-9.\-_]{2,49}@[a-zA-Z]{2,15}$'
    return re.match(pattern, upi_id) is not None

def generate_upi_qr_code(upi_id):
    """Generate QR code URL for UPI ID"""
    # Create a simple UPI payment URL
    upi_url = f"upi://pay?pa={upi_id}&pn=Textile%20Bazar&mc=0000&mode=02&purpose=00"
    
    # You can integrate with a QR code generation service here
    # For now, we'll use a placeholder
    return f"/static/qr_placeholder.png"

def ensure_qr_directory():
    """Ensure the QR code directory exists"""
    qr_dir = os.path.join('static', 'qr_codes')
    
    if os.path.exists(qr_dir) and not os.path.isdir(qr_dir):
        try:
            os.remove(qr_dir)
            print(f"Removed file 'qr_codes' to create directory")
        except Exception as e:
            print(f"Error removing file 'qr_codes': {e}")
    
    try:
        os.makedirs(qr_dir, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating QR directory: {e}")
        return False

# ============================================================================
# QR PAYMENT HISTORY FUNCTIONS
# ============================================================================

def generate_transaction_id():
    """Generate a unique transaction ID"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_str = secrets.token_hex(4).upper()
    return f"TX{timestamp}{random_str}"

def record_qr_payment(user_id, qr_code_id, customer_name, customer_phone, amount, 
                     payment_method='cash', status='pending', notes=None, bill_id=None):
    """Record a QR payment in the database"""
    conn = get_db_connection()
    try:
        transaction_id = generate_transaction_id()
        now = datetime.now().isoformat()
        
        conn.execute('''
            INSERT INTO qr_payment_history 
            (user_id, qr_code_id, transaction_id, customer_name, customer_phone, 
             amount, payment_method, status, notes, bill_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, qr_code_id, transaction_id, customer_name, customer_phone,
            amount, payment_method, status, notes, bill_id, now, now
        ))
        
        conn.commit()
        payment_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        
        return True, payment_id, transaction_id
    except sqlite3.IntegrityError as e:
        conn.close()
        return False, None, f"Transaction ID already exists: {str(e)}"
    except Exception as e:
        conn.close()
        return False, None, f"Error recording payment: {str(e)}"

def get_qr_payment_stats(user_id):
    """Get payment statistics for a user"""
    conn = get_db_connection()
    
    stats = conn.execute('''
        SELECT 
            COUNT(*) as total_transactions,
            SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END) as total_received,
            SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END) as pending_amount,
            SUM(CASE WHEN status = 'failed' THEN amount ELSE 0 END) as failed_amount,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_count,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_count,
            CASE 
                WHEN COUNT(*) > 0 THEN 
                    ROUND((SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 1)
                ELSE 0 
            END as success_rate
        FROM qr_payment_history 
        WHERE user_id = ?
    ''', (user_id,)).fetchone()
    
    conn.close()
    
    if stats:
        return dict(stats)
    else:
        return {
            'total_transactions': 0,
            'total_received': 0,
            'pending_amount': 0,
            'failed_amount': 0,
            'completed_count': 0,
            'pending_count': 0,
            'failed_count': 0,
            'success_rate': 0
        }

def get_recent_qr_payments(user_id, limit=10):
    """Get recent QR payments for a user"""
    conn = get_db_connection()
    
    payments = conn.execute('''
        SELECT qp.*, qc.display_name as qr_code_name, qc.qr_type
        FROM qr_payment_history qp
        LEFT JOIN user_qr_codes qc ON qp.qr_code_id = qc.id
        WHERE qp.user_id = ?
        ORDER BY qp.created_at DESC
        LIMIT ?
    ''', (user_id, limit)).fetchall()
    
    conn.close()
    return payments

def get_qr_payment_count(user_id):
    """Get total number of QR payments for a user"""
    conn = get_db_connection()
    
    count = conn.execute('''
        SELECT COUNT(*) as count 
        FROM qr_payment_history 
        WHERE user_id = ?
    ''', (user_id,)).fetchone()['count']
    
    conn.close()
    return count

def update_payment_status(payment_id, user_id, status, notes=None):
    """Update payment status"""
    conn = get_db_connection()
    
    try:
        conn.execute('''
            UPDATE qr_payment_history 
            SET status = ?, notes = COALESCE(?, notes), updated_at = ?
            WHERE id = ? AND user_id = ?
        ''', (status, notes, datetime.now().isoformat(), payment_id, user_id))
        
        conn.commit()
        conn.close()
        return True, "Payment status updated successfully"
    except Exception as e:
        conn.close()
        return False, f"Error updating payment status: {str(e)}"

def get_qr_payment_by_id(payment_id, user_id):
    """Get payment details by ID"""
    conn = get_db_connection()
    
    payment = conn.execute('''
        SELECT qp.*, qc.display_name as qr_code_name, qc.qr_type, qc.qr_url,
               i.date as bill_date, i.total as bill_amount
        FROM qr_payment_history qp
        LEFT JOIN user_qr_codes qc ON qp.qr_code_id = qc.id
        LEFT JOIN items i ON qp.bill_id = i.id
        WHERE qp.id = ? AND qp.user_id = ?
    ''', (payment_id, user_id)).fetchone()
    
    conn.close()
    return payment

def search_qr_payments(user_id, search_query=None, start_date=None, end_date=None, 
                      status=None, payment_method=None, limit=50, offset=0):
    """Search and filter QR payments"""
    conn = get_db_connection()
    
    query = '''
        SELECT qp.*, qc.display_name as qr_code_name, qc.qr_type
        FROM qr_payment_history qp
        LEFT JOIN user_qr_codes qc ON qp.qr_code_id = qc.id
        WHERE qp.user_id = ?
    '''
    params = [user_id]
    
    if search_query:
        query += '''
            AND (qp.customer_name LIKE ? OR qp.customer_phone LIKE ? 
                 OR qp.transaction_id LIKE ? OR qp.notes LIKE ?)
        '''
        search_term = f'%{search_query}%'
        params.extend([search_term, search_term, search_term, search_term])
    
    if start_date:
        query += ' AND DATE(qp.created_at) >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND DATE(qp.created_at) <= ?'
        params.append(end_date)
    
    if status:
        query += ' AND qp.status = ?'
        params.append(status)
    
    if payment_method:
        query += ' AND qp.payment_method = ?'
        params.append(payment_method)
    
    query += ' ORDER BY qp.created_at DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    payments = conn.execute(query, params).fetchall()
    
    # Get total count for pagination
    count_query = '''
        SELECT COUNT(*) as count
        FROM qr_payment_history qp
        WHERE qp.user_id = ?
    '''
    count_params = [user_id]
    
    if search_query:
        count_query += '''
            AND (qp.customer_name LIKE ? OR qp.customer_phone LIKE ? 
                 OR qp.transaction_id LIKE ? OR qp.notes LIKE ?)
        '''
        search_term = f'%{search_query}%'
        count_params.extend([search_term, search_term, search_term, search_term])
    
    if start_date:
        count_query += ' AND DATE(qp.created_at) >= ?'
        count_params.append(start_date)
    
    if end_date:
        count_query += ' AND DATE(qp.created_at) <= ?'
        count_params.append(end_date)
    
    if status:
        count_query += ' AND qp.status = ?'
        count_params.append(status)
    
    if payment_method:
        count_query += ' AND qp.payment_method = ?'
        count_params.append(payment_method)
    
    count_result = conn.execute(count_query, count_params).fetchone()
    total_count = count_result['count'] if count_result else 0
    
    conn.close()
    
    return payments, total_count

def export_qr_payments_csv(user_id, payments):
    """Export payments to CSV format"""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Transaction ID', 'Date', 'Customer Name', 'Customer Phone', 
        'Amount', 'Payment Method', 'Status', 'QR Code', 'Notes'
    ])
    
    # Write data
    for payment in payments:
        writer.writerow([
            payment['transaction_id'],
            payment['created_at'][:19],
            payment['customer_name'],
            payment['customer_phone'],
            f"₹{payment['amount']:,.2f}",
            payment['payment_method'].upper(),
            payment['status'].title(),
            payment['qr_code_name'] or 'N/A',
            payment['notes'] or ''
        ])
    
    return output.getvalue()

# ============================================================================
# INTRO / LANDING PAGE ROUTES
# ============================================================================

@app.route('/')
def intro():
    """Intro/Landing page - accessible without login"""
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url(),
        'environment': 'Production' if is_production() else 'Development'
    }
    return render_template('intro.html', server_info=server_info)

@app.route('/home', endpoint='home')
@login_required
def home():
    """Home page after login - displays records for selected date"""
    selected_date = request.args.get('date')
    
    if not selected_date:
        selected_date = datetime.now().strftime('%Y-%m-%d')
    
    conn = get_db_connection()
    
    items = conn.execute(
        '''SELECT i.*, 
                  CASE WHEN i.bill_sent = 1 THEN 'Yes' ELSE 'No' END as bill_sent_status,
                  CASE WHEN i.pdf_generated = 1 THEN 'Yes' ELSE 'No' END as pdf_generated_status
           FROM items i 
           WHERE date = ? 
           ORDER BY customer_name, item_name''',
        (selected_date,)
    ).fetchall()
    
    daily_total_result = conn.execute(
        'SELECT SUM(total) as total FROM items WHERE date = ?',
        (selected_date,)
    ).fetchone()
    daily_total = daily_total_result['total'] if daily_total_result['total'] is not None else 0
    
    available_dates = conn.execute(
        'SELECT DISTINCT date FROM items ORDER BY date DESC LIMIT 10'
    ).fetchall()
    
    today_stats = conn.execute('''
        SELECT 
            COUNT(DISTINCT customer_name) as total_customers,
            COUNT(*) as total_transactions,
            SUM(quantity) as total_items
        FROM items 
        WHERE date = ?
    ''', (selected_date,)).fetchone()
    
    inventory_stats = conn.execute('''
        SELECT 
            COUNT(*) as total_items,
            SUM(current_stock) as total_stock,
            SUM(CASE WHEN current_stock <= minimum_stock THEN 1 ELSE 0 END) as low_stock_count,
            SUM(current_stock * cost_price) as total_inventory_value
        FROM clothing_items 
        WHERE is_active = 1
    ''').fetchone()
    
    low_stock_items = conn.execute('''
        SELECT * FROM clothing_items 
        WHERE is_active = 1 AND current_stock <= minimum_stock
        ORDER BY current_stock ASC
        LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url(),
        'environment': 'Production' if is_production() else 'Development'
    }
    
    return render_template('index.html', 
                         items=items, 
                         selected_date=selected_date,
                         daily_total=daily_total,
                         available_dates=available_dates,
                         today_stats=today_stats,
                         inventory_stats=inventory_stats,
                         low_stock_items=low_stock_items,
                         server_info=server_info)

# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        remember = 'remember' in request.form
        
        conn = get_db_connection()
        
        try:
            user = conn.execute('''
                SELECT * FROM users 
                WHERE (username = ? OR email = ?) AND is_active = 1
            ''', (username, username)).fetchone()
            
            if not user:
                flash('Invalid username or password', 'danger')
                return redirect(url_for('auth_login'))
            
            locked, message = is_account_locked(user)
            if locked:
                flash(message, 'danger')
                conn.close()
                return redirect(url_for('auth_login'))
            
            if verify_password(password, user['password_hash']):
                conn.execute('''
                    UPDATE users 
                    SET failed_attempts = 0, 
                        locked_until = NULL,
                        last_login = ?
                    WHERE id = ?
                ''', (datetime.now().isoformat(), user['id']))
                
                conn.commit()
                
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['full_name'] = user['full_name']
                session['role'] = user['role']
                session['logged_in'] = True
                
                if remember:
                    session.permanent = True
                
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                return redirect(url_for('home'))
            
            else:
                new_attempts = user['failed_attempts'] + 1
                lock_until = None
                
                if new_attempts >= 5:
                    lock_until = (datetime.now() + timedelta(minutes=30)).isoformat()
                    flash('Too many failed attempts. Account locked for 30 minutes.', 'danger')
                else:
                    flash(f'Invalid password. {5 - new_attempts} attempts remaining.', 'danger')
                
                conn.execute('''
                    UPDATE users 
                    SET failed_attempts = ?, 
                        locked_until = ?
                    WHERE id = ?
                ''', (new_attempts, lock_until, user['id']))
                
                conn.commit()
                return redirect(url_for('auth_login'))
                
        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
            return redirect(url_for('auth_login'))
        finally:
            conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    return render_template('auth/login.html', server_info=server_info)

@app.route('/auth/register', methods=['GET', 'POST'])
def auth_register():
    """User registration"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        full_name = request.form['full_name'].strip()
        phone = request.form.get('phone', '').strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not all([username, email, full_name, password, confirm_password]):
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('auth_register'))
        
        if not validate_email(email):
            flash('Please enter a valid email address', 'danger')
            return redirect(url_for('auth_register'))
        
        if phone and not validate_phone(phone):
            flash('Please enter a valid 10-digit Indian phone number', 'danger')
            return redirect(url_for('auth_register'))
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('auth_register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth_register'))
        
        conn = get_db_connection()
        try:
            existing_user = conn.execute('''
                SELECT * FROM users 
                WHERE username = ? OR email = ?
            ''', (username, email)).fetchone()
            
            if existing_user:
                if existing_user['username'] == username:
                    flash('Username already exists', 'danger')
                else:
                    flash('Email already registered', 'danger')
                return redirect(url_for('auth_register'))
            
            password_hash = hash_password(password)
            conn.execute('''
                INSERT INTO users (username, email, password_hash, full_name, phone, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, email, password_hash, full_name, phone, datetime.now().isoformat()))
            
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth_login'))
            
        except Exception as e:
            flash(f'Registration error: {str(e)}', 'danger')
            return redirect(url_for('auth_register'))
        finally:
            conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    return render_template('auth/register.html', server_info=server_info)

@app.route('/auth/forgot-password', methods=['GET', 'POST'])
def auth_forgot_password():
    """Forgot password - check email and auto-proceed to reset"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address', 'danger')
            return redirect(url_for('auth_forgot_password'))
        
        if not validate_email(email):
            flash('Please enter a valid email address', 'danger')
            return redirect(url_for('auth_forgot_password'))
        
        conn = get_db_connection()
        try:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user:
                session['reset_email'] = email
                session['reset_verified'] = True
                
                flash('Email verified successfully. Please set your new password.', 'success')
                
                conn.close()
                return redirect(url_for('auth_reset_password'))
            else:
                flash('Email not found in our system. Please check and try again.', 'danger')
                conn.close()
                return redirect(url_for('auth_forgot_password'))
                
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('auth_forgot_password'))
        finally:
            if 'conn' in locals():
                conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    return render_template('auth/forgot_password.html', server_info=server_info)

@app.route('/api/check-email', methods=['GET'])
def api_check_email():
    """API endpoint to check if email exists"""
    email = request.args.get('email', '').strip().lower()
    
    if not email:
        return jsonify({
            'exists': False, 
            'message': 'Email is required',
            'timestamp': datetime.now().isoformat()
        })
    
    if not validate_email(email):
        return jsonify({
            'exists': False, 
            'message': 'Invalid email format',
            'timestamp': datetime.now().isoformat()
        })
    
    conn = get_db_connection()
    try:
        user = conn.execute(
            'SELECT id, email, full_name, username, is_active FROM users WHERE LOWER(email) = ?',
            (email,)
        ).fetchone()
        
        if user:
            if not user['is_active']:
                return jsonify({
                    'exists': True,
                    'active': False,
                    'message': 'Account is deactivated. Please contact administrator.',
                    'user': {
                        'id': user['id'],
                        'email': user['email'],
                        'full_name': user['full_name'],
                        'username': user['username']
                    },
                    'timestamp': datetime.now().isoformat()
                })
            
            return jsonify({
                'exists': True,
                'active': True,
                'message': 'Email verified successfully',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'full_name': user['full_name'],
                    'username': user['username']
                },
                'redirect_url': url_for('auth_reset_password'),
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'exists': False, 
                'message': 'Email not found in our system',
                'suggestion': 'Please check the email or register for a new account',
                'register_url': url_for('auth_register'),
                'timestamp': datetime.now().isoformat()
            })
            
    except Exception as e:
        app.logger.error(f'Error checking email {email}: {str(e)}')
        return jsonify({
            'exists': False, 
            'message': f'Server error: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500
    finally:
        conn.close()

@app.route('/auth/reset-password', methods=['GET', 'POST'])
def auth_reset_password():
    """Reset password after email verification"""
    if not session.get('reset_verified') or not session.get('reset_email'):
        flash('Please verify your email first', 'danger')
        return redirect(url_for('auth_forgot_password'))
    
    email = session['reset_email']
    
    if request.method == 'GET':
        server_info = {
            'is_production': is_production(),
            'base_url': get_server_base_url()
        }
        return render_template('auth/reset_password.html', email=email, server_info=server_info)
    
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    
    if password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('auth_reset_password'))
    
    is_valid, message = validate_password(password)
    if not is_valid:
        flash(message, 'danger')
        return redirect(url_for('auth_reset_password'))
    
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if not user:
            flash('User not found', 'danger')
            session.pop('reset_email', None)
            session.pop('reset_verified', None)
            return redirect(url_for('auth_forgot_password'))
        
        password_hash = hash_password(password)
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                    (password_hash, user['id']))
        
        conn.commit()
        
        session.pop('reset_email', None)
        session.pop('reset_verified', None)
        
        flash('Password reset successful! Please login with your new password.', 'success')
        return redirect(url_for('auth_login'))
        
    except Exception as e:
        flash(f'Error resetting password: {str(e)}', 'danger')
        return redirect(url_for('auth_reset_password'))
    finally:
        conn.close()

@app.route('/auth/logout')
def auth_logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('intro'))

@app.route('/auth/profile')
@login_required
def auth_profile():
    """User profile"""
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        # Get recent QR payments
        recent_payments = get_recent_qr_payments(session['user_id'], limit=3)
        
        # Get payment statistics
        payment_stats = get_qr_payment_stats(session['user_id'])
        
        server_info = {
            'is_production': is_production(),
            'base_url': get_server_base_url()
        }
        
        return render_template('auth/profile.html', 
                             user=user, 
                             recent_payments=recent_payments,
                             payment_stats=payment_stats,
                             server_info=server_info)
        
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'danger')
        return redirect(url_for('home'))
    finally:
        conn.close()

@app.route('/auth/change-password', methods=['GET', 'POST'])
@login_required
def auth_change_password():
    """Change password for logged in users"""
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        conn = get_db_connection()
        try:
            user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            
            if not verify_password(current_password, user['password_hash']):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('auth_change_password'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('auth_change_password'))
            
            is_valid, message = validate_password(new_password)
            if not is_valid:
                flash(message, 'danger')
                return redirect(url_for('auth_change_password'))
            
            new_password_hash = hash_password(new_password)
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                        (new_password_hash, session['user_id']))
            conn.commit()
            
            flash('Password changed successfully!', 'success')
            return redirect(url_for('auth_profile'))
            
        except Exception as e:
            flash(f'Error changing password: {str(e)}', 'danger')
            return redirect(url_for('auth_change_password'))
        finally:
            conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    return render_template('auth/change_password.html', server_info=server_info)

# ============================================================================
# PAYMENTS & QR CODE MANAGEMENT ROUTES
# ============================================================================

@app.route('/payments/qr-codes', methods=['GET', 'POST'])
@login_required
def payments_qr_codes():
    """Manage user's payment QR codes"""
    conn = get_db_connection()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'upload':
            # Handle QR code upload
            qr_type = request.form.get('qr_type', '').strip()
            display_name = request.form.get('display_name', '').strip()
            upi_id = request.form.get('upi_id', '').strip()
            
            if not qr_type:
                flash('Please select a QR code type', 'danger')
                return redirect(url_for('payments_qr_codes'))
            
            qr_image = None
            qr_url = None
            
            # Check if file was uploaded
            if 'qr_image' in request.files:
                file = request.files['qr_image']
                if file and file.filename and allowed_file(file.filename):
                    # Ensure QR directory exists
                    ensure_qr_directory()
                    
                    # Save file
                    timestamp = int(datetime.now().timestamp())
                    filename = secure_filename(f"qr_{session['user_id']}_{timestamp}_{file.filename}")
                    
                    qr_dir = os.path.join('static', 'qr_codes')
                    filepath = os.path.join(qr_dir, filename)
                    file.save(filepath)
                    
                    # Store relative path
                    qr_url = f"/static/qr_codes/{filename}"
                else:
                    flash('Please upload a valid image file (PNG, JPG, JPEG, GIF, SVG)', 'danger')
                    return redirect(url_for('payments_qr_codes'))
            
            # If no file uploaded but UPI ID provided, generate QR code
            elif upi_id:
                # Validate UPI ID
                if not validate_upi_id(upi_id):
                    flash('Please enter a valid UPI ID (e.g., username@upi)', 'danger')
                    return redirect(url_for('payments_qr_codes'))
                
                # Generate QR code URL
                qr_url = generate_upi_qr_code(upi_id)
            
            else:
                flash('Please either upload a QR code image or enter a UPI ID', 'danger')
                return redirect(url_for('payments_qr_codes'))
            
            # Save to database
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO user_qr_codes 
                    (user_id, qr_type, qr_image, qr_url, upi_id, display_name, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session['user_id'],
                    qr_type,
                    qr_image,
                    qr_url,
                    upi_id if upi_id else None,
                    display_name if display_name else f"{qr_type.capitalize()} QR",
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
                
                conn.commit()
                flash(f'{display_name or qr_type.capitalize()} QR code added successfully!', 'success')
                
            except Exception as e:
                flash(f'Error saving QR code: {str(e)}', 'danger')
                return redirect(url_for('payments_qr_codes'))
        
        elif action == 'delete':
            qr_id = request.form.get('qr_id')
            if qr_id:
                try:
                    # First get the QR code to check if it has a file that needs to be deleted
                    qr = conn.execute(
                        'SELECT qr_url FROM user_qr_codes WHERE id = ? AND user_id = ?',
                        (qr_id, session['user_id'])
                    ).fetchone()
                    
                    if qr and qr['qr_url'] and qr['qr_url'].startswith('/static/qr_codes/'):
                        # Delete the file
                        try:
                            filename = qr['qr_url'].replace('/static/qr_codes/', '')
                            filepath = os.path.join('static', 'qr_codes', filename)
                            if os.path.exists(filepath):
                                os.remove(filepath)
                        except Exception as e:
                            app.logger.error(f"Error deleting QR file: {e}")
                    
                    # Delete from database
                    conn.execute(
                        'DELETE FROM user_qr_codes WHERE id = ? AND user_id = ?',
                        (qr_id, session['user_id'])
                    )
                    conn.commit()
                    
                    flash('QR code deleted successfully!', 'success')
                    
                except Exception as e:
                    flash(f'Error deleting QR code: {str(e)}', 'danger')
        
        elif action == 'toggle':
            qr_id = request.form.get('qr_id')
            if qr_id:
                try:
                    # Get current status
                    current = conn.execute(
                        'SELECT is_active FROM user_qr_codes WHERE id = ? AND user_id = ?',
                        (qr_id, session['user_id'])
                    ).fetchone()
                    
                    if current:
                        new_status = 0 if current['is_active'] else 1
                        conn.execute(
                            'UPDATE user_qr_codes SET is_active = ?, updated_at = ? WHERE id = ? AND user_id = ?',
                            (new_status, datetime.now().isoformat(), qr_id, session['user_id'])
                        )
                        conn.commit()
                        
                        status_text = "activated" if new_status else "deactivated"
                        flash(f'QR code {status_text} successfully!', 'success')
                        
                except Exception as e:
                    flash(f'Error updating QR code: {str(e)}', 'danger')
    
    # Get user's QR codes
    qr_codes = conn.execute('''
        SELECT * FROM user_qr_codes 
        WHERE user_id = ? 
        ORDER BY is_active DESC, created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get user info for display
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Get QR statistics
    qr_stats = conn.execute('''
        SELECT 
            COUNT(*) as total_qr_codes,
            SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_qr_codes,
            SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) as inactive_qr_codes
        FROM user_qr_codes 
        WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Count default QR codes
    default_qr_count = conn.execute('''
        SELECT COUNT(*) as count 
        FROM user_qr_codes 
        WHERE user_id = ? AND id = (SELECT default_qr_id FROM users WHERE id = ?)
    ''', (session['user_id'], session['user_id'])).fetchone()
    
    # Get payment statistics
    payment_stats = get_qr_payment_stats(session['user_id'])
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    # Add default_qr_codes to qr_stats
    if qr_stats:
        qr_stats = dict(qr_stats)  # Convert from Row to dict
        qr_stats['default_qr_codes'] = default_qr_count['count'] if default_qr_count else 0
        qr_stats['total_payments'] = payment_stats['total_received']
    else:
        qr_stats = {
            'total_qr_codes': 0,
            'active_qr_codes': 0,
            'inactive_qr_codes': 0,
            'default_qr_codes': 0,
            'total_payments': 0
        }
    
    return render_template('payments/qr_codes.html',
                         user=user,
                         qr_codes=qr_codes,
                         qr_stats=qr_stats,
                         payment_stats=payment_stats,
                         server_info=server_info)
                         
@app.route('/payments/delete/<int:id>', methods=['POST'])
@login_required
def delete_qr_payment(id):
    """Delete a QR payment"""
    conn = get_db_connection()
    
    try:
        # Check if payment belongs to user
        payment = conn.execute(
            'SELECT * FROM qr_payment_history WHERE id = ? AND user_id = ?',
            (id, session['user_id'])
        ).fetchone()
        
        if not payment:
            flash('Payment not found or access denied!', 'danger')
            return redirect(url_for('payments_history'))
        
        # Delete the payment
        conn.execute(
            'DELETE FROM qr_payment_history WHERE id = ? AND user_id = ?',
            (id, session['user_id'])
        )
        conn.commit()
        
        flash('Payment deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting payment: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('payments_history'))
                         
@app.route('/payments/qr-codes/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_qr_payment(id):
    """Edit QR payment details"""
    conn = get_db_connection()
    
    # Get the payment
    payment = get_qr_payment_by_id(id, session['user_id'])
    
    if not payment:
        flash('Payment not found or access denied!', 'danger')
        return redirect(url_for('payments_history'))
    
    if request.method == 'POST':
        # Update payment details
        customer_name = request.form['customer_name'].strip()
        customer_phone = request.form['customer_phone'].strip()
        amount = float(request.form['amount'])
        payment_method = request.form.get('payment_method', 'cash')  # Default to cash
        qr_code_id = request.form.get('qr_code_id')
        status = request.form.get('status', 'completed')
        notes = request.form.get('notes', '').strip()
        bill_id = request.form.get('bill_id')
        
        # Validate required fields
        if not customer_name or not customer_phone:
            flash('Customer name and phone are required', 'danger')
            return redirect(url_for('edit_qr_payment', id=id))
        
        if amount <= 0:
            flash('Amount must be greater than 0', 'danger')
            return redirect(url_for('edit_qr_payment', id=id))
        
        # Validate phone number
        if not validate_phone(customer_phone):
            flash('Please enter a valid 10-digit Indian phone number', 'danger')
            return redirect(url_for('edit_qr_payment', id=id))
        
        # Convert bill_id to integer if provided
        if bill_id:
            try:
                bill_id = int(bill_id)
            except ValueError:
                bill_id = None
        
        try:
            conn.execute('''
                UPDATE qr_payment_history 
                SET customer_name = ?, customer_phone = ?, amount = ?, 
                    payment_method = ?, qr_code_id = ?, status = ?, 
                    notes = ?, bill_id = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
            ''', (
                customer_name, customer_phone, amount, payment_method,
                qr_code_id, status, notes, bill_id,
                datetime.now().isoformat(), id, session['user_id']
            ))
            
            conn.commit()
            flash('Payment updated successfully!', 'success')
            return redirect(url_for('view_payment', id=id))
            
        except Exception as e:
            flash(f'Error updating payment: {str(e)}', 'danger')
            return redirect(url_for('edit_qr_payment', id=id))
    
    # GET request - show edit form
    qr_codes = conn.execute('''
        SELECT * FROM user_qr_codes 
        WHERE user_id = ? AND is_active = 1
        ORDER BY display_name
    ''', (session['user_id'],)).fetchall()
    
    # Get recent bills for linking
    recent_bills = conn.execute('''
        SELECT i.id, i.date, i.customer_name, i.total
        FROM items i
        WHERE i.date >= DATE('now', '-30 days')
        ORDER BY i.date DESC, i.id DESC
        LIMIT 20
    ''').fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('payments/edit_qr_payment.html',
                         qr_payment=payment,
                         qr_codes=qr_codes,
                         recent_bills=recent_bills,
                         server_info=server_info)

@app.route('/payments/qr-codes/default/<int:qr_id>')
@login_required
def set_default_qr_code(qr_id):
    """Set a QR code as default"""
    conn = get_db_connection()
    
    try:
        # First, check if QR code belongs to user
        qr = conn.execute(
            'SELECT id FROM user_qr_codes WHERE id = ? AND user_id = ?',
            (qr_id, session['user_id'])
        ).fetchone()
        
        if not qr:
            flash('QR code not found!', 'danger')
            return redirect(url_for('payments_qr_codes'))
        
        # Set this as the user's default QR code
        conn.execute(
            'UPDATE users SET default_qr_id = ? WHERE id = ?',
            (qr_id, session['user_id'])
        )
        conn.commit()
        
        flash('Default QR code updated successfully!', 'success')
        
    except Exception as e:
        flash(f'Error setting default QR code: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('payments_qr_codes'))

@app.route('/payments/qr-codes/<int:qr_id>')
@login_required
def view_qr_code(qr_id):
    """View QR code details"""
    conn = get_db_connection()
    
    qr = conn.execute('''
        SELECT qc.*, u.username, u.full_name
        FROM user_qr_codes qc
        JOIN users u ON qc.user_id = u.id
        WHERE qc.id = ? AND (qc.user_id = ? OR u.role = 'admin')
    ''', (qr_id, session['user_id'])).fetchone()
    
    if not qr:
        flash('QR code not found or access denied!', 'danger')
        return redirect(url_for('auth_profile'))
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('payments/view_qr_code.html',
                         qr=qr,
                         server_info=server_info)

# ============================================================================
# PAYMENT HISTORY ROUTES
# ============================================================================

@app.route('/payments/history', methods=['GET'])
@login_required
def payments_history():
    """View all QR payments with filtering"""
    # Get filter parameters
    search_query = request.args.get('search', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    status = request.args.get('status', '').strip()
    payment_method = request.args.get('payment_method', '').strip()
    page = request.args.get('page', 1, type=int)
    
    # Set default end date to today if start_date is provided
    if start_date and not end_date:
        end_date = datetime.now().strftime('%Y-%m-%d')
    
    # Pagination
    limit = 20
    offset = (page - 1) * limit
    
    # Get payments with filters
    payments, total_count = search_qr_payments(
        session['user_id'],
        search_query=search_query,
        start_date=start_date,
        end_date=end_date,
        status=status,
        payment_method=payment_method,
        limit=limit,
        offset=offset
    )
    
    # Get payment statistics
    payment_stats = get_qr_payment_stats(session['user_id'])
    
    # Calculate pagination
    total_pages = (total_count + limit - 1) // limit
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('payments/qr_payments_list.html',
                         payments=payments,
                         payment_stats=payment_stats,
                         search_query=search_query,
                         start_date=start_date,
                         end_date=end_date,
                         status=status,
                         payment_method=payment_method,
                         page=page,
                         total_pages=total_pages,
                         total_count=total_count,
                         server_info=server_info)

@app.route('/payments/add', methods=['GET', 'POST'])
@login_required
def add_payment():
    """Add a new QR payment manually"""
    conn = get_db_connection()
    
    if request.method == 'POST':
        customer_name = request.form['customer_name'].strip()
        customer_phone = request.form['customer_phone'].strip()
        amount = float(request.form['amount'])
        payment_method = request.form.get('payment_method', 'cash')  # Default to cash
        qr_code_id = request.form.get('qr_code_id')
        status = request.form.get('status', 'completed')
        notes = request.form.get('notes', '').strip()
        bill_id = request.form.get('bill_id')
        
        # Validate required fields
        if not customer_name or not customer_phone:
            flash('Customer name and phone are required', 'danger')
            return redirect(url_for('add_payment'))
        
        if amount <= 0:
            flash('Amount must be greater than 0', 'danger')
            return redirect(url_for('add_payment'))
        
        # Validate phone number
        if not validate_phone(customer_phone):
            flash('Please enter a valid 10-digit Indian phone number', 'danger')
            return redirect(url_for('add_payment'))
        
        # Convert bill_id to integer if provided
        if bill_id:
            try:
                bill_id = int(bill_id)
            except ValueError:
                bill_id = None
        
        # Record payment
        success, payment_id, message = record_qr_payment(
            session['user_id'],
            qr_code_id,
            customer_name,
            customer_phone,
            amount,
            payment_method,
            status,
            notes,
            bill_id
        )
        
        if success:
            flash(f'Payment recorded successfully! Transaction ID: {message}', 'success')
            return redirect(url_for('payments_history'))
        else:
            flash(f'Error recording payment: {message}', 'danger')
            return redirect(url_for('add_payment'))
    
    # GET request - show form
    qr_codes = conn.execute('''
        SELECT * FROM user_qr_codes 
        WHERE user_id = ? AND is_active = 1
        ORDER BY display_name
    ''', (session['user_id'],)).fetchall()
    
    # Get recent bills for linking
    recent_bills = conn.execute('''
        SELECT i.id, i.date, i.customer_name, i.total
        FROM items i
        WHERE i.date >= DATE('now', '-30 days')
        ORDER BY i.date DESC, i.id DESC
        LIMIT 20
    ''').fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('payments/add_qr_payment.html',
                         qr_codes=qr_codes,
                         recent_bills=recent_bills,
                         server_info=server_info)

@app.route('/payments/<int:id>')
@login_required
def view_payment(id):
    """View details of a specific QR payment"""
    payment = get_qr_payment_by_id(id, session['user_id'])
    
    if not payment:
        flash('Payment not found or access denied!', 'danger')
        return redirect(url_for('payments_history'))
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('payments/view_qr_payment.html',
                         payment=payment,
                         server_info=server_info)

@app.route('/payments/<int:id>/update', methods=['POST'])
@login_required
def update_payment(id):
    """Update payment status"""
    status = request.form.get('status')
    notes = request.form.get('notes', '').strip()
    
    if not status:
        flash('Status is required', 'danger')
        return redirect(url_for('view_payment', id=id))
    
    if status not in ['pending', 'completed', 'failed']:
        flash('Invalid status', 'danger')
        return redirect(url_for('view_payment', id=id))
    
    success, message = update_payment_status(id, session['user_id'], status, notes)
    
    if success:
        flash(f'Payment status updated to {status}', 'success')
    else:
        flash(f'Error updating payment: {message}', 'danger')
    
    return redirect(url_for('view_payment', id=id))

@app.route('/payments/export')
@login_required
def export_payments():
    """Export QR payments to CSV"""
    # Get filter parameters
    search_query = request.args.get('search', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    status = request.args.get('status', '').strip()
    payment_method = request.args.get('payment_method', '').strip()
    
    # Get all payments with filters (no pagination)
    payments, _ = search_qr_payments(
        session['user_id'],
        search_query=search_query,
        start_date=start_date,
        end_date=end_date,
        status=status,
        payment_method=payment_method,
        limit=10000  # Large limit to get all payments
    )
    
    if not payments:
        flash('No payments found to export', 'warning')
        return redirect(url_for('payments_history'))
    
    # Generate CSV
    csv_data = export_qr_payments_csv(session['user_id'], payments)
    
    # Create response
    response = make_response(csv_data)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename="qr_payments_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    return response

@app.route('/payments/stats')
@login_required
def payment_stats():
    """View detailed payment statistics"""
    payment_stats = get_qr_payment_stats(session['user_id'])
    
    # Get recent payments for the chart
    recent_payments = get_recent_qr_payments(session['user_id'], limit=10)
    
    # Calculate daily stats for the last 7 days
    conn = get_db_connection()
    daily_stats = conn.execute('''
        SELECT 
            DATE(created_at) as date,
            COUNT(*) as transaction_count,
            SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END) as completed_amount,
            SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END) as pending_amount,
            SUM(CASE WHEN status = 'failed' THEN amount ELSE 0 END) as failed_amount
        FROM qr_payment_history 
        WHERE user_id = ? AND DATE(created_at) >= DATE('now', '-7 days')
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at) DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get payment method distribution
    method_stats = conn.execute('''
        SELECT 
            payment_method,
            COUNT(*) as count,
            SUM(amount) as total_amount
        FROM qr_payment_history 
        WHERE user_id = ?
        GROUP BY payment_method
    ''', (session['user_id'],)).fetchall()
    
    # Get status distribution
    status_stats = conn.execute('''
        SELECT 
            status,
            COUNT(*) as count,
            SUM(amount) as total_amount
        FROM qr_payment_history 
        WHERE user_id = ?
        GROUP BY status
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('payments/payment_stats.html',
                         payment_stats=payment_stats,
                         recent_payments=recent_payments,
                         daily_stats=daily_stats,
                         method_stats=method_stats,
                         status_stats=status_stats,
                         server_info=server_info)

# ============================================================================
# UTILITY FUNCTIONS AND FILTERS
# ============================================================================

def format_indian_rupees(amount):
    """Format amount in Indian Rupees format with comma separators"""
    try:
        amount = float(amount)
        if amount >= 10000000:
            crores = amount / 10000000
            return f"₹{crores:,.2f} Cr"
        elif amount >= 100000:
            lakhs = amount / 100000
            return f"₹{lakhs:,.2f} L"
        else:
            formatted = f"₹{amount:,.2f}"
            return formatted
    except (ValueError, TypeError):
        return "₹0.00"

def format_phone_number(phone):
    """Format phone number for display"""
    if not phone:
        return ""
    phone = str(phone).strip()
    if len(phone) == 10:
        return f"{phone[:5]} {phone[5:]}"
    return phone

@app.template_filter('format_rupees')
def format_rupees_filter(amount):
    """Filter to format amount in Indian Rupees format"""
    return format_indian_rupees(amount)

@app.context_processor
def utility_processor():
    """Make utility functions available in templates"""
    
    def get_stock_info(item_name):
        """Get stock information for an item"""
        conn = get_db_connection()
        try:
            item = conn.execute('''
                SELECT * FROM clothing_items 
                WHERE LOWER(item_name) = LOWER(?) AND is_active = 1
            ''', (item_name,)).fetchone()
            
            if not item:
                # Try fuzzy matching
                item = conn.execute('''
                    SELECT * FROM clothing_items 
                    WHERE item_name LIKE ? AND is_active = 1
                    LIMIT 1
                ''', (f'%{item_name}%',)).fetchone()
            
            return item
        except Exception as e:
            app.logger.error(f"Error getting stock info: {str(e)}")
            return None
        finally:
            conn.close()
    
    return dict(
        format_rupees=format_indian_rupees,
        format_phone=format_phone_number,
        current_year=datetime.now().year,
        current_date=datetime.now().strftime('%Y-%m-%d'),
        is_production=is_production,
        get_server_base_url=get_server_base_url,
        get_stock_info=get_stock_info
    )

# ============================================================================
# PWA ROUTES
# ============================================================================

@app.route('/manifest.json')
def manifest():
    """PWA Manifest file"""
    manifest_data = {
        "name": "Textile Bazar",
        "short_name": "TextileBazar",
        "description": "Textile Bazar - Clothing Store Management System",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0066CC",
        "theme_color": "#0066CC",
        "orientation": "portrait-primary",
        "icons": [
            {
                "src": "/static/icons/icon-72x72.png",
                "sizes": "72x72",
                "type": "image/png"
            },
            {
                "src": "/static/icons/icon-96x96.png",
                "sizes": "96x96",
                "type": "image/png"
            },
            {
                "src": "/static/icons/icon-128x128.png",
                "sizes": "128x128",
                "type": "image/png"
            },
            {
                "src": "/static/icons/icon-144x144.png",
                "sizes": "144x144",
                "type": "image/png"
            },
            {
                "src": "/static/icons/icon-152x152.png",
                "sizes": "152x152",
                "type": "image/png"
            },
            {
                "src": "/static/icons/icon-192x192.png",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any maskable"
            },
            {
                "src": "/static/icons/icon-384x384.png",
                "sizes": "384x384",
                "type": "image/png"
            },
            {
                "src": "/static/icons/icon-512x512.png",
                "sizes": "512x512",
                "type": "image/png"
            }
        ],
        "screenshots": [
            {
                "src": "/static/screenshots/screenshot1.png",
                "sizes": "1280x720",
                "type": "image/png",
                "form_factor": "wide"
            },
            {
                "src": "/static/screenshots/screenshot2.png",
                "sizes": "750x1334",
                "type": "image/png",
                "form_factor": "narrow"
            }
        ],
        "categories": ["business", "productivity", "utilities"],
        "shortcuts": [
            {
                "name": "Add New Sale",
                "short_name": "Add Sale",
                "description": "Add a new sales entry",
                "url": "/add",
                "icons": [{"src": "/static/icons/add-icon.png", "sizes": "96x96"}]
            },
            {
                "name": "View Customers",
                "short_name": "Customers",
                "description": "View customer list",
                "url": "/customers",
                "icons": [{"src": "/static/icons/customer-icon.png", "sizes": "96x96"}]
            },
            {
                "name": "Generate Report",
                "short_name": "Report",
                "description": "Generate sales report",
                "url": "/stats",
                "icons": [{"src": "/static/icons/report-icon.png", "sizes": "96x96"}]
            }
        ],
        "prefer_related_applications": False
    }
    
    response = make_response(jsonify(manifest_data))
    response.headers['Content-Type'] = 'application/manifest+json'
    return response

@app.route('/service-worker.js')
def service_worker():
    """PWA Service Worker"""
    base_url = get_server_base_url()
    
    service_worker_js = f"""// Textile Bazar Service Worker
const CACHE_NAME = 'textile-bazar-v2.1.0';
const PDF_CACHE_NAME = 'textile-bazar-pdfs-v1';
const BASE_URL = '{base_url}';

const urlsToCache = [
  '/',
  '/home',
  '/auth/login',
  '/auth/register',
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/icons/icon-72x72.png',
  '/static/icons/icon-96x96.png',
  '/static/icons/icon-128x128.png',
  '/static/icons/icon-144x144.png',
  '/static/icons/icon-152x152.png',
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-384x384.png',
  '/static/icons/icon-512x512.png',
  '/offline'
];

self.addEventListener('install', event => {{
  console.log('[Service Worker] Installing...');
  
  event.waitUntil(
    Promise.all([
      caches.open(CACHE_NAME)
        .then(cache => {{
          console.log('[Service Worker] Caching app shell);
          return cache.addAll(urlsToCache);
        }}),
      self.skipWaiting()
    ])
  );
}});

self.addEventListener('activate', event => {{
  console.log('[Service Worker] Activating...');
  
  event.waitUntil(
    Promise.all([
      caches.keys().then(cacheNames => {{
        return Promise.all(
          cacheNames.map(cacheName => {{
            if (cacheName !== CACHE_NAME && cacheName !== PDF_CACHE_NAME) {{
              console.log('[Service Worker] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }}
          }})
        );
      }}),
      self.clients.claim()
    ])
  );
}});

self.addEventListener('fetch', event => {{
  const url = new URL(event.request.url);
  
  if (event.request.method !== 'GET' || !url.protocol.startsWith('http')) {{
    return;
  }}
  
  if (url.pathname.includes('.pdf') || url.pathname.includes('/download/pdf/')) {{
    event.respondWith(handlePdfRequest(event));
    return;
  }}
  
  if (url.pathname.includes('/api/')) {{
    event.respondWith(networkOnly(event));
    return;
  }}
  
  if (event.request.headers.get('Accept').includes('text/html') || 
      url.pathname === '/' || 
      url.pathname.includes('/home') ||
      url.pathname.includes('/auth/')) {{
    event.respondWith(networkFirstWithOfflinePage(event));
    return;
  }}
  
  if (url.pathname.includes('/static/')) {{
    event.respondWith(cacheFirst(event));
    return;
  }}
  
  event.respondWith(networkFirst(event));
}});

async function handlePdfRequest(event) {{
  try {{
    const networkResponse = await fetch(event.request);
    
    if (networkResponse.ok) {{
      const cache = await caches.open(PDF_CACHE_NAME);
      cache.put(event.request, networkResponse.clone());
      return networkResponse;
    }}
    throw new Error('Network request failed');
  }} catch (error) {{
    console.log('[Service Worker] PDF network failed, trying cache:', error);
    
    const cachedResponse = await caches.match(event.request);
    if (cachedResponse) {{
      return cachedResponse;
    }}
    
    return new Response(
      '<!DOCTYPE html><html><head><title>PDF Offline</title><style>body{{font-family: Arial; text-align: center; padding: 50px;}}</style></head><body><h1>📄 PDF Unavailable Offline</h1><p>Please connect to the internet to view this PDF.</p><p>Once downloaded, PDFs will be available offline.</p><button onclick="window.history.back()">Go Back</button></body></html>',
      {{
        headers: {{ 'Content-Type': 'text/html' }}
      }}
    );
  }}
}}

async function networkFirst(event) {{
  try {{
    const networkResponse = await fetch(event.request);
    
    if (networkResponse.ok) {{
      const cache = await caches.open(CACHE_NAME);
      cache.put(event.request, networkResponse.clone());
    }}
    
    return networkResponse;
  }} catch (error) {{
    console.log('[Service Worker] Network failed, trying cache:', error);
    
    const cachedResponse = await caches.match(event.request);
    if (cachedResponse) {{
      return cachedResponse;
    }}
    
    if (event.request.mode === 'navigate') {{
      return caches.match('/offline');
    }}
    
    throw error;
  }}
}}

async function networkFirstWithOfflinePage(event) {{
  try {{
    const networkResponse = await fetch(event.request);
    
    if (networkResponse.ok) {{
      const cache = await caches.open(CACHE_NAME);
      cache.put(event.request, networkResponse.clone());
    }}
    
    return networkResponse;
  }} catch (error) {{
    console.log('[Service Worker] Network failed for page, showing offline page');
    
    const offlineResponse = await caches.match('/offline');
    if (offlineResponse) {{
      return offlineResponse;
    }}
    
    return new Response(
      '<!DOCTYPE html><html><head><title>Offline</title><style>body{{font-family: Arial; text-align: center; padding: 50px;}}</style></head><body><h1>📵 You are offline</h1><p>Please check your internet connection and try again.</p><p>Some features may not be available offline.</p></body></html>',
      {{
        headers: {{ 'Content-Type': 'text/html' }}
      }}
    );
  }}
}}

async function cacheFirst(event) {{
  const cachedResponse = await caches.match(event.request);
  
  if (cachedResponse) {{
    return cachedResponse;
  }}
  
  try {{
    const networkResponse = await fetch(event.request);
    
    if (networkResponse.ok) {{
      const cache = await caches.open(CACHE_NAME);
      cache.put(event.request, networkResponse.clone());
    }}
    
    return networkResponse;
  }} catch (error) {{
    console.log('[Service Worker] Cache first failed:', error);
    
    if (event.request.url.includes('.png') || event.request.url.includes('.jpg')) {{
      return new Response(
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 24 24"><path fill="#ccc" d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>',
        {{
          headers: {{ 'Content-Type': 'image/svg+xml' }}
        }}
      );
    }}
    
    throw error;
  }}
}}

async function networkOnly(event) {{
  return fetch(event.request);
}}

self.addEventListener('push', event => {{
  console.log('[Service Worker] Push received:', event);
  
  let data = {{
    title: 'Textile Bazar',
    body: 'New update available!',
    icon: '/static/icons/icon-192x192.png'
  }};
  
  if (event.data) {{
    try {{
      data = event.data.json();
    }} catch (e) {{
      data.body = event.data.text();
    }}
  }}
  
  event.waitUntil(
    self.registration.showNotification(data.title, {{
      body: data.body,
      icon: data.icon || '/static/icons/icon-192x192.png',
      badge: '/static/icons/icon-72x72.png',
      vibrate: [100, 50, 100],
      data: {{
        url: data.url || '/'
      }},
      actions: [
        {{
          action: 'open',
          title: 'Open App'
        }},
        {{
          action: 'close',
          title: 'Close'
        }}
      ]
    }})
  );
}});

self.addEventListener('notificationclick', event => {{
  console.log('[Service Worker] Notification click:', event.action);
  
  event.notification.close();
  
  if (event.action === 'open' || event.action === '') {{
    event.waitUntil(
      clients.matchAll({{type: 'window'}}).then(windowClients => {{
        for (let client of windowClients) {{
          if (client.url === BASE_URL + '/' && 'focus' in client) {{
            return client.focus();
          }}
        }}
        
        if (clients.openWindow) {{
          return clients.openWindow(event.notification.data.url || '/');
        }}
      }})
    );
  }}
}});

console.log('[Service Worker] Loaded successfully');
"""
    
    response = make_response(service_worker_js)
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Service-Worker-Allowed'] = '/'
    return response

@app.route('/offline')
def offline():
    """Offline page for PWA"""
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    return render_template('offline.html', server_info=server_info)

# ============================================================================
# DOWNLOAD PDF ROUTE
# ============================================================================

@app.route('/download/pdf/<filename>')
@login_required
def download_pdf(filename):
    """Download generated PDF bill"""
    try:
        safe_name = secure_filename(filename)
        pdf_path = os.path.join('static', 'temp', safe_name)
        
        if not os.path.exists(pdf_path):
            flash('PDF file not found!', 'danger')
            return redirect(url_for('home'))
        
        if not os.path.isfile(pdf_path):
            flash('Invalid PDF file!', 'danger')
            return redirect(url_for('home'))
        
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"textile_bazar_bill_{safe_name}",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        flash(f'Error downloading PDF: {str(e)}', 'danger')
        return redirect(url_for('home'))

# ============================================================================
# PDF GENERATION FUNCTIONS
# ============================================================================

def create_whatsapp_pdf_link_message(customer_name, bill_number, total, pdf_download_url):
    """Create WhatsApp message with ONLY PDF download link"""
    message = f"""📄 *Textile Bazar - Bill Receipt*

Hello {customer_name},

Your PDF bill is ready for download:
{pdf_download_url}

• Bill No: {bill_number}
• Total Amount: ₹{total:,.2f}

Thank you for shopping with us! 🛍️"""
    
    return message

def generate_whatsapp_pdf(customer_name, phone, date, items, total, bill_number):
    """Generate a professional PDF bill for WhatsApp sharing"""
    try:
        buffer = io.BytesIO()
        
        doc = SimpleDocTemplate(buffer, 
                               pagesize=letter,
                               rightMargin=36, 
                               leftMargin=36,
                               topMargin=36, 
                               bottomMargin=36,
                               title=f"Textile Bazar Bill - {bill_number}")
        
        elements = []
        styles = getSampleStyleSheet()
        
        header_style = ParagraphStyle(
            'HeaderStyle',
            parent=styles['Title'],
            fontSize=24,
            textColor=HexColor('#0066CC'),
            spaceAfter=10,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        subheader_style = ParagraphStyle(
            'SubheaderStyle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=HexColor('#004C99'),
            spaceAfter=8,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        customer_style = ParagraphStyle(
            'CustomerStyle',
            parent=styles['Normal'],
            fontSize=12,
            textColor=HexColor('#333333'),
            spaceAfter=5,
            alignment=TA_LEFT,
            fontName='Helvetica'
        )
        
        bill_info_style = ParagraphStyle(
            'BillInfoStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#666666'),
            spaceAfter=15,
            alignment=TA_CENTER,
            fontName='Helvetica'
        )
        
        table_header_style = ParagraphStyle(
            'TableHeaderStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        table_text_style = ParagraphStyle(
            'TableTextStyle',
            parent=styles['Normal'],
            fontSize=9,
            textColor=HexColor('#333333'),
            alignment=TA_LEFT,
            fontName='Helvetica'
        )
        
        table_number_style = ParagraphStyle(
            'TableNumberStyle',
            parent=styles['Normal'],
            fontSize=9,
            textColor=HexColor('#333333'),
            alignment=TA_RIGHT,
            fontName='Helvetica'
        )
        
        total_style = ParagraphStyle(
            'TotalStyle',
            parent=styles['Normal'],
            fontSize=14,
            textColor=HexColor('#0066CC'),
            alignment=TA_RIGHT,
            fontName='Helvetica-Bold'
        )
        
        footer_style = ParagraphStyle(
            'FooterStyle',
            parent=styles['Normal'],
            fontSize=8,
            textColor=HexColor('#666666'),
            alignment=TA_CENTER,
            fontName='Helvetica'
        )
        
        elements.append(Spacer(1, 10))
        
        header = Paragraph("TEXTILE BAZAR", header_style)
        elements.append(header)
        
        subheader = Paragraph("Your Trusted Clothing Store", subheader_style)
        elements.append(subheader)
        
        elements.append(Spacer(1, 5))
        drawing = Drawing(500, 1)
        drawing.add(Line(0, 0, 500, 0, strokeColor=HexColor('#0066CC'), strokeWidth=1))
        elements.append(drawing)
        
        elements.append(Spacer(1, 15))
        
        bill_info = Paragraph(f"BILL NO: {bill_number} | DATE: {date}", bill_info_style)
        elements.append(bill_info)
        
        elements.append(Spacer(1, 10))
        
        customer_box = [
            [Paragraph("<b>CUSTOMER DETAILS</b>", ParagraphStyle('CustomerHeader', parent=customer_style, fontSize=11, fontName='Helvetica-Bold'))],
            [Paragraph(f"<b>Name:</b> {customer_name}", customer_style)],
            [Paragraph(f"<b>Phone:</b> +91 {format_phone_number(phone)}", customer_style)],
            [Paragraph(f"<b>Bill Date:</b> {date}", customer_style)]
        ]
        
        customer_table = Table(customer_box, colWidths=[5*inch])
        customer_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0066CC')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
            ('TEXTCOLOR', (0, 1), (-1, -1), HexColor('#333333')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#DEE2E6')),
            ('PADDING', (0, 1), (-1, -1), 8),
        ]))
        
        elements.append(customer_table)
        elements.append(Spacer(1, 20))
        
        table_data = []
        header_row = [
            Paragraph('<b>Sr.</b>', table_header_style),
            Paragraph('<b>Item Description</b>', table_header_style),
            Paragraph('<b>Quantity</b>', table_header_style),
            Paragraph('<b>Price (₹)</b>', table_header_style),
            Paragraph('<b>Total (₹)</b>', table_header_style)
        ]
        table_data.append(header_row)
        
        for idx, item in enumerate(items, 1):
            row = [
                Paragraph(str(idx), table_text_style),
                Paragraph(item['item_name'], table_text_style),
                Paragraph(str(item['quantity']), table_number_style),
                Paragraph(f"{item['price']:,.2f}", table_number_style),
                Paragraph(f"{item['total']:,.2f}", table_number_style)
            ]
            table_data.append(row)
        
        total_row = [
            Paragraph('', table_text_style),
            Paragraph('', table_text_style),
            Paragraph('', table_text_style),
            Paragraph('<b>GRAND TOTAL:</b>', ParagraphStyle('TotalLabel', parent=table_text_style, fontSize=10, fontName='Helvetica-Bold', alignment=TA_RIGHT)),
            Paragraph(f'<b>₹{total:,.2f}</b>', ParagraphStyle('TotalValue', parent=total_style, fontSize=12, fontName='Helvetica-Bold'))
        ]
        table_data.append(total_row)
        
        table = Table(table_data, colWidths=[0.5*inch, 3*inch, 1*inch, 1.2*inch, 1.3*inch])
        
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0066CC')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            
            ('BACKGROUND', (0, 1), (-1, -2), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -2), HexColor('#333333')),
            ('FONTNAME', (0, 1), (-1, -2), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -2), 9),
            ('ALIGN', (0, 1), (0, -2), 'CENTER'),
            ('ALIGN', (1, 1), (1, -2), 'LEFT'),
            ('ALIGN', (2, 1), (-1, -2), 'RIGHT'),
            ('GRID', (0, 0), (-1, -2), 0.5, HexColor('#E9ECEF')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, HexColor('#F8F9FA')]),
            
            ('BACKGROUND', (0, -1), (-1, -1), HexColor('#E6F2FF')),
            ('TEXTCOLOR', (0, -1), (-1, -1), HexColor('#0066CC')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, -1), (-1, -1), 11),
            ('ALIGN', (0, -1), (-2, -1), 'RIGHT'),
            ('ALIGN', (-1, -1), (-1, -1), 'RIGHT'),
            ('TOPPADDING', (0, -1), (-1, -1), 12),
            ('BOTTOMPADDING', (0, -1), (-1, -1), 12),
            ('BOX', (0, -1), (-1, -1), 1, HexColor('#0066CC')),
        ])
        
        table.setStyle(table_style)
        elements.append(table)
        
        elements.append(Spacer(1, 25))
        
        payment_data = [
            [Paragraph('<b>PAYMENT SUMMARY</b>', ParagraphStyle('PaymentHeader', parent=customer_style, fontSize=11, fontName='Helvetica-Bold', alignment=TA_CENTER))],
            [Paragraph(f"<b>Total Items:</b> {len(items)}", customer_style)],
            [Paragraph(f"<b>Total Quantity:</b> {sum(item['quantity'] for item in items)}", customer_style)],
            [Paragraph(f"<b>Subtotal:</b> ₹{total:,.2f}", customer_style)],
            [Paragraph(f"<b>GST (0%):</b> ₹0.00", customer_style)],
            [Paragraph(f"<b>Grand Total:</b> ₹{total:,.2f}", ParagraphStyle('GrandTotal', parent=customer_style, fontSize=12, fontName='Helvetica-Bold', textColor=HexColor('#0066CC')))],
        ]
        
        payment_table = Table(payment_data, colWidths=[3*inch])
        payment_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#004C99')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
            ('TEXTCOLOR', (0, 1), (-1, -1), HexColor('#333333')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#DEE2E6')),
            ('PADDING', (0, 1), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(payment_table)
        elements.append(Spacer(1, 20))
        
        terms_text = """
        <b>Terms & Conditions:</b><br/>
        1. Goods once sold will not be taken back.<br/>
        2. All disputes subject to local jurisdiction only.<br/>
        3. Payment should be made in full at the time of purchase.<br/>
        4. Prices are inclusive of all taxes unless specified.<br/>
        5. Please check all items before leaving the store.
        """
        
        terms = Paragraph(terms_text, ParagraphStyle('TermsStyle', parent=footer_style, fontSize=8, alignment=TA_JUSTIFY))
        elements.append(terms)
        
        elements.append(Spacer(1, 15))
        
        thank_you = Paragraph(
            "Thank you for shopping at Textile Bazar! 🛍️<br/>"
            "We appreciate your business and look forward to serving you again.",
            ParagraphStyle('ThankYouStyle', parent=footer_style, fontSize=9, textColor=HexColor('#0066CC'))
        )
        elements.append(thank_you)
        
        elements.append(Spacer(1, 10))
        
        footer = Paragraph(
            "<b>Textile Bazar</b> | 📍 Your Trusted Clothing Store<br/>"
            "📞 Customer Care: +91 9876543210 | 📧 info@textilebazar.com<br/>"
            "⏰ Store Hours: 9:00 AM - 9:00 PM (Monday-Saturday)",
            footer_style
        )
        elements.append(footer)
        
        elements.append(Spacer(1, 5))
        
        qr_note = Paragraph(
            "Scan to save contact or visit our store",
            ParagraphStyle('QRNote', parent=footer_style, fontSize=7)
        )
        elements.append(qr_note)
        
        doc.build(elements)
        
        pdf = buffer.getvalue()
        buffer.close()
        
        return pdf
        
    except Exception as e:
        print(f"Error generating WhatsApp PDF: {str(e)}")
        raise e

# ============================================================================
# SEND WHATSAPP WITH PDF LINK FUNCTION
# ============================================================================

@app.route('/send_whatsapp_pdf/<int:id>')
@login_required
def send_whatsapp_pdf(id):
    """Generate PDF and send WhatsApp with ONLY PDF download link"""
    conn = get_db_connection()
    
    item = conn.execute('SELECT * FROM items WHERE id = ?', (id,)).fetchone()
    
    if not item:
        flash('Transaction not found!', 'danger')
        return redirect(url_for('home'))
    
    items = conn.execute('''
        SELECT * FROM items 
        WHERE phone_number = ? AND date = ?
        ORDER BY item_name
    ''', (item['phone_number'], item['date'])).fetchall()
    
    total_result = conn.execute('''
        SELECT SUM(total) as total 
        FROM items 
        WHERE phone_number = ? AND date = ?
    ''', (item['phone_number'], item['date'])).fetchone()
    total = total_result['total'] if total_result['total'] is not None else 0
    
    bill_number = f"TB{datetime.now().strftime('%Y%m%d')}{id:04d}"
    
    try:
        pdf_content = generate_whatsapp_pdf(
            item['customer_name'],
            item['phone_number'],
            item['date'],
            items,
            total,
            bill_number
        )
        
        pdf_filename = f"textile_bazar_bill_{bill_number}.pdf"
        
        if not ensure_temp_directory():
            flash('Error creating temporary directory for PDF', 'danger')
            conn.close()
            return redirect(url_for('home'))
        
        pdf_path = os.path.join('static', 'temp', pdf_filename)
        with open(pdf_path, 'wb') as f:
            f.write(pdf_content)
        
        pdf_download_url = get_pdf_download_url(pdf_filename)
        
        whatsapp_message = create_whatsapp_pdf_link_message(
            item['customer_name'],
            bill_number,
            total,
            pdf_download_url
        )
        
        encoded_message = quote(whatsapp_message)
        
        whatsapp_url = f"https://wa.me/91{item['phone_number']}?text={encoded_message}"
        
        conn.execute('''
            UPDATE items 
            SET pdf_generated = 1, 
                pdf_filename = ?,
                bill_sent = 1,
                bill_sent_date = ?
            WHERE id = ?
        ''', (pdf_filename, datetime.now().isoformat(), id))
        
        conn.commit()
        conn.close()
        
        app.logger.info(f"PDF generated for bill {bill_number} to {item['customer_name']}")
        app.logger.info(f"PDF URL: {pdf_download_url}")
        
        return redirect(whatsapp_url)
        
    except Exception as e:
        conn.close()
        app.logger.error(f'Error generating PDF or WhatsApp message: {str(e)}')
        flash(f'Error generating PDF or WhatsApp message: {str(e)}', 'danger')
        return redirect(url_for('home'))

# ============================================================================
# INVENTORY MANAGEMENT ROUTES
# ============================================================================

@app.route('/inventory')
@login_required
def inventory():
    """View inventory dashboard"""
    filter_type = request.args.get('filter', '')
    
    conn = get_db_connection()
    
    if filter_type == 'low':
        inventory_items = conn.execute('''
            SELECT * FROM clothing_items 
            WHERE is_active = 1 AND current_stock <= minimum_stock
            ORDER BY current_stock ASC, item_name
        ''').fetchall()
    elif filter_type == 'out':
        inventory_items = conn.execute('''
            SELECT * FROM clothing_items 
            WHERE is_active = 1 AND current_stock = 0
            ORDER BY item_name
        ''').fetchall()
    else:
        inventory_items = conn.execute('''
            SELECT * FROM clothing_items 
            WHERE is_active = 1
            ORDER BY category, item_name
        ''').fetchall()
    
    low_stock_items = conn.execute('''
        SELECT * FROM clothing_items 
        WHERE is_active = 1 AND current_stock <= minimum_stock
        ORDER BY current_stock ASC
        LIMIT 5
    ''').fetchall()
    
    stats = conn.execute('''
        SELECT 
            COUNT(*) as total_items,
            SUM(current_stock) as total_stock,
            SUM(CASE WHEN current_stock <= minimum_stock THEN 1 ELSE 0 END) as low_stock_count,
            SUM(current_stock * cost_price) as total_inventory_value
        FROM clothing_items 
        WHERE is_active = 1
    ''').fetchone()
    
    recent_movements = conn.execute('''
        SELECT sh.*, ci.item_code
        FROM stock_history sh
        JOIN clothing_items ci ON sh.item_id = ci.id
        ORDER BY sh.created_date DESC
        LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('inventory.html',
                         inventory_items=inventory_items,
                         low_stock_items=low_stock_items,
                         stats=stats,
                         recent_movements=recent_movements,
                         server_info=server_info)

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_inventory_item():
    """Add new clothing item to inventory"""
    conn = get_db_connection()
    
    if request.method == 'POST':
        item_data = {
            'item_code': request.form.get('item_code', '').strip(),
            'item_name': request.form['item_name'].strip(),
            'category': request.form['category'].strip(),
            'description': request.form.get('description', '').strip(),
            'color': request.form.get('color', '').strip(),
            'size': request.form.get('size', '').strip(),
            'cost_price': float(request.form['cost_price']),
            'selling_price': float(request.form['selling_price']),
            'current_stock': int(request.form.get('current_stock', 0)),
            'minimum_stock': int(request.form.get('minimum_stock', 5)),
            'unit': request.form.get('unit', 'pcs').strip()
        }
        
        if not all([item_data['item_name'], item_data['category'], item_data['cost_price'] > 0, item_data['selling_price'] > 0]):
            flash('Please fill in all required fields with valid values', 'danger')
            return redirect(url_for('add_inventory_item'))
        
        success, message = add_new_clothing_item(item_data)
        
        if success:
            flash(f'✅ {message}', 'success')
            return redirect(url_for('inventory'))
        else:
            flash(f'❌ {message}', 'danger')
            return redirect(url_for('add_inventory_item'))
    
    categories = conn.execute('SELECT * FROM categories WHERE is_active = 1 ORDER BY category_name').fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('add_inventory_item.html',
                         categories=categories,
                         server_info=server_info)

@app.route('/inventory/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_inventory_item(id):
    """Edit clothing item"""
    conn = get_db_connection()
    
    item = conn.execute('SELECT * FROM clothing_items WHERE id = ?', (id,)).fetchone()
    
    if not item:
        flash('Item not found!', 'danger')
        return redirect(url_for('inventory'))
    
    if request.method == 'POST':
        item_data = {
            'item_name': request.form['item_name'].strip(),
            'category': request.form['category'].strip(),
            'description': request.form.get('description', '').strip(),
            'color': request.form.get('color', '').strip(),
            'size': request.form.get('size', '').strip(),
            'cost_price': float(request.form['cost_price']),
            'selling_price': float(request.form['selling_price']),
            'minimum_stock': int(request.form.get('minimum_stock', 5)),
            'unit': request.form.get('unit', 'pcs').strip()
        }
        
        success, message = update_clothing_item(id, item_data)
        
        if success:
            flash(f'✅ {message}', 'success')
            return redirect(url_for('inventory'))
        else:
            flash(f'❌ {message}', 'danger')
            return redirect(url_for('edit_inventory_item', id=id))
    
    categories = conn.execute('SELECT * FROM categories WHERE is_active = 1 ORDER BY category_name').fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('edit_inventory_item.html',
                         item=item,
                         categories=categories,
                         server_info=server_info)

@app.route('/inventory/view/<int:id>')
@login_required
def view_inventory_item(id):
    """View clothing item details and history"""
    conn = get_db_connection()
    
    item = conn.execute('SELECT * FROM clothing_items WHERE id = ?', (id,)).fetchone()
    
    if not item:
        flash('Item not found!', 'danger')
        return redirect(url_for('inventory'))
    
    stock_history = conn.execute('''
        SELECT * FROM stock_history 
        WHERE item_id = ?
        ORDER BY created_date DESC
    ''', (id,)).fetchall()
    
    sales_stats = conn.execute('''
        SELECT 
            SUM(quantity) as total_sold,
            SUM(total) as total_revenue,
            COUNT(DISTINCT customer_name) as unique_customers,
            MIN(date) as first_sale_date,
            MAX(date) as last_sale_date
        FROM items 
        WHERE LOWER(item_name) = LOWER(?)
    ''', (item['item_name'],)).fetchone()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('view_inventory_item.html',
                         item=item,
                         stock_history=stock_history,
                         sales_stats=sales_stats,
                         server_info=server_info)

@app.route('/inventory/restock', methods=['GET', 'POST'])
@login_required
def restock_inventory():
    """Restock multiple items"""
    conn = get_db_connection()
    
    if request.method == 'POST':
        items_to_restock = []
        
        for key, value in request.form.items():
            if key.startswith('item_') and key.endswith('_quantity') and value:
                item_id = int(key.replace('item_', '').replace('_quantity', ''))
                quantity = int(value)
                notes = request.form.get(f'item_{item_id}_notes', '').strip()
                
                if quantity > 0:
                    items_to_restock.append({
                        'id': item_id,
                        'quantity': quantity,
                        'notes': notes
                    })
        
        if not items_to_restock:
            flash('Please select items and enter quantities to restock', 'warning')
            return redirect(url_for('restock_inventory'))
        
        success_count = 0
        for item_data in items_to_restock:
            success, message = restock_item(item_data['id'], item_data['quantity'], item_data['notes'])
            if success:
                success_count += 1
        
        flash(f'✅ Successfully restocked {success_count} item(s)', 'success')
        return redirect(url_for('inventory'))
    
    low_stock_items = conn.execute('''
        SELECT * FROM clothing_items 
        WHERE is_active = 1 AND current_stock <= minimum_stock
        ORDER BY current_stock ASC
    ''').fetchall()
    
    all_items = conn.execute('''
        SELECT * FROM clothing_items 
        WHERE is_active = 1
        ORDER BY category, item_name
    ''').fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('restock_inventory.html',
                         low_stock_items=low_stock_items,
                         all_items=all_items,
                         server_info=server_info)

@app.route('/inventory/restock/<int:id>', methods=['GET', 'POST'])
@login_required
def restock_single_item(id):
    """Restock a single item"""
    conn = get_db_connection()
    
    item = conn.execute('SELECT * FROM clothing_items WHERE id = ?', (id,)).fetchone()
    
    if not item:
        flash('Item not found!', 'danger')
        return redirect(url_for('inventory'))
    
    if request.method == 'POST':
        quantity = int(request.form['quantity'])
        notes = request.form.get('notes', '').strip()
        
        if quantity <= 0:
            flash('Please enter a valid quantity', 'danger')
            return redirect(url_for('restock_single_item', id=id))
        
        success, message = restock_item(id, quantity, notes)
        
        if success:
            flash(f'✅ {message}', 'success')
            return redirect(url_for('view_inventory_item', id=id))
        else:
            flash(f'❌ {message}', 'danger')
            return redirect(url_for('restock_single_item', id=id))
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('restock_single_item.html',
                         item=item,
                         server_info=server_info)

@app.route('/inventory/toggle/<int:id>')
@login_required
def toggle_inventory_item(id):
    """Toggle item active status"""
    conn = get_db_connection()
    
    item = conn.execute('SELECT * FROM clothing_items WHERE id = ?', (id,)).fetchone()
    
    if not item:
        flash('Item not found!', 'danger')
        return redirect(url_for('inventory'))
    
    new_status = 0 if item['is_active'] else 1
    
    conn.execute('''
        UPDATE clothing_items 
        SET is_active = ?, last_updated = ?
        WHERE id = ?
    ''', (new_status, datetime.now().isoformat(), id))
    
    conn.commit()
    conn.close()
    
    status_text = "activated" if new_status else "deactivated"
    flash(f'✅ Item {status_text} successfully', 'success')
    return redirect(url_for('inventory'))

@app.route('/inventory/report')
@login_required
def inventory_report():
    """Generate inventory report"""
    conn = get_db_connection()
    
    stats_data = get_inventory_stats()
    
    # Get stats with proper defaults
    stats_row = stats_data['stats']
    
    # Create stats object with default values
    stats = {
        'total_items': stats_row['total_items'] or 0 if stats_row['total_items'] is not None else 0,
        'total_stock': stats_row['total_stock'] or 0 if stats_row['total_stock'] is not None else 0,
        'low_stock_count': stats_row['low_stock_count'] or 0 if stats_row['low_stock_count'] is not None else 0,
        'total_inventory_value': stats_row['total_inventory_value'] or 0 if stats_row['total_inventory_value'] is not None else 0,
        'total_potential_value': stats_row['total_potential_value'] or 0 if stats_row['total_potential_value'] is not None else 0,
        'total_items_sold': stats_row['total_items_sold'] or 0 if stats_row['total_items_sold'] is not None else 0,
        'total_sales_value': stats_row['total_sales_value'] or 0 if stats_row['total_sales_value'] is not None else 0
    }
    
    items_with_sales = conn.execute('''
        SELECT 
            ci.*,
            COALESCE(SUM(i.quantity), 0) as total_sold_quantity,
            COALESCE(SUM(i.total), 0) as total_sales_revenue
        FROM clothing_items ci
        LEFT JOIN items i ON LOWER(ci.item_name) = LOWER(i.item_name)
        WHERE ci.is_active = 1
        GROUP BY ci.id
        ORDER BY ci.category, ci.item_name
    ''').fetchall()
    
    category_summary = conn.execute('''
        SELECT 
            category,
            COUNT(*) as item_count,
            COALESCE(SUM(current_stock), 0) as total_stock,
            COALESCE(SUM(current_stock * cost_price), 0) as inventory_value,
            COALESCE(SUM(current_stock * selling_price), 0) as potential_value,
            COALESCE(SUM(total_sold), 0) as total_sold
        FROM clothing_items 
        WHERE is_active = 1
        GROUP BY category
        ORDER BY inventory_value DESC
    ''').fetchall()
    
    # Get recent stock movements
    recent_movements = conn.execute('''
        SELECT sh.*, ci.item_code
        FROM stock_history sh
        JOIN clothing_items ci ON sh.item_id = ci.id
        ORDER BY sh.created_date DESC
        LIMIT 10
    ''').fetchall()
    
    # Get all categories for filter
    categories = conn.execute('''
        SELECT DISTINCT category 
        FROM clothing_items 
        WHERE is_active = 1 AND category IS NOT NULL
        ORDER BY category
    ''').fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('inventory_report.html',
                         stats=stats,
                         categories=categories,
                         items_with_sales=items_with_sales,
                         category_summary=category_summary,
                         recent_movements=recent_movements,
                         server_info=server_info)
                         
@app.route('/inventory/pdf-template')
@login_required
def inventory_pdf_template():
    """Render PDF template for inventory report"""
    conn = get_db_connection()
    
    stats_data = get_inventory_stats()
    
    # Get stats with proper defaults
    stats_row = stats_data['stats']
    
    # Create stats object with default values
    stats = {
        'total_items': stats_row['total_items'] or 0 if stats_row['total_items'] is not None else 0,
        'total_stock': stats_row['total_stock'] or 0 if stats_row['total_stock'] is not None else 0,
        'low_stock_count': stats_row['low_stock_count'] or 0 if stats_row['low_stock_count'] is not None else 0,
        'total_inventory_value': stats_row['total_inventory_value'] or 0 if stats_row['total_inventory_value'] is not None else 0,
        'total_potential_value': stats_row['total_potential_value'] or 0 if stats_row['total_potential_value'] is not None else 0,
        'total_items_sold': stats_row['total_items_sold'] or 0 if stats_row['total_items_sold'] is not None else 0,
        'total_sales_value': stats_row['total_sales_value'] or 0 if stats_row['total_sales_value'] is not None else 0
    }
    
    items_with_sales = conn.execute('''
        SELECT 
            ci.*,
            COALESCE(SUM(i.quantity), 0) as total_sold_quantity,
            COALESCE(SUM(i.total), 0) as total_sales_revenue
        FROM clothing_items ci
        LEFT JOIN items i ON LOWER(ci.item_name) = LOWER(i.item_name)
        WHERE ci.is_active = 1
        GROUP BY ci.id
        ORDER BY ci.category, ci.item_name
    ''').fetchall()
    
    category_summary = conn.execute('''
        SELECT 
            category,
            COUNT(*) as item_count,
            COALESCE(SUM(current_stock), 0) as total_stock,
            COALESCE(SUM(current_stock * cost_price), 0) as inventory_value,
            COALESCE(SUM(current_stock * selling_price), 0) as potential_value,
            COALESCE(SUM(total_sold), 0) as total_sold
        FROM clothing_items 
        WHERE is_active = 1
        GROUP BY category
        ORDER BY inventory_value DESC
    ''').fetchall()
    
    # Get recent stock movements
    recent_movements = conn.execute('''
        SELECT sh.*, ci.item_code
        FROM stock_history sh
        JOIN clothing_items ci ON sh.item_id = ci.id
        ORDER BY sh.created_date DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    # Generate a report ID
    import random
    report_id = f"{datetime.now().strftime('%Y%m%d')}{random.randint(1000, 9999)}"
    
    return render_template('inventory_pdf_template.html',
                         stats=stats,
                         items_with_sales=items_with_sales,
                         category_summary=category_summary,
                         recent_movements=recent_movements,
                         report_id=report_id)

@app.route('/inventory/export/pdf')
@login_required
def export_inventory_pdf():
    """Export inventory report as downloadable PDF"""
    conn = get_db_connection()
    
    # Get inventory data
    items = conn.execute('''
        SELECT * FROM clothing_items 
        WHERE is_active = 1
        ORDER BY category, item_name
    ''').fetchall()
    
    stats = conn.execute('''
        SELECT 
            COUNT(*) as total_items,
            SUM(current_stock) as total_stock,
            SUM(CASE WHEN current_stock <= minimum_stock THEN 1 ELSE 0 END) as low_stock_count,
            SUM(current_stock * cost_price) as total_inventory_value,
            SUM(current_stock * selling_price) as total_potential_value,
            SUM(total_sold) as total_items_sold,
            SUM(total_sold * selling_price) as total_sales_value
        FROM clothing_items 
        WHERE is_active = 1
    ''').fetchone()
    
    # Get category summary
    category_summary = conn.execute('''
        SELECT 
            category,
            COUNT(*) as item_count,
            COALESCE(SUM(current_stock), 0) as total_stock,
            COALESCE(SUM(current_stock * cost_price), 0) as inventory_value,
            COALESCE(SUM(current_stock * selling_price), 0) as potential_value,
            COALESCE(SUM(total_sold), 0) as total_sold
        FROM clothing_items 
        WHERE is_active = 1
        GROUP BY category
        ORDER BY inventory_value DESC
    ''').fetchall()
    
    conn.close()
    
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=36, leftMargin=36,
                               topMargin=36, bottomMargin=36,
                               title="Textile Bazar Inventory Report")
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Custom Styles
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Title'],
            fontSize=20,
            textColor=colors.HexColor('#0066CC'),
            spaceAfter=15,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#004C99'),
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName='Helvetica'
        )
        
        header_style = ParagraphStyle(
            'HeaderStyle',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#0066CC'),
            spaceAfter=10,
            fontName='Helvetica-Bold'
        )
        
        normal_style = ParagraphStyle(
            'NormalStyle',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.black,
            fontName='Helvetica'
        )
        
        small_style = ParagraphStyle(
            'SmallStyle',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            fontName='Helvetica'
        )
        
        bold_style = ParagraphStyle(
            'BoldStyle',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.black,
            fontName='Helvetica-Bold'
        )
        
        # Title
        elements.append(Paragraph("TEXTILE BAZAR", title_style))
        elements.append(Paragraph("INVENTORY REPORT", subtitle_style))
        
        # Report Info
        report_info = f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        elements.append(Paragraph(report_info, small_style))
        elements.append(Spacer(1, 20))
        
        # Summary Statistics
        elements.append(Paragraph("SUMMARY STATISTICS", header_style))
        
        stats_data = [
            ['Total Items:', str(stats['total_items'] or 0)],
            ['Total Stock:', f"{stats['total_stock'] or 0} units"],
            ['Low Stock Items:', str(stats['low_stock_count'] or 0)],
            ['Inventory Value:', f"₹{stats['total_inventory_value'] or 0:,.2f}"],
            ['Potential Value:', f"₹{stats['total_potential_value'] or 0:,.2f}"],
            ['Total Items Sold:', str(stats['total_items_sold'] or 0)],
            ['Sales Revenue:', f"₹{stats['total_sales_value'] or 0:,.2f}"]
        ]
        
        stats_table = Table(stats_data, colWidths=[4*cm, 5*cm])
        stats_style = TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#0066CC')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#F8F9FA')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ])
        stats_table.setStyle(stats_style)
        elements.append(stats_table)
        elements.append(Spacer(1, 25))
        
        # Category Summary
        if category_summary:
            elements.append(Paragraph("CATEGORY SUMMARY", header_style))
            
            cat_data = [['Category', 'Items', 'Stock', 'Value', 'Potential', 'Sold']]
            
            for cat in category_summary:
                cat_data.append([
                    cat['category'],
                    str(cat['item_count']),
                    str(cat['total_stock']),
                    f"₹{cat['inventory_value']:,.2f}",
                    f"₹{cat['potential_value']:,.2f}",
                    str(cat['total_sold'])
                ])
            
            cat_table = Table(cat_data, colWidths=[3*cm, 1.5*cm, 1.5*cm, 2.5*cm, 2.5*cm, 1.5*cm])
            cat_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#004C99')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 1), (2, -1), 'CENTER'),
                ('ALIGN', (3, 1), (5, -1), 'RIGHT'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8F9FA')]),
            ])
            cat_table.setStyle(cat_style)
            elements.append(cat_table)
            elements.append(Spacer(1, 25))
        
        # Detailed Inventory Table
        if items:
            elements.append(Paragraph("DETAILED INVENTORY LIST", header_style))
            
            table_data = []
            header_row = [
                Paragraph('#', bold_style),
                Paragraph('Item Code', bold_style),
                Paragraph('Item Name', bold_style),
                Paragraph('Category', bold_style),
                Paragraph('Stock', bold_style),
                Paragraph('Min', bold_style),
                Paragraph('Status', bold_style),
                Paragraph('Cost', bold_style),
                Paragraph('Sell', bold_style),
                Paragraph('Sold', bold_style)
            ]
            table_data.append(header_row)
            
            for idx, item in enumerate(items, 1):
                # Determine status
                if item['current_stock'] <= 0:
                    status = 'OUT'
                    bg_color = colors.pink
                elif item['current_stock'] <= item['minimum_stock']:
                    status = 'LOW'
                    bg_color = colors.lightyellow
                else:
                    status = 'OK'
                    bg_color = colors.white
                
                row = [
                    Paragraph(str(idx), normal_style),
                    Paragraph(item['item_code'], normal_style),
                    Paragraph(item['item_name'], normal_style),
                    Paragraph(item['category'], normal_style),
                    Paragraph(str(item['current_stock']), normal_style),
                    Paragraph(str(item['minimum_stock']), normal_style),
                    Paragraph(status, bold_style),
                    Paragraph(f"₹{item['cost_price']:,.2f}", normal_style),
                    Paragraph(f"₹{item['selling_price']:,.2f}", normal_style),
                    Paragraph(str(item['total_sold'] or 0), normal_style)
                ]
                table_data.append(row)
            
            table = Table(table_data, colWidths=[0.7*cm, 1.5*cm, 3.5*cm, 2*cm, 1*cm, 1*cm, 1*cm, 1.5*cm, 1.5*cm, 1*cm])
            
            table_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0066CC')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ALIGN', (0, 1), (0, -1), 'CENTER'),
                ('ALIGN', (4, 1), (6, -1), 'CENTER'),
                ('ALIGN', (7, 1), (9, -1), 'RIGHT'),
            ])
            
            # Apply background colors for status
            for i in range(1, len(table_data)):
                item = items[i-1]
                if item['current_stock'] <= 0:
                    table_style.add('BACKGROUND', (0, i), (-1, i), colors.pink)
                elif item['current_stock'] <= item['minimum_stock']:
                    table_style.add('BACKGROUND', (0, i), (-1, i), colors.lightyellow)
            
            table.setStyle(table_style)
            elements.append(table)
        
        # Footer
        elements.append(Spacer(1, 30))
        footer_text = """
        <b>Textile Bazar Inventory Report</b><br/>
        Generated automatically. All amounts in Indian Rupees (INR ₹).<br/>
        This report includes all active inventory items as of the generation date.
        """
        footer = Paragraph(footer_text, small_style)
        elements.append(footer)
        
        # Build PDF
        doc.build(elements)
        
        # Get PDF content
        pdf = buffer.getvalue()
        buffer.close()
        
        # Create response with PDF
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename="textile_bazar_inventory_report.pdf"'
        
        return response
        
    except Exception as e:
        app.logger.error(f'Error generating PDF: {str(e)}')
        flash(f'❌ Error generating PDF: {str(e)}', 'danger')
        return redirect(url_for('inventory_report'))

# ============================================================================
# MAIN ROUTES WITH LOGIN REQUIRED
# ============================================================================

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_entry():
    """Add new item entry"""
    if request.method == 'POST':
        date = request.form['date']
        customer_name = request.form['customer_name'].strip()
        phone_number = request.form['phone_number'].strip()
        item_name = request.form['item_name'].strip()
        
        if not re.match(r'^[6-9]\d{9}$', phone_number):
            flash('Please enter a valid 10-digit Indian phone number', 'danger')
            return redirect(url_for('add_entry'))
        
        try:
            price = float(request.form['price'])
        except ValueError:
            flash('Please enter a valid price', 'danger')
            return redirect(url_for('add_entry'))
        
        try:
            quantity = int(request.form['quantity'])
        except ValueError:
            flash('Please enter a valid quantity', 'danger')
            return redirect(url_for('add_entry'))
        
        total = price * quantity
        
        if not all([date, customer_name, phone_number, item_name]):
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('add_entry'))
        
        if price <= 0 or quantity <= 0:
            flash('Price and quantity must be positive numbers', 'danger')
            return redirect(url_for('add_entry'))
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO items (date, customer_name, phone_number, item_name, price, quantity, total) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (date, customer_name, phone_number, item_name, price, quantity, total)
            )
            
            sale_id = cursor.lastrowid
            
            cursor.execute('''
                INSERT OR REPLACE INTO customers (name, phone, total_purchases, last_purchase_date, created_date)
                VALUES (
                    ?,
                    ?,
                    COALESCE((SELECT total_purchases FROM customers WHERE phone = ?), 0) + ?,
                    ?,
                    COALESCE((SELECT created_date FROM customers WHERE phone = ?), ?)
                )
            ''', (customer_name, phone_number, phone_number, total, date, phone_number, date))
            
            conn.commit()
            
            success, message = update_inventory_on_sale(item_name, quantity, sale_id)
            if not success:
                flash(f'⚠️ {message}', 'warning')
            else:
                flash(f'✅ {item_name} added successfully for {customer_name}!', 'success')
        except sqlite3.Error as e:
            flash(f'❌ Error adding item: {str(e)}', 'danger')
        finally:
            conn.close()
        
        return redirect(url_for('home', date=date))
    
    default_date = datetime.now().strftime('%Y-%m-%d')
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    return render_template('add.html', default_date=default_date, server_info=server_info)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_entry(id):
    """Edit an existing entry"""
    conn = get_db_connection()
    
    if request.method == 'POST':
        date = request.form['date']
        customer_name = request.form['customer_name'].strip()
        phone_number = request.form['phone_number'].strip()
        item_name = request.form['item_name'].strip()
        
        if not re.match(r'^[6-9]\d{9}$', phone_number):
            flash('Please enter a valid 10-digit Indian phone number', 'danger')
            return redirect(url_for('edit_entry', id=id))
        
        try:
            price = float(request.form['price'])
        except ValueError:
            flash('Please enter a valid price', 'danger')
            return redirect(url_for('edit_entry', id=id))
        
        try:
            quantity = int(request.form['quantity'])
        except ValueError:
            flash('Please enter a valid quantity', 'danger')
            return redirect(url_for('edit_entry', id=id))
        
        total = price * quantity
        
        if not all([date, customer_name, phone_number, item_name]):
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('edit_entry', id=id))
        
        if price <= 0 or quantity <= 0:
            flash('Price and quantity must be positive numbers', 'danger')
            return redirect(url_for('edit_entry', id=id))
        
        old_item = conn.execute('SELECT * FROM items WHERE id = ?', (id,)).fetchone()
        
        quantity_diff = quantity - old_item['quantity']
        
        try:
            conn.execute(
                '''UPDATE items 
                   SET date = ?, customer_name = ?, phone_number = ?, item_name = ?, price = ?, quantity = ?, total = ?
                   WHERE id = ?''',
                (date, customer_name, phone_number, item_name, price, quantity, total, id)
            )
            
            if old_item:
                amount_diff = total - old_item['total']
                
                conn.execute('''
                    UPDATE customers 
                    SET total_purchases = total_purchases + ?,
                        last_purchase_date = ?
                    WHERE phone = ?
                ''', (amount_diff, date, phone_number))
            
            conn.commit()
            
            if quantity_diff != 0:
                if quantity_diff > 0:
                    success, message = update_inventory_on_sale(item_name, quantity_diff, id)
                else:
                    success, message = restock_item_by_name(item_name, abs(quantity_diff), f"Sale adjustment for order #{id}")
                
                if not success:
                    flash(f'⚠️ {message}', 'warning')
            
            flash(f'✅ {item_name} updated successfully for {customer_name}!', 'success')
        except sqlite3.Error as e:
            flash(f'❌ Error updating item: {str(e)}', 'danger')
        
        conn.close()
        return redirect(url_for('home', date=date))
    
    item = conn.execute('SELECT * FROM items WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    if not item:
        flash('Item not found!', 'danger')
        return redirect(url_for('home'))
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('add.html', 
                         item=item, 
                         default_date=item['date'],
                         edit_mode=True,
                         server_info=server_info)

@app.route('/delete/<int:id>')
@login_required
def delete_entry(id):
    """Delete a specific entry"""
    conn = get_db_connection()
    
    item = conn.execute('SELECT * FROM items WHERE id = ?', (id,)).fetchone()
    
    if item:
        try:
            conn.execute('DELETE FROM items WHERE id = ?', (id,))
            
            conn.execute('''
                UPDATE customers 
                SET total_purchases = total_purchases - ?
                WHERE phone = ?
            ''', (item['total'], item['phone_number']))
            
            conn.execute('''
                DELETE FROM customers 
                WHERE phone = ? 
                AND (SELECT COUNT(*) FROM items WHERE phone_number = ?) = 0
            ''', (item['phone_number'], item['phone_number']))
            
            conn.commit()
            
            success, message = restock_item_by_name(item['item_name'], item['quantity'], f"Sale deletion for order #{id}")
            if not success:
                flash(f'⚠️ {message}', 'warning')
            
            flash(f'✅ {item["item_name"]} deleted successfully for {item["customer_name"]}!', 'success')
        except sqlite3.Error as e:
            flash(f'❌ Error deleting item: {str(e)}', 'danger')
    else:
        flash('Item not found!', 'danger')
    
    conn.close()
    
    date = item['date'] if item else datetime.now().strftime('%Y-%m-%d')
    return redirect(url_for('home', date=date))

@app.route('/customers')
@login_required
def customers():
    """View all customers"""
    conn = get_db_connection()
    
    customers_list = conn.execute('''
        SELECT c.*, 
               COUNT(i.id) as total_transactions,
               MAX(i.date) as recent_purchase_date
        FROM customers c
        LEFT JOIN items i ON c.phone = i.phone_number
        GROUP BY c.id
        ORDER BY c.total_purchases DESC
    ''').fetchall()
    
    stats = conn.execute('''
        SELECT 
            COUNT(*) as total_customers,
            SUM(total_purchases) as total_revenue,
            AVG(total_purchases) as avg_spent,
            MIN(created_date) as first_customer_date,
            MAX(last_purchase_date) as last_purchase_date
        FROM customers
    ''').fetchone()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('customers.html',
                         customers=customers_list,
                         stats=stats,
                         server_info=server_info)

@app.route('/customer/<phone>')
@login_required
def customer_detail(phone):
    """View customer details and purchase history"""
    conn = get_db_connection()
    
    customer = conn.execute(
        'SELECT * FROM customers WHERE phone = ?',
        (phone,)
    ).fetchone()
    
    if not customer:
        flash('Customer not found!', 'danger')
        return redirect(url_for('customers'))
    
    purchases = conn.execute('''
        SELECT * FROM items 
        WHERE phone_number = ? 
        ORDER BY date DESC, id DESC
    ''', (phone,)).fetchall()
    
    total_spent = sum(p['total'] for p in purchases) if purchases else 0
    total_items = sum(p['quantity'] for p in purchases) if purchases else 0
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('customer_detail.html',
                         customer=customer,
                         purchases=purchases,
                         total_spent=total_spent,
                         total_items=total_items,
                         server_info=server_info)

@app.route('/search_customers', methods=['GET', 'POST'])
@login_required
def search_customers():
    """Search for customers by name or phone"""
    query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'both')
    
    if not query:
        return redirect(url_for('customers'))
    
    conn = get_db_connection()
    
    if search_type == 'name':
        customers_list = conn.execute('''
            SELECT c.*, 
                   COUNT(i.id) as total_transactions,
                   MAX(i.date) as recent_purchase_date
            FROM customers c
            LEFT JOIN items i ON c.phone = i.phone_number
            WHERE LOWER(c.name) LIKE ?
            GROUP BY c.id
            ORDER BY c.total_purchases DESC
        ''', (f'%{query.lower()}%',)).fetchall()
    elif search_type == 'phone':
        customers_list = conn.execute('''
            SELECT c.*, 
                   COUNT(i.id) as total_transactions,
                   MAX(i.date) as recent_purchase_date
            FROM customers c
            LEFT JOIN items i ON c.phone = i.phone_number
            WHERE c.phone LIKE ?
            GROUP BY c.id
            ORDER BY c.total_purchases DESC
        ''', (f'%{query}%',)).fetchall()
    else:
        customers_list = conn.execute('''
            SELECT c.*, 
                   COUNT(i.id) as total_transactions,
                   MAX(i.date) as recent_purchase_date
            FROM customers c
            LEFT JOIN items i ON c.phone = i.phone_number
            WHERE LOWER(c.name) LIKE ? OR c.phone LIKE ?
            GROUP BY c.id
            ORDER BY c.total_purchases DESC
        ''', (f'%{query.lower()}%', f'%{query}%')).fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('search_customers.html',
                         customers=customers_list,
                         query=query,
                         search_type=search_type,
                         server_info=server_info)

@app.route('/whatsapp_preview/<int:id>')
@login_required
def whatsapp_preview(id):
    """Preview PDF bill info before sending"""
    conn = get_db_connection()
    
    item = conn.execute('SELECT * FROM items WHERE id = ?', (id,)).fetchone()
    
    if not item:
        flash('Transaction not found!', 'danger')
        return redirect(url_for('home'))
    
    items = conn.execute('''
        SELECT * FROM items 
        WHERE phone_number = ? AND date = ?
        ORDER BY item_name
    ''', (item['phone_number'], item['date'])).fetchall()
    
    total_result = conn.execute('''
        SELECT SUM(total) as total 
        FROM items 
        WHERE phone_number = ? AND date = ?
    ''', (item['phone_number'], item['date'])).fetchone()
    total = total_result['total'] if total_result['total'] is not None else 0
    
    bill_number = f"TB{datetime.now().strftime('%Y%m%d')}{id:04d}"
    
    pdf_filename = f"textile_bazar_bill_{bill_number}.pdf"
    pdf_download_url = get_pdf_download_url(pdf_filename)
    
    whatsapp_message = create_whatsapp_pdf_link_message(
        item['customer_name'],
        bill_number,
        total,
        pdf_download_url
    )
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('whatsapp_preview.html',
                         customer_name=item['customer_name'],
                         phone_number=item['phone_number'],
                         date=item['date'],
                         items=items,
                         total=total,
                         bill_number=bill_number,
                         whatsapp_message=whatsapp_message,
                         pdf_download_url=pdf_download_url,
                         item_id=id,
                         server_info=server_info)

@app.route('/send_bulk_whatsapp/<date>/<phone>')
@login_required
def send_bulk_whatsapp(date, phone):
    """Send WhatsApp message for all items of a customer on a specific date"""
    conn = get_db_connection()
    
    customer = conn.execute(
        'SELECT * FROM customers WHERE phone = ?',
        (phone,)
    ).fetchone()
    
    if not customer:
        flash('Customer not found!', 'danger')
        return redirect(url_for('home', date=date))
    
    items = conn.execute('''
        SELECT * FROM items 
        WHERE phone_number = ? AND date = ?
        ORDER BY item_name
    ''', (phone, date)).fetchall()
    
    if not items:
        flash('No items found for this customer on the selected date!', 'danger')
        return redirect(url_for('home', date=date))
    
    total = sum(item['total'] for item in items)
    
    bill_number = f"TB{date.replace('-', '')}{phone[-4:]}"
    
    try:
        pdf_content = generate_whatsapp_pdf(
            customer['name'],
            phone,
            date,
            items,
            total,
            bill_number
        )
        
        pdf_filename = f"textile_bazar_bill_{bill_number}.pdf"
        
        if not ensure_temp_directory():
            flash('Error creating temporary directory for PDF', 'danger')
            conn.close()
            return redirect(url_for('home', date=date))
        
        pdf_path = os.path.join('static', 'temp', pdf_filename)
        with open(pdf_path, 'wb') as f:
            f.write(pdf_content)
        
        pdf_download_url = get_pdf_download_url(pdf_filename)
        
        whatsapp_message = create_whatsapp_pdf_link_message(
            customer['name'],
            bill_number,
            total,
            pdf_download_url
        )
        
        whatsapp_url = f"https://wa.me/91{phone}?text={quote(whatsapp_message)}"
        
        conn.execute('''
            UPDATE items 
            SET pdf_generated = 1,
                pdf_filename = ?,
                bill_sent = 1, 
                bill_sent_date = ?
            WHERE phone_number = ? AND date = ?
        ''', (pdf_filename, datetime.now().isoformat(), phone, date))
        
        conn.commit()
        conn.close()
        
        flash(f'PDF generated and WhatsApp message prepared for {customer["name"]}!', 'success')
        
        return redirect(whatsapp_url)
        
    except Exception as e:
        conn.close()
        flash(f'Error generating PDF: {str(e)}', 'danger')
        return redirect(url_for('home', date=date))

@app.route('/pdf/<date>')
@login_required
def generate_pdf(date):
    """Generate and download PDF report for a specific date"""
    try:
        conn = get_db_connection()
        
        items = conn.execute('''
            SELECT i.*, 
                   CASE WHEN i.bill_sent = 1 THEN 'Yes' ELSE 'No' END as bill_sent_status
            FROM items i 
            WHERE date = ? 
            ORDER BY customer_name, item_name
        ''', (date,)).fetchall()
        
        daily_total_result = conn.execute(
            'SELECT SUM(total) as total FROM items WHERE date = ?',
            (date,)
        ).fetchone()
        daily_total = daily_total_result['total'] if daily_total_result['total'] is not None else 0
        
        total_customers = len(set(item['customer_name'] for item in items))
        total_items = sum(item['quantity'] for item in items)
        total_transactions = len(items)
        
        conn.close()
        
        # Debug logging
        app.logger.info(f"Generating PDF for {date} with {len(items)} items")
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=72,
                               title=f"Textile Bazar Report - {date}")
        
        elements = []
        styles = getSampleStyleSheet()
        
        # ... (rest of your PDF generation code remains the same)
        
        doc.build(elements)
        pdf = buffer.getvalue()
        buffer.close()
        
        app.logger.info(f"PDF generated successfully for {date}, size: {len(pdf)} bytes")
        
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="textile_bazar_report_{date}.pdf"'
        
        return response
        
    except Exception as e:
        app.logger.error(f'❌ Error generating PDF: {str(e)}', exc_info=True)
        flash(f'❌ Error generating PDF: {str(e)}', 'danger')
        return redirect(url_for('home', date=date))

@app.route('/stats')
@login_required
def stats():
    """Show statistics and summaries"""
    conn = get_db_connection()
    
    stats_data = conn.execute('''
        SELECT 
            COUNT(DISTINCT customer_name) as total_customers,
            COUNT(*) as total_transactions,
            SUM(quantity) as total_items,
            SUM(total) as grand_total,
            AVG(price) as avg_price,
            MIN(date) as first_date,
            MAX(date) as last_date,
            COUNT(DISTINCT date) as total_days
        FROM items
    ''').fetchone()
    
    recent_dates = conn.execute('''
        SELECT date, 
               SUM(total) as daily_total, 
               COUNT(*) as transaction_count,
               COUNT(DISTINCT customer_name) as customer_count
        FROM items 
        GROUP BY date 
        ORDER BY date DESC 
        LIMIT 10
    ''').fetchall()
    
    top_customers = conn.execute('''
        SELECT customer_name, 
               phone_number,
               SUM(total) as total_spent,
               SUM(quantity) as total_items,
               COUNT(*) as transaction_count
        FROM items 
        GROUP BY customer_name, phone_number
        ORDER BY total_spent DESC 
        LIMIT 10
    ''').fetchall()
    
    top_items = conn.execute('''
        SELECT item_name, 
               SUM(total) as item_total, 
               SUM(quantity) as total_quantity,
               COUNT(DISTINCT customer_name) as customer_count
        FROM items 
        GROUP BY item_name 
        ORDER BY item_total DESC 
        LIMIT 10
    ''').fetchall()
    
    monthly_summary = conn.execute('''
        SELECT 
            strftime('%Y-%m', date) as month,
            COUNT(DISTINCT customer_name) as customer_count,
            COUNT(*) as transaction_count,
            SUM(total) as monthly_total,
            SUM(quantity) as monthly_quantity
        FROM items 
        GROUP BY strftime('%Y-%m', date)
        ORDER BY month DESC
        LIMIT 6
    ''').fetchall()
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('stats.html',
                         stats=stats_data,
                         recent_dates=recent_dates,
                         top_customers=top_customers,
                         top_items=top_items,
                         monthly_summary=monthly_summary,
                         server_info=server_info)

@app.route('/search', methods=['GET'])
@login_required
def search():
    """Search for items"""
    query = request.args.get('q', '').strip()
    date = request.args.get('date', '')
    customer = request.args.get('customer', '')
    
    if not query and not date and not customer:
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    
    if date:
        items = conn.execute(
            '''SELECT i.*, 
                      CASE WHEN i.bill_sent = 1 THEN 'Yes' ELSE 'No' END as bill_sent_status
               FROM items i 
               WHERE date = ? 
               ORDER BY customer_name, item_name''',
            (date,)
        ).fetchall()
        search_type = f"Date: {date}"
    elif customer:
        items = conn.execute(
            '''SELECT i.*, 
                      CASE WHEN i.bill_sent = 1 THEN 'Yes' ELSE 'No' END as bill_sent_status
               FROM items i 
               WHERE LOWER(customer_name) LIKE ? 
               ORDER BY date DESC, item_name''',
            (f'%{customer.lower()}%',)
        ).fetchall()
        search_type = f"Customer: {customer}"
    elif query:
        items = conn.execute(
            '''SELECT i.*, 
                      CASE WHEN i.bill_sent = 1 THEN 'Yes' ELSE 'No' END as bill_sent_status
               FROM items i 
               WHERE LOWER(item_name) LIKE ? 
               ORDER BY date DESC, customer_name''',
            (f'%{query.lower()}%',)
        ).fetchall()
        search_type = f"Item: {query}"
    else:
        items = []
        search_type = "All"
    
    total_amount = sum(item['total'] for item in items) if items else 0
    total_items = len(items)
    unique_customers = len(set(item['customer_name'] for item in items)) if items else 0
    
    conn.close()
    
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    
    return render_template('search.html',
                         items=items,
                         search_query=query,
                         search_date=date,
                         search_customer=customer,
                         search_type=search_type,
                         total_amount=total_amount,
                         item_count=total_items,
                         customer_count=unique_customers,
                         server_info=server_info)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        conn = get_db_connection()
        conn.execute('SELECT 1')
        conn.close()
        db_status = '✅ Connected'
    except Exception as e:
        db_status = f'❌ Error: {str(e)}'
    
    health_info = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'server': {
            'environment': 'Production' if is_production() else 'Development',
            'base_url': get_server_base_url(),
            'pythonanywhere': 'PYTHONANYWHERE_DOMAIN' in os.environ,
            'debug_mode': app.debug
        },
        'database': db_status,
        'pdf_generation': 'ReportLab',
        'currency': 'Indian Rupees (₹)',
        'features': {
            'customer_management': 'Enabled',
            'whatsapp_integration': 'Enabled',
            'pdf_reports': 'Enabled',
            'whatsapp_pdf': 'Enabled',
            'inventory_management': 'Enabled',
            'pwa': 'Enabled',
            'auto_server_detection': 'Enabled',
            'qr_code_management': 'Enabled',
            'qr_payment_tracking': 'Enabled'
        }
    }
    
    return jsonify(health_info)

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def page_not_found(e):
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page not found",
                         server_info=server_info), 404

@app.errorhandler(500)
def internal_server_error(e):
    server_info = {
        'is_production': is_production(),
        'base_url': get_server_base_url()
    }
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Internal server error",
                         server_info=server_info), 500

# ============================================================================
# MAIN APPLICATION
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("TEXTILE BAZAR - Clothing Store Management System")
    print("=" * 60)
    
    try:
        import reportlab
        print(f"✓ ReportLab version: {reportlab.Version}")
        print("✓ PDF generation: READY")
    except ImportError:
        print("✗ ReportLab not installed. PDF generation will not work.")
    
    try:
        init_database()
        print("✓ Database: INITIALIZED")
    except Exception as e:
        print(f"✗ Database error: {e}")
    
    try:
        if not os.path.exists('static'):
            os.makedirs('static')
        
        temp_path = os.path.join('static', 'temp')
        if os.path.exists(temp_path) and not os.path.isdir(temp_path):
            os.remove(temp_path)
            print("✓ Removed file 'temp' that was blocking directory creation")
        
        # Create all necessary directories
        os.makedirs(temp_path, exist_ok=True)
        os.makedirs(os.path.join('static', 'icons'), exist_ok=True)
        os.makedirs(os.path.join('static', 'screenshots'), exist_ok=True)
        os.makedirs(os.path.join('static', 'qr_codes'), exist_ok=True)
        print("✓ Directories: CLEANED AND CREATED")
    except Exception as e:
        print(f"✗ Directory creation error: {e}")
    
    server_type = "PRODUCTION" if is_production() else "DEVELOPMENT"
    base_url = get_server_base_url()
    
    print(f"\n🌐 Server Environment: {server_type}")
    print(f"🔗 Base URL: {base_url}")
    print(f"📅 Current date: {datetime.now().strftime('%Y-%m-%d')}")
    print("💵 Currency: Indian Rupees (₹)")
    print("📱 WhatsApp Integration: READY")
    print("📄 WhatsApp PDF Bills: READY")
    print("📦 Inventory Management: READY")
    print("📱 PWA Support: READY")
    print("🔐 Authentication: ENABLED")
    print("💰 QR Code Management: ENABLED")
    print("💰 QR Payment Tracking: ENABLED")
    print("\n📊 PAYMENTS MODULE:")
    print("   - QR Codes: /payments/qr-codes")
    print("   - Payment History: /payments/history")
    print("   - Add Payment: /payments/add")
    print("   - Payment Statistics: /payments/stats")
    print("\n📁 AUTH MODULE:")
    print("   - Landing Page: /")
    print("   - Dashboard: /home (after login)")
    print("   - Inventory: /inventory")
    print("   - Login: /auth/login")
    print("   - Register: /auth/register")
    print("   - Profile: /auth/profile")
    print(f"\n🔗 Available at: {base_url}")
    print("   Default admin: admin / admin123")
    print("   Press Ctrl+C to stop")
    print("=" * 60)
    
    if is_production():
        app.config['DEBUG'] = False
        app.config['ENV'] = 'production'
        port = 8080
    else:
        app.config['DEBUG'] = True
        app.config['ENV'] = 'development'
        port = 5000
    
    app.run(
        debug=app.config['DEBUG'], 
        port=port, 
        host='0.0.0.0',
        threaded=True
    )