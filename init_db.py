import sqlite3
from datetime import datetime
import hashlib

DATABASE = 'textile_bazar.db'

def hash_password(password):
    """Hash password using SHA-256 with salt"""
    salt = "textile-bazar-2024"
    return hashlib.sha256((password + salt).encode()).hexdigest()

def init_database_with_inventory():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create items table (sales transactions)
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
    
    # Create customers table
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
    
    # Create users table for authentication
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
            locked_until TEXT
        )
    ''')
    
    # **NEW: Create clothing_items table for inventory management**
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
    
    # **NEW: Create stock_history table**
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stock_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            transaction_type TEXT NOT NULL, -- 'purchase', 'sale', 'return', 'adjustment'
            quantity INTEGER NOT NULL,
            previous_stock INTEGER NOT NULL,
            new_stock INTEGER NOT NULL,
            reference_id TEXT, -- Reference to sale ID or purchase ID
            notes TEXT,
            created_by TEXT,
            created_date TEXT NOT NULL,
            FOREIGN KEY (item_id) REFERENCES clothing_items (id)
        )
    ''')
    
    # **NEW: Create categories table**
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_name TEXT UNIQUE NOT NULL,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_date TEXT NOT NULL
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_date ON items (date)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_customer_name ON items (customer_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_phone ON items (phone_number)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_customer_phone ON customers (phone)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)')
    
    # **NEW: Indexes for inventory**
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clothing_items_name ON clothing_items (item_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clothing_items_code ON clothing_items (item_code)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clothing_items_category ON clothing_items (category)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_stock_history_item ON stock_history (item_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_stock_history_date ON stock_history (created_date)')
    
    # Check if admin user exists, create if not
    cursor.execute("SELECT COUNT(*) as count FROM users WHERE username = 'admin'")
    admin_exists = cursor.fetchone()[0]
    
    if admin_exists == 0:
        # Create default admin user (password: admin123)
        password_hash = hash_password('admin123')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@textilebazar.com', password_hash, 'Administrator', 'admin', datetime.now().isoformat()))
        print("✅ Created default admin user (username: admin, password: admin123)")
    
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
    
    # Insert sample clothing items
    sample_items = [
        ('CT001', 'Cotton Shirt', 'Shirts', 'Pure cotton formal shirt', 'White', 'M', 450.00, 799.00, 50, 10),
        ('DT002', 'Denim Jeans', 'Pants', 'Blue denim jeans', 'Blue', '32', 800.00, 1499.00, 30, 5),
        ('TS003', 'Polo T-Shirt', 'T-Shirts', 'Cotton polo t-shirt', 'Black', 'L', 250.00, 499.00, 100, 20),
        ('SR004', 'Silk Saree', 'Sarees', 'Pure silk saree with border', 'Red', 'Free', 1500.00, 2999.00, 15, 3),
        ('KT005', 'Cotton Kurta', 'Kurtas', 'Handloom cotton kurta', 'White', 'XL', 600.00, 1199.00, 25, 5),
        ('DR006', 'Summer Dress', 'Dresses', 'Floral summer dress', 'Pink', 'M', 700.00, 1299.00, 20, 4),
        ('JK007', 'Leather Jacket', 'Jackets', 'Genuine leather jacket', 'Black', 'L', 2000.00, 3999.00, 10, 2),
        ('SC008', 'Woolen Scarf', 'Accessories', 'Winter woolen scarf', 'Grey', 'One Size', 150.00, 299.00, 50, 10)
    ]
    
    for item_code, item_name, category, description, color, size, cost_price, selling_price, current_stock, min_stock in sample_items:
        cursor.execute('SELECT id FROM clothing_items WHERE item_code = ?', (item_code,))
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO clothing_items (item_code, item_name, category, description, color, size, 
                                          cost_price, selling_price, current_stock, minimum_stock, 
                                          created_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (item_code, item_name, category, description, color, size, 
                  cost_price, selling_price, current_stock, min_stock, 
                  datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    print("=" * 60)
    print("✅ Textile Bazar Database with Inventory INITIALIZED!")
    print("=" * 60)
    print("📦 Inventory Tables Created:")
    print("   - clothing_items (for storing clothing products)")
    print("   - stock_history (for tracking stock changes)")
    print("   - categories (for product categorization)")
    print("")
    print("📊 Sample Data Added:")
    print("   8 default categories")
    print("   8 sample clothing items with inventory")
    print("")
    print("🔐 Default Admin Credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("=" * 60)

if __name__ == '__main__':
    init_database_with_inventory()