"""
invenzu - Inventory Management System
Backend: Python 3 + Flask + SQLite3
"""

import csv
import os
import sqlite3
import hashlib
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from datetime import datetime, timedelta
from io import StringIO


def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def check_pw(hashed: str, password: str) -> bool:
    return hashed == hash_pw(password)


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY',
    'invenzu-super-secret-key-2025'
)

DB_PATH = os.path.join(os.path.dirname(__file__), 'invenzu.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def create_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("PRAGMA foreign_keys = ON")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suppliers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT NOT NULL,
            address TEXT NOT NULL,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            brand TEXT NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 0,
            price REAL NOT NULL DEFAULT 0.0,
            supplier_id INTEGER,
            status TEXT NOT NULL DEFAULT 'In Stock',
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (supplier_id)
                REFERENCES suppliers(id)
                ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS stock_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            reason TEXT,
            transaction_date TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id)
                REFERENCES products(id)
                ON DELETE CASCADE
        )
    """)

    if cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO users
            (full_name, username, email, password_hash)
            VALUES (?, ?, ?, ?)
        """, (
            "Indu",
            "indu",
            "indu123@example.com",
            hash_pw("password123")
        ))


    # Ensure user ownership columns exist in older databases.
    supplier_columns = [row[1] for row in cursor.execute("PRAGMA table_info(suppliers)").fetchall()]
    if 'user_id' not in supplier_columns:
        cursor.execute("ALTER TABLE suppliers ADD COLUMN user_id INTEGER")

    product_columns = [row[1] for row in cursor.execute("PRAGMA table_info(products)").fetchall()]
    if 'user_id' not in product_columns:
        cursor.execute("ALTER TABLE products ADD COLUMN user_id INTEGER")

    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


@app.context_processor
def inject_user():
    db = get_db()

    low_stock_notifications = db.execute("""
        SELECT id, name, quantity
        FROM products
        WHERE user_id = ?
        AND quantity <= 5
        ORDER BY quantity ASC, name ASC
    """, (session.get('user_id', 0),)).fetchall()

    db.close()

    return {
         'current_user': session.get('username'),
         'current_user_name': session.get('username'),
         'current_user_email': session.get('email'),
         'unread_notifications': len(low_stock_notifications),
         'low_stock_notifications': low_stock_notifications
        }
        


# =========================================================
# AUTH ROUTES
# =========================================================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form.get(
            'username',
            ''
        ).strip()

        password = request.form.get(
            'password',
            ''
        ).strip()

        db = get_db()

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE username = ? OR email = ?
            """,
            (username, username)
        ).fetchone()

        db.close()

        if user and check_pw(
            user['password_hash'],
            password
        ):

            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['email'] = user['email']

            flash(
                'Welcome back, ' + user['full_name'] + '!',
                'success'
            )

            return redirect(
                url_for('dashboard')
            )

        else:
            flash(
                'Invalid username or password!',
                'error'
            )

    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'GET':
        session.pop('_flashes', None)

    if request.method == 'POST':

        email = request.form.get(
            'email',
            ''
        ).strip()

        new_password = request.form.get(
            'new_password',
            ''
        )

        confirm_password = request.form.get(
            'confirm_password',
            ''
        )

        if not email or not new_password or not confirm_password:

            flash(
                'Please fill in all fields.',
                'error'
            )

            return render_template(
                'forgot_password.html'
            )

        if new_password != confirm_password:

            flash(
                'Passwords do not match!',
                'error'
            )

            return render_template(
                'forgot_password.html'
            )

        if len(new_password) < 6:

            flash(
                'Password must contain at least 6 characters.',
                'error'
            )

            return render_template(
                'forgot_password.html'
            )

        db = get_db()

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if not user:

            db.close()

            flash(
                'No account was found with that email address.',
                'error'
            )

            return render_template(
                'forgot_password.html'
            )

        new_password_hash = hash_pw(
            new_password
        )

        db.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            """,
            (
                new_password_hash,
                user['id']
            )
        )

        db.commit()
        db.close()

        flash(
            'Password reset successfully! Please login with your new password.',
            'success'
        )

        return redirect(
            url_for('login')
        )

    return render_template(
        'forgot_password.html'
    )


@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        full_name = request.form.get(
            'full_name',
            ''
        ).strip()

        username = request.form.get(
            'username',
            ''
        ).strip()

        email = request.form.get(
            'email',
            ''
        ).strip()

        password = request.form.get(
            'password',
            ''
        )

        confirm_password = request.form.get(
            'confirm_password',
            ''
        )

        if not full_name or not username or not email or not password:

            flash(
                'Please fill in all required fields.',
                'error'
            )

            return render_template(
                'register.html'
            )

        if password != confirm_password:

            flash(
                'Passwords do not match!',
                'error'
            )

            return render_template(
                'register.html'
            )

        db = get_db()

        existing = db.execute(
            """
            SELECT id
            FROM users
            WHERE username = ? OR email = ?
            """,
            (username, email)
        ).fetchone()

        if existing:

            flash(
                'Username or email already exists!',
                'error'
            )

            db.close()

            return render_template(
                'register.html'
            )

        p_hash = hash_pw(password)

        db.execute(
            """
            INSERT INTO users
            (full_name, username, email, password_hash)
            VALUES (?, ?, ?, ?)
            """,
            (
                full_name,
                username,
                email,
                p_hash
            )
        )

        db.commit()
        db.close()

        flash(
            'Account created successfully! Please login.',
            'success'
        )

        return redirect(
            url_for('login')
        )

    return render_template(
        'register.html'
    )


@app.route('/logout', methods=['POST', 'GET'])
def logout():

    session.clear()

    flash(
        'You have been logged out securely.',
        'info'
    )

    return redirect(
        url_for('login')
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():

    db = get_db()

    selected_date = request.args.get('date')

    if selected_date:
        try:
            current_date = datetime.strptime(
            selected_date,
            '%Y-%m-%d'
        )
        except ValueError:
            current_date = datetime.now()
    else:
        current_date = datetime.now()

    selected_date_string = current_date.strftime('%Y-%m-%d')

    # Get products belonging to the current user
    products_for_date = db.execute(
        """
        SELECT id,name, quantity, created_at
        FROM products
        WHERE user_id = ?
        """,
        (session['user_id'],)
    ).fetchall()

    total_products = 0
    total_stock = 0
    low_stock = 0
    out_of_stock = 0

    for product in products_for_date:

        # Product did not exist on the selected date
        if product['created_at']:
            created_date = product['created_at'][:10]

            if created_date > selected_date_string:
                continue

        total_products += 1

        # Start with the current quantity
        quantity_on_date = product['quantity']

        # Reverse transactions that happened after the selected date
        transactions_after_date = db.execute(
            """
            SELECT action_type, quantity
            FROM stock_transactions
            WHERE product_id = ?
            AND transaction_date > ?
            """,
            (
                product['id'],
                selected_date_string
            )
        ).fetchall()

        for transaction in transactions_after_date:

            if transaction['action_type'] == 'Stock In':
                quantity_on_date -= transaction['quantity']

            elif transaction['action_type'] == 'Stock Out':
                quantity_on_date += transaction['quantity']

        total_stock += quantity_on_date

        if quantity_on_date == 0:
            out_of_stock += 1

        elif quantity_on_date <= 5:
            low_stock += 1

    # Supplier count on the selected date
    total_suppliers = db.execute(
        """
        SELECT COUNT(*) as count
        FROM suppliers
        WHERE user_id = ?
        AND (
            created_at IS NULL
            OR substr(created_at, 1, 10) <= ?
        )
        """,
        (
            session['user_id'],
            selected_date_string
        )
    ).fetchone()['count']   

    recent_activity = db.execute("""
        SELECT
            t.id,
            p.name as product_name,
            t.action_type,
            t.quantity,
            t.transaction_date
        FROM stock_transactions t
        JOIN products p
            ON t.product_id = p.id
        WHERE p.user_id = ?
        AND t.transaction_date = ?
        ORDER BY t.id DESC
        LIMIT 5
    """, (
        session['user_id'],
        selected_date_string
    )).fetchall()

    low_stock_products = []

    for product in products_for_date:

        if product['created_at']:
            created_date = product['created_at'][:10]

            if created_date > selected_date_string:
                continue

        quantity_on_date = product['quantity']

        transactions_after_date = db.execute(
            """
            SELECT action_type, quantity
            FROM stock_transactions
            WHERE product_id = ?
            AND transaction_date > ?
            """,
            (
                product['id'],
                selected_date_string
            )
        ).fetchall()

        for transaction in transactions_after_date:

            if transaction['action_type'] == 'Stock In':
                quantity_on_date -= transaction['quantity']

            elif transaction['action_type'] == 'Stock Out':
                quantity_on_date += transaction['quantity']

        if quantity_on_date <= 5:
            low_stock_products.append({
                'id': product['id'],
                'name': product['name'],
                'quantity': quantity_on_date
            })

    low_stock_products = sorted(
        low_stock_products,
        key=lambda product: product['quantity']
    )[:5]

    # =====================================================
    # STOCK OVERVIEW
    # =====================================================

        # Stock Status for the selected date
    current_in_stock = total_products - out_of_stock

    current_out_stock = out_of_stock

    chart_labels = []
    chart_stock_in = []
    chart_stock_out = []

    # Calculate product stock status for each of the last 7 days
    for i in range(6, -1, -1):

        day = current_date - timedelta(days=i)
        date_string = day.strftime('%Y-%m-%d')

        chart_labels.append(
            day.strftime('%b %d')
        )

        # Get all products belonging to the current user
        products_for_day = db.execute(
            """
            SELECT id, quantity, created_at
            FROM products
            WHERE user_id = ?
            """,
            (session['user_id'],)
        ).fetchall()

        total_stock_on_day = 0
        out_of_stock_products = 0

        for product in products_for_day:

            # Products created after this day did not exist yet
            if product['created_at']:
                created_date = product['created_at'][:10]

                if created_date > date_string:
                    continue

            # Start from the current quantity
            quantity_on_day = product['quantity']

            # Reverse transactions that happened after this day
            transactions_after_day = db.execute(
                """
                SELECT action_type, quantity
                FROM stock_transactions
                WHERE product_id = ?
                AND transaction_date > ?
                """,
                (
                    product['id'],
                    date_string
                )
            ).fetchall()

            for transaction in transactions_after_day:

                if transaction['action_type'] == 'Stock In':
                    quantity_on_day -= transaction['quantity']

                elif transaction['action_type'] == 'Stock Out':
                    quantity_on_day += transaction['quantity']

            total_stock_on_day += quantity_on_day

            if quantity_on_day == 0:
                out_of_stock_products += 1

        chart_stock_in.append(total_stock_on_day)
        chart_stock_out.append(out_of_stock_products)
    
    db.close()

    return render_template(
        'dashboard.html',
        total_products=total_products,
        total_stock=total_stock,
        low_stock=low_stock,
        total_suppliers=total_suppliers,
        out_of_stock=out_of_stock,
        recent_activity=recent_activity,
        low_stock_products=low_stock_products,
        current_date=current_date,
        chart_labels=chart_labels,
        chart_stock_in=chart_stock_in,
        chart_stock_out=chart_stock_out,
        current_in_stock=current_in_stock,
        current_out_stock=current_out_stock
    )

# =========================================================
# PRODUCTS CRUD
# =========================================================

@app.route('/products')
@login_required
def products():

    search = request.args.get(
        'search',
        ''
    ).strip()

    category = request.args.get(
        'category',
        ''
    ).strip()

    status = request.args.get(
        'status',
        ''
    ).strip()

    # Pagination
    per_page = 10

    try:
        page = int(
            request.args.get(
                'page',
                1
            )
        )
    except ValueError:
        page = 1

    if page < 1:
        page = 1

    # Main query
    query = """
        SELECT
            p.*,
            s.name as supplier_name
        FROM products p
        LEFT JOIN suppliers s
            ON p.supplier_id = s.id
            AND s.user_id = p.user_id
        WHERE p.user_id = ?
    """

    params = [session['user_id']]

    if search:
        query += """
            AND (
                p.name LIKE ?
                OR p.brand LIKE ?
            )
        """

        params.extend([
            f'%{search}%',
            f'%{search}%'
        ])

    if category and category != 'All Categories':
        query += """
            AND p.category = ?
        """

        params.append(category)

    if status and status != 'All Status':
        query += """
            AND p.status = ?
        """

        params.append(status)

    # Count matching products
    count_query = """
        SELECT COUNT(*)
        FROM products p
        WHERE p.user_id = ?
    """

    count_params = [session['user_id']]

    if search:
        count_query += """
            AND (
                p.name LIKE ?
                OR p.brand LIKE ?
            )
        """

        count_params.extend([
            f'%{search}%',
            f'%{search}%'
        ])

    if category and category != 'All Categories':
        count_query += """
            AND p.category = ?
        """

        count_params.append(category)

    if status and status != 'All Status':
        count_query += """
            AND p.status = ?
        """

        count_params.append(status)

    db = get_db()

    total_products = db.execute(
        count_query,
        count_params
    ).fetchone()[0]

    # Calculate total pages
    total_pages = max(
        1,
        (total_products + per_page - 1) // per_page
    )

    if page > total_pages:
        page = total_pages

    offset = (
        page - 1
    ) * per_page

    # Get current page
    query += """
        ORDER BY p.id ASC
        LIMIT ? OFFSET ?
    """

    params.extend([
        per_page,
        offset
    ])

    products_list = db.execute(
        query,
        params
    ).fetchall()

    # Categories
    categories = [
        row['category']
        for row in db.execute(
            """
            SELECT DISTINCT category
            FROM products
            WHERE user_id = ?
            ORDER BY category ASC
            """,
            (session['user_id'],)
        ).fetchall()
    ]

    db.close()

    return render_template(
        'products.html',
        products=products_list,
        categories=categories,
        selected_category=category,
        selected_status=status,
        search=search,
        current_page=page,
        total_pages=total_pages,
        total_products=total_products,
        per_page=per_page
    )


@app.route('/products/add', methods=['GET', 'POST'])
@login_required
def add_product():

    db = get_db()

    if request.method == 'POST':

        name = request.form.get(
            'name',
            ''
        ).strip()

        category = request.form.get(
            'category',
            ''
        ).strip()

        brand = request.form.get(
            'brand',
            ''
        ).strip()

        quantity = request.form.get(
            'quantity',
            0
        )

        price = request.form.get(
            'price',
            0
        )

        supplier_id = request.form.get(
            'supplier_id'
        )

        if supplier_id:
            supplier = db.execute(
                """
                SELECT id
                FROM suppliers
                WHERE id = ? AND user_id = ?
                """,
                (supplier_id, session['user_id'])
            ).fetchone()

            if not supplier:
                flash('Invalid supplier selected.', 'error')
                suppliers = db.execute(
                    """
                    SELECT id, name
                    FROM suppliers
                    WHERE user_id = ?
                    ORDER BY name ASC
                    """,
                    (session['user_id'],)
                ).fetchall()
                db.close()
                return render_template('add_product.html', suppliers=suppliers)

        try:

            qty_int = int(quantity)

            if qty_int < 0:

                flash(
                    'Product quantity cannot be negative!',
                    'error'
                )

                suppliers = db.execute(
                    """
                    SELECT id, name
                    FROM suppliers
                    WHERE user_id = ?
                    ORDER BY name ASC
                    """,
                    (session['user_id'],)
                ).fetchall()

                db.close()

                return render_template(
                    'add_product.html',
                    suppliers=suppliers
                )

            price_float = float(price)

        except ValueError:

            flash(
                'Invalid numeric values for quantity or price!',
                'error'
            )

            suppliers = db.execute(
                """
                SELECT id, name
                FROM suppliers
                WHERE user_id = ?
                ORDER BY name ASC
                """,
                (session['user_id'],)
            ).fetchall()

            db.close()

            return render_template(
                'add_product.html',
                suppliers=suppliers
            )
        if qty_int == 0:
            status = 'Out of Stock'
        elif qty_int <= 5:
            status = 'Low Stock'
        else:
            status = 'In Stock'

        db.execute("""
    INSERT INTO products
    (
        name,
        category,
        brand,
        quantity,
        price,
        supplier_id,
        status,
        user_id
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
       name,
       category,
       brand,
       qty_int,
       price_float,
       supplier_id,
       status,
      session['user_id']
    ))
        db.commit()
        db.close()

        flash(
            'Product added successfully!',
            'success'
        )

        return redirect(
            url_for('products')
        )

    suppliers = db.execute(
        """
        SELECT id, name
        FROM suppliers
        WHERE user_id = ?
        ORDER BY name ASC
        """,
        (session['user_id'],)
    ).fetchall()

    db.close()

    return render_template(
        'add_product.html',
        suppliers=suppliers
    )


@app.route('/products/<int:id>')
@login_required
def product_details(id):

    db = get_db()

    product = db.execute("""
        SELECT
            p.*,
            s.name as supplier_name
        FROM products p
        LEFT JOIN suppliers s
            ON p.supplier_id = s.id
            AND s.user_id = p.user_id
        WHERE p.id = ? AND p.user_id = ?
    """, (id,session['user_id'])).fetchone()

    if not product:

        db.close()

        return render_template(
            '404.html'
        ), 404

    stock_in = db.execute(
        """
        SELECT
            COALESCE(SUM(quantity), 0) as total
        FROM stock_transactions
        WHERE product_id = ?
        AND action_type = 'Stock In'
        """,
        (id,)
    ).fetchone()['total']

    stock_out = db.execute(
        """
        SELECT
            COALESCE(SUM(quantity), 0) as total
        FROM stock_transactions
        WHERE product_id = ?
        AND action_type = 'Stock Out'
        """,
        (id,)
    ).fetchone()['total']

   

    db.close()

    return render_template(
        'product_details.html',
        product=product,
        stock_in=stock_in,
        stock_out=stock_out
    )


@app.route('/products/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_product(id):

    db = get_db()

    product = db.execute(
        """
        SELECT *
        FROM products
        WHERE id = ? AND user_id = ?
        """,
        (id, session['user_id'])
    ).fetchone()

    if not product:

        db.close()

        return render_template(
            '404.html'
        ), 404

    if request.method == 'POST':

        name = request.form.get(
            'name',
            ''
        ).strip()

        category = request.form.get(
            'category',
            ''
        ).strip()

        brand = request.form.get(
            'brand',
            ''
        ).strip()

        quantity = int(
            request.form.get(
                'quantity',
                0
            )
        )

        price = float(
            request.form.get(
                'price',
                0
            )
        )

        supplier_id = request.form.get(
            'supplier_id'
        )

        if quantity == 0:
           status = 'Out of Stock'
        elif quantity <= 5:
           status = 'Low Stock'
        else:
           status = 'In Stock'

        if supplier_id:
            supplier = db.execute(
                """
                SELECT id
                FROM suppliers
                WHERE id = ? AND user_id = ?
                """,
                (supplier_id, session['user_id'])
            ).fetchone()

            if not supplier:
                flash('Invalid supplier selected.', 'error')
                suppliers = db.execute(
                    """
                    SELECT id, name
                    FROM suppliers
                    WHERE user_id = ?
                    ORDER BY name ASC
                    """,
                    (session['user_id'],)
                ).fetchall()
                db.close()
                return render_template('edit_product.html', product=product, suppliers=suppliers)

        # Record quantity changes in stock transactions
        old_quantity = product['quantity']

        if quantity > old_quantity:
           db.execute(
            """
             INSERT INTO stock_transactions
             (
               product_id,
               action_type,
               quantity,
               reason,
               transaction_date
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                id,
               'Stock In',
                quantity - old_quantity,
               'Quantity updated manually',
                datetime.now().strftime('%Y-%m-%d')
            )
         )

        elif quantity < old_quantity:
           db.execute(
            """
             INSERT INTO stock_transactions
             (
                product_id,
                action_type,
                quantity,
                reason,
                transaction_date
            )
            VALUES (?, ?, ?, ?, ?)
             """,
            (
               id,
              'Stock Out',
               old_quantity - quantity,
              'Quantity updated manually',
               datetime.now().strftime('%Y-%m-%d')
            )
         )
        db.execute("""
            UPDATE products
            SET
                name = ?,
                category = ?,
                brand = ?,
                quantity = ?,
                price = ?,
                supplier_id = ?,
                status = ?
            WHERE id = ? AND user_id = ?
        """, (
            name,
            category,
            brand,
            quantity,
            price,
            supplier_id,
            status,
            id,
            session['user_id']
        ))

        db.commit()
        db.close()

        flash(
            'Product updated successfully!',
            'success'
        )

        return redirect(
            url_for('products')
        )

    suppliers = db.execute(
        """
        SELECT id, name
        FROM suppliers
        WHERE user_id = ?
        ORDER BY name ASC
        """,
        (session['user_id'],)
    ).fetchall()

    db.close()

    return render_template(
        'edit_product.html',
        product=product,
        suppliers=suppliers
    )


@app.route('/products/delete/<int:id>', methods=['POST'])
@login_required
def delete_product(id):

    db = get_db()

    db.execute(
        """
        DELETE FROM products
        WHERE id = ? AND user_id = ?
        """,
        (id,session['user_id'])
    )

    db.commit()
    db.close()

    flash(
        'Product deleted successfully!',
        'success'
    )

    return redirect(
        url_for('products')
    )


# =========================================================
# SUPPLIERS CRUD
# =========================================================

@app.route('/suppliers')
@login_required
def suppliers():

    search = request.args.get(
        'search',
        ''
    ).strip()

    # Pagination
    per_page = 5

    try:
        page = int(
            request.args.get(
                'page',
                1
            )
        )
    except ValueError:
        page = 1

    if page < 1:
        page = 1

    # Main query
    query = """
        SELECT
            s.*,
            COUNT(p.id) as products_count
        FROM suppliers s
        LEFT JOIN products p
            ON s.id = p.supplier_id
            AND p.user_id = s.user_id
        WHERE s.user_id = ?
    """

    params = [session['user_id']]

    if search:
        query += """
            AND (
                s.name LIKE ?
                OR s.email LIKE ?
                OR s.phone LIKE ?
            )
        """

        params.extend([
            f'%{search}%',
            f'%{search}%',
            f'%{search}%'
        ])

    query += """
        GROUP BY s.id
        ORDER BY s.id ASC
    """

    # Count matching suppliers
    count_query = """
        SELECT COUNT(*)
        FROM suppliers
        WHERE user_id = ?
    """

    count_params = [session['user_id']]

    if search:
        count_query += """
            AND (
                name LIKE ?
                OR email LIKE ?
                OR phone LIKE ?
            )
        """

        count_params.extend([
            f'%{search}%',
            f'%{search}%',
            f'%{search}%'
        ])

    db = get_db()

    total_suppliers = db.execute(
        count_query,
        count_params
    ).fetchone()[0]

    # Calculate total pages
    total_pages = max(
        1,
        (total_suppliers + per_page - 1) // per_page
    )

    if page > total_pages:
        page = total_pages

    offset = (
        page - 1
    ) * per_page

    # Get current page
    query += """
        LIMIT ? OFFSET ?
    """

    params.extend([
        per_page,
        offset
    ])

    suppliers_list = db.execute(
        query,
        params
    ).fetchall()

    db.close()

    return render_template(
        'suppliers.html',
        suppliers=suppliers_list,
        search=search,
        current_page=page,
        total_pages=total_pages,
        total_suppliers=total_suppliers,
        per_page=per_page
    )


@app.route('/suppliers/add', methods=['GET', 'POST'])
@login_required
def add_supplier():

    if request.method == 'POST':

        name = request.form.get(
            'name',
            ''
        ).strip()

        phone = request.form.get(
            'phone',
            ''
        ).strip()

        email = request.form.get(
            'email',
            ''
        ).strip()

        address = request.form.get(
            'address',
            ''
        ).strip()

        db = get_db()

        db.execute(
            """
            INSERT INTO suppliers
            (name, phone, email, address, user_id)
            VALUES (?, ?, ?, ?, ?)
           """,
          (
            name,
            phone,
            email,
            address,
            session['user_id']
          )
        )

        db.commit()
        db.close()

        flash(
            'Supplier added successfully!',
            'success'
        )

        return redirect(
            url_for('suppliers')
        )

    return render_template(
        'add_supplier.html'
    )

# =========================================================
# EDIT SUPPLIER
# =========================================================

@app.route('/suppliers/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_supplier(id):

    db = get_db()

    supplier = db.execute(
        """
        SELECT *
        FROM suppliers
        WHERE id = ? AND user_id = ?
        """,
        (id, session['user_id'])
    ).fetchone()

    if not supplier:
        db.close()
        return render_template(
            '404.html'
        ), 404

    if request.method == 'POST':

        name = request.form.get(
            'name',
            ''
        ).strip()

        phone = request.form.get(
            'phone',
            ''
        ).strip()

        email = request.form.get(
            'email',
            ''
        ).strip()

        address = request.form.get(
            'address',
            ''
        ).strip()

        db.execute(
            """
            UPDATE suppliers
            SET
                name = ?,
                phone = ?,
                email = ?,
                address = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                name,
                phone,
                email,
                address,
                id,
                session['user_id']
            )
        )

        db.commit()
        db.close()

        flash(
            'Supplier updated successfully!',
            'success'
        )

        return redirect(
            url_for('suppliers')
        )

    db.close()

    return render_template(
        'edit_supplier.html',
        supplier=supplier
    )


# =========================================================
# DELETE SUPPLIER
# =========================================================

@app.route('/suppliers/delete/<int:id>', methods=['POST'])
@login_required
def delete_supplier(id):

    db = get_db()

    supplier = db.execute(
        """
        SELECT *
        FROM suppliers
        WHERE id = ? AND user_id = ?
        """,
        (id, session['user_id'])
    ).fetchone()

    if not supplier:
        db.close()
        return render_template(
            '404.html'
        ), 404

    db.execute(
    """
     UPDATE products
    SET supplier_id = NULL
    WHERE supplier_id = ? AND user_id = ?
    """,
    (id, session['user_id'])
    )

    db.execute(
    """
    DELETE FROM suppliers
    WHERE id = ? AND user_id = ?
    """,
    (id,session['user_id'])
    )

    db.commit()
    db.close()

    flash(
        'Supplier deleted successfully!',
        'success'
    )

    return redirect(
        url_for('suppliers')
    )

# =========================================================
# STOCK TRANSACTIONS
# =========================================================

@app.route('/stock-in', methods=['GET', 'POST'])
@login_required
def stock_in():

    db = get_db()

    if request.method == 'POST':

        product_id = request.form.get(
            'product_id'
        )

        quantity = int(
            request.form.get(
                'quantity',
                0
            )
        )

        reason = request.form.get(
            'reason',
            'New Purchase'
        )

        # Always use today's date
        date = datetime.now().strftime(
            '%Y-%m-%d'
        )

        if quantity <= 0:

            flash(
                'Quantity must be greater than 0!',
                'error'
            )

            products = db.execute(
                """
                SELECT id, name, quantity
                FROM products
                WHERE user_id = ?
                ORDER BY name ASC
                """,
                (session['user_id'],)
            ).fetchall()

            db.close()

            return render_template(
                'stock_in.html',
                products=products
            )

        product = db.execute(
            """
            SELECT id
            FROM products
            WHERE id = ? AND user_id = ?
            """,
            (product_id, session['user_id'])
        ).fetchone()

        if not product:
            flash('Invalid product selected.', 'error')
            products = db.execute(
                """
                SELECT id, name, quantity
                FROM products
                WHERE user_id = ?
                ORDER BY name ASC
                """,
                (session['user_id'],)
            ).fetchall()
            db.close()
            return render_template('stock_in.html', products=products)

        db.execute(
            """
            INSERT INTO stock_transactions
            (
                product_id,
                action_type,
                quantity,
                reason,
                transaction_date
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                product_id,
                'Stock In',
                quantity,
                reason,
                date
            )
        )

        db.execute(
            """
            UPDATE products
            SET
                quantity = quantity + ?,
                status =
                    CASE
                        WHEN quantity + ? > 5
                        THEN 'In Stock'
                        ELSE 'Low Stock'
                    END
            WHERE id = ? AND user_id = ?
            """,
            (
                quantity,
                quantity,
                product_id,
                session['user_id']
            )
        )

        db.commit()
        db.close()

        flash(
            f'Successfully added {quantity} units to inventory!',
            'success'
        )

        return redirect(
            url_for('dashboard')
        )

    products = db.execute(
        """
        SELECT id, name, quantity
        FROM products
        WHERE user_id = ?
        ORDER BY name ASC
        """,
        (session['user_id'],)
    ).fetchall()

    db.close()

    return render_template(
        'stock_in.html',
        products=products
    )


@app.route('/stock-out', methods=['GET', 'POST'])
@login_required
def stock_out():

    db = get_db()

    if request.method == 'POST':

        product_id = request.form.get(
            'product_id'
        )

        quantity = int(
            request.form.get(
                'quantity',
                0
            )
        )

        reason = request.form.get(
            'reason',
            'Sale / Damaged'
        )

        # Always use today's date
        date = datetime.now().strftime(
            '%Y-%m-%d'
        )

        product = db.execute(
            """
            SELECT quantity
            FROM products
            WHERE id = ? AND user_id = ?
            """,
            (product_id, session['user_id'])
        ).fetchone()

        if (
            not product
            or product['quantity'] < quantity
        ):

            flash(
                'Cannot remove more stock than available!',
                'error'
            )

            products = db.execute(
                """
                SELECT id, name, quantity
                FROM products
                WHERE user_id = ?
                ORDER BY name ASC
                """,
                (session['user_id'],)
            ).fetchall()

            db.close()

            return render_template(
                'stock_out.html',
                products=products
            )

        db.execute(
            """
            INSERT INTO stock_transactions
            (
                product_id,
                action_type,
                quantity,
                reason,
                transaction_date
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                product_id,
                'Stock Out',
                quantity,
                reason,
                date
            )
        )

        new_qty = (
            product['quantity'] - quantity
        )

        new_status = (
            'Out of Stock'
            if new_qty == 0
            else (
                'Low Stock'
                if new_qty <= 5
                else 'In Stock'
            )
        )

        db.execute(
            """
            UPDATE products
            SET quantity = ?, status = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                new_qty,
                new_status,
                product_id,
                session['user_id']
            )
        )

        db.commit()
        db.close()

        flash(
            f'Successfully deducted {quantity} units from inventory!',
            'success'
        )

        return redirect(
            url_for('dashboard')
        )

    products = db.execute(
        """
        SELECT id, name, quantity
        FROM products
        WHERE user_id = ?
        ORDER BY name ASC
        """,
        (session['user_id'],)
    ).fetchall()

    db.close()

    return render_template(
    'stock_out.html',
    products=products,
    current_date=datetime.now().strftime('%Y-%m-%d')
)

@app.route('/generate_report')
@login_required
def generate_report():

    db = get_db()

    products = db.execute(
        """
        SELECT
            products.id,
            products.name,
            products.quantity,
            products.price,
            suppliers.name AS supplier_name
        FROM products
        LEFT JOIN suppliers
        ON products.supplier_id = suppliers.id
        AND suppliers.user_id = products.user_id
        WHERE products.user_id = ?
        ORDER BY products.id
        """, (session['user_id'],)
    ).fetchall()

    total_products = db.execute(
        "SELECT COUNT(*) AS count FROM products WHERE user_id = ?",
        (session['user_id'],)
    ).fetchone()['count']

    total_stock = db.execute(
        "SELECT COALESCE(SUM(quantity), 0) AS total FROM products WHERE user_id = ?",
        (session['user_id'],)
    ).fetchone()['total']

    low_stock = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM products
        WHERE user_id = ?
        AND quantity > 0 AND quantity <= 5
        """,
        (session['user_id'],)
    ).fetchone()['count']

    out_of_stock = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM products
        WHERE user_id = ?
        AND quantity = 0
        """,
        (session['user_id'],)
    ).fetchone()['count']

    generated_date = datetime.now().strftime('%d %B %Y, %I:%M %p')

    db.close()

    return render_template(
        'inventory_report.html',
        products=products,
        total_products=total_products,
        total_stock=total_stock,
        low_stock=low_stock,
        out_of_stock=out_of_stock,
        generated_date=generated_date
    )
# =========================================================
# REPORTS
# =========================================================

@app.route('/reports')
@login_required
def reports():

    db = get_db()

    # -----------------------------
    # Summary statistics
    # -----------------------------
    total_products = db.execute(
        """
        SELECT COUNT(*) as count
        FROM products
        WHERE user_id = ?
        """,
        (session['user_id'],)
    ).fetchone()['count']

    total_stock = db.execute(
        """
        SELECT COALESCE(SUM(quantity), 0) as total
        FROM products
        WHERE user_id = ?
        """,
        (session['user_id'],)
    ).fetchone()['total']

    low_stock = db.execute(
        """
        SELECT COUNT(*) as count
        FROM products
        WHERE user_id = ?
        AND quantity > 0
        AND quantity <= 5
        """,
        (session['user_id'],)
    ).fetchone()['count']

    out_of_stock = db.execute(
        """
        SELECT COUNT(*) as count
        FROM products
        WHERE user_id = ?
        AND quantity = 0
        """,
        (session['user_id'],)
    ).fetchone()['count']

    # -----------------------------
    # Last 7 days stock activity
    # -----------------------------
    today = datetime.now().date()

    chart_labels = []
    chart_stock_in = []
    chart_stock_out = []

    for i in range(6, -1, -1):

        current_date = today - timedelta(days=i)

        chart_labels.append(
            current_date.strftime('%b %d')
        )

        stock_in_day = db.execute(
            """
            SELECT COALESCE(SUM(t.quantity), 0) AS total
            FROM stock_transactions t
            JOIN products p ON t.product_id = p.id
            WHERE t.action_type = 'Stock In'
            AND t.transaction_date = ?
            AND p.user_id = ?
            """,
            (current_date.isoformat(), session['user_id'])
        ).fetchone()['total']

        stock_out_day = db.execute(
            """
            SELECT COALESCE(SUM(t.quantity), 0) AS total
            FROM stock_transactions t
            JOIN products p ON t.product_id = p.id
            WHERE t.action_type = 'Stock Out'
            AND t.transaction_date = ?
            AND p.user_id = ?
            """,
            (current_date.isoformat(), session['user_id'])
        ).fetchone()['total']

        chart_stock_in.append(stock_in_day)
        chart_stock_out.append(stock_out_day)

    db.close()

    return render_template(
        'reports.html',
        total_products=total_products,
        total_stock=total_stock,
        low_stock=low_stock,
        out_of_stock=out_of_stock,
        chart_labels=chart_labels,
        chart_stock_in=chart_stock_in,
        chart_stock_out=chart_stock_out
    )

# =========================================================
# PROFILE
# =========================================================

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():

    db = get_db()

    if request.method == 'POST':

        full_name = request.form.get(
            'full_name',
            ''
        ).strip()

        email = request.form.get(
            'email',
            ''
        ).strip()

        current_password = request.form.get(
            'current_password',
            ''
        )

        new_password = request.form.get(
            'new_password',
            ''
        )

        confirm_new_password = request.form.get(
            'confirm_new_password',
            ''
        )

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (session.get('user_id', 1),)
        ).fetchone()

        if new_password:

            if not check_pw(
                user['password_hash'],
                current_password
            ):

                flash(
                    'Current password incorrect!',
                    'error'
                )

                db.close()

                return render_template(
                    'profile.html',
                    user=user
                )

            if new_password != confirm_new_password:

                flash(
                    'New passwords do not match!',
                    'error'
                )

                db.close()

                return render_template(
                    'profile.html',
                    user=user
                )

            p_hash = hash_pw(
                new_password
            )

            db.execute(
                """
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
                """,
                (
                    p_hash,
                    user['id']
                )
            )

        db.execute(
            """
            UPDATE users
            SET full_name = ?, email = ?
            WHERE id = ?
            """,
            (
                full_name or user['full_name'],
                email or user['email'],
                user['id']
            )
        )

        db.commit()

        session['full_name'] = (
            full_name or user['full_name']
        )

        session['email'] = (
            email or user['email']
        )

        db.close()

        flash(
            'Profile updated successfully!',
            'success'
        )

        return redirect(
            url_for('profile')
        )

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (session.get('user_id', 1),)
    ).fetchone()

    db.close()

    return render_template(
        'profile.html',
        user=user
    )


# =========================================================
# 404 HANDLER
# =========================================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template(
        '404.html'
    ), 404


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == '__main__':

    create_database()

    port = int(
        os.environ.get(
            'PORT',
            5000
        )
    )

    app.run(
        host='0.0.0.0',
        port=port,
        debug=False
    )