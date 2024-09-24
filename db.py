import sqlite3
import hashlib
from flask import g

DATABASE = 'users.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db

def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()

def hash_password(password):
    """Hash a password using MD5."""
    return hashlib.md5(password.encode()).hexdigest()

def init_db():
    db = get_db()
    cursor = db.cursor()
    # Create a table for storing users
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL
                      )''')

    # Create a table for storing products
    cursor.execute('''CREATE TABLE IF NOT EXISTS products (
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        price REAL NOT NULL
                      )''')

    # Insert sample products if they don't exist
    cursor.execute("DELETE FROM products")  # Optional: clear existing products
    products = [
        (1, 'Laptop', 1000.00),
        (2, 'Smartphone', 500.00),
        (3, 'Headphones', 150.00),
        (4, 'Keyboard', 100.00),
        (5, 'Mouse', 50.00)
    ]
    cursor.executemany('INSERT INTO products (id, name, price) VALUES (?, ?, ?)', products)

    # Insert sample users if they don't exist
    users = [
        ('admin', hash_password('password123')),
        ('user1', hash_password('pass1')),
        ('user2', hash_password('pass2')),
        ('john_doe', hash_password('john123')),
        ('jane_doe', hash_password('jane123')),
        ('guest', hash_password('guestpass')),
        ('testuser', hash_password('testpass'))
    ]
    cursor.execute('DELETE FROM users')  # Optional: clear existing data
    cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
    db.commit()
    