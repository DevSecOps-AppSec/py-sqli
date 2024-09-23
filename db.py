import sqlite3
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

def init_db():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL
                      )''')
    users = [
        ('admin', 'password123'),
        ('user1', 'pass1'),
        ('user2', 'pass2'),
        ('john_doe', 'john123'),
        ('jane_doe', 'jane123'),
        ('guest', 'guestpass'),
        ('testuser', 'testpass')
    ]
    cursor.execute('DELETE FROM users')  # Optional: clear existing data
    cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
    db.commit()
    