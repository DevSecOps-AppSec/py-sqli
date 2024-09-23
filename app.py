from flask import Flask, request, render_template_string, g, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for session management

# Database connection setup
DATABASE = 'users.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db

def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()

@app.teardown_appcontext
def teardown_db(exception):
    close_db()

# Initialize the database and add multiple users
def init_db():
    db = get_db()
    cursor = db.cursor()
    # Create a table for storing users
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL
                      )''')
    # Insert multiple sample users
    users = [
        ('admin', 'password123'),
        ('user1', 'pass1'),
        ('user2', 'pass2'),
        ('john_doe', 'john123'),
        ('jane_doe', 'jane123'),
        ('guest', 'guestpass'),
        ('testuser', 'testpass')
    ]
    # Clear existing data and insert new users
    cursor.execute('DELETE FROM users')  # Optional: clear existing data
    cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
    db.commit()

# Home page with navigation
@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        return render_template_string('''
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
                <title>Welcome</title>
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="card p-4 shadow-sm">
                        <h2 class="text-center">Welcome, {{ username }}</h2>
                        <hr>
                        {% if username == 'admin' %}
                            <a href="/search-user" class="btn btn-primary btn-block mb-3">Search User by ID</a>
                        {% endif %}
                        <a href="/logout" class="btn btn-danger btn-block">Logout</a>
                    </div>
                </div>
                <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
                <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
                <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
            </body>
            </html>
        ''', username=username)
    else:
        return render_template_string('''
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
                <title>Home</title>
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="card p-4 shadow-sm">
                        <h2 class="text-center">Welcome to SQL Injection Demo</h2>
                        <hr>
                        <a href="/login" class="btn btn-primary btn-block">Login</a>
                    </div>
                </div>
                <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
                <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
                <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
            </body>
            </html>
        ''')

# Login page and functionality
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"Executing SQL Query: {query}")  # Print the SQL query being executed
        result = db.execute(query).fetchone()
        if result:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template_string('''
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
                    <title>Login Failed</title>
                </head>
                <body class="bg-light">
                    <div class="container mt-5">
                        <div class="alert alert-danger text-center">
                            Invalid credentials!
                        </div>
                        <a href="/login" class="btn btn-secondary btn-block">Try Again</a>
                    </div>
                    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
                    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
                    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
                </body>
                </html>
            ''')
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
            <title>Login</title>
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="card p-4 shadow-sm">
                    <h2 class="text-center">Login</h2>
                    <form method="post">
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" class="form-control" id="username" name="username" placeholder="Enter username" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" class="form-control" id="password" name="password" placeholder="Enter password" required>
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">Login</button>
                    </form>
                </div>
                <a href="/" class="btn btn-secondary mt-3 btn-block">Go Back</a>
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        </body>
        </html>
    ''')

# Logout functionality
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

# Vulnerable search functionality accessible to all logged-in users through forced browsing
@app.route('/search-user', methods=['GET', 'POST'])
def search_user():
    # Allow access to all logged-in users without displaying the link on the home page for non-admin users
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = request.form['user_id']
        db = get_db()
        try:
            # Intentionally vulnerable SQL query allowing SQL injection
            query = f"SELECT * FROM users WHERE id = {user_id}"
            print(f"Executing SQL Query: {query}")  # Print the SQL query being executed
            result = db.execute(query).fetchall()  # Fetch all results to demonstrate vulnerability
            
            # Display all fetched user data in a vulnerable manner
            user_data = '<br>'.join([f"ID: {row[0]}, Username: {row[1]}, Password: {row[2]}" for row in result])
            
            if result:
                return render_template_string(f'''
                    <!doctype html>
                    <html lang="en">
                    <head>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
                        <title>User Details</title>
                    </head>
                    <body class="bg-light">
                        <div class="container mt-5">
                            <div class="card p-4 shadow-sm">
                                <h2 class="text-center">User Details</h2>
                                <p>{user_data}</p>
                                <a href="/search-user" class="btn btn-secondary mt-3 btn-block">Search Another User</a>
                                <a href="/" class="btn btn-primary mt-3 btn-block">Home</a>
                            </div>
                        </div>
                        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
                        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
                        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
                    </body>
                    </html>
                ''')
            else:
                return render_template_string('''
                    <!doctype html>
                    <html lang="en">
                    <head>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
                        <title>No User Found</title>
                    </head>
                    <body class="bg-light">
                        <div class="container mt-5">
                            <div class="alert alert-warning text-center">
                                No user found with that ID!
                            </div>
                            <a href="/search-user" class="btn btn-secondary btn-block">Try Again</a>
                            <a href="/" class="btn btn-primary btn-block">Home</a>
                        </div>
                        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
                        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
                        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
                    </body>
                    </html>
                ''')
        except Exception as e:
            return render_template_string(f'''
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
                    <title>Error</title>
                </head>
                <body class="bg-light">
                    <div class="container mt-5">
                        <div class="alert alert-danger text-center">
                            An error occurred: {str(e)}
                        </div>
                        <a href="/search-user" class="btn btn-secondary btn-block">Try Again</a>
                        <a href="/" class="btn btn-primary btn-block">Home</a>
                    </div>
                    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
                    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
                    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
                </body>
                </html>
            ''')
    
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
            <title>Search User</title>
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="card p-4 shadow-sm">
                    <h2 class="text-center">Search User by ID</h2>
                    <form method="post">
                        <div class="form-group">
                            <label for="user_id">User ID</label>
                            <input type="text" class="form-control" id="user_id" name="user_id" placeholder="Enter User ID" required>
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">Search</button>
                    </form>
                </div>
                <a href="/" class="btn btn-secondary mt-3 btn-block">Home</a>
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        </body>
        </html>
    ''')

if __name__ == '__main__':
    # Wrap init_db() inside app context
    with app.app_context():
        init_db()
    # Run the Flask app on port 8080
    app.run(debug=True, port=8080)
    