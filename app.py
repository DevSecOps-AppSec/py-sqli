from flask import Flask
from db import init_db
from routes import configure_routes

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for session management

# Initialize the database
with app.app_context():
    init_db()

# Configure routes
configure_routes(app)

if __name__ == '__main__':
    app.run(debug=True, port=8082)
