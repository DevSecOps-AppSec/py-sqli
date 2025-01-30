from flask import Flask
from db import init_db
from routes import configure_routes

# Set environment: Change this value to 'production' or 'development'
ENV = 'production'  # Change to 'production' when deploying

app = Flask(__name__)

# Configuration based on environment
if ENV == 'production':
    app.config['SECRET_KEY'] = 'your_production_secret_key'
    DEBUG_MODE = False
    HOST = '0.0.0.0'
    PORT = 8080
else:
    app.config['SECRET_KEY'] = 'your_dev_secret_key'
    DEBUG_MODE = True
    HOST = '127.0.0.1'
    PORT = 8083

# Initialize the database
with app.app_context():
    init_db()

# Configure routes
configure_routes(app)

if __name__ == '__main__':
    app.run(debug=DEBUG_MODE, host=HOST, port=PORT)
    
