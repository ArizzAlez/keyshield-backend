import os
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import jwt
import psycopg
from urllib.parse import urlparse

# Setup
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-permanent-secret-key')

# CORS - Allow your domain
CORS(app, origins=[
    "https://keyshield.my",
    "https://www.keyshield.my",
    "http://localhost:3000",
    "http://127.0.0.1:3000"
])

bcrypt = Bcrypt(app)

# PERMANENT PostgreSQL Connection
def get_db_connection():
    try:
        # Railway provides DATABASE_URL
        database_url = os.environ.get('DATABASE_URL')
        
        if database_url:
            # Connect using psycopg3 (modern, works with Python 3.13)
            conn = psycopg.connect(database_url)
            logging.info("✅ PostgreSQL connected successfully with psycopg3!")
            return conn
        else:
            # Fallback for local development
            conn = psycopg.connect(
                host=os.environ.get('DB_HOST', 'localhost'),
                dbname=os.environ.get('DB_NAME', 'keyshield'),
                user=os.environ.get('DB_USER', 'postgres'),
                password=os.environ.get('DB_PASSWORD', ''),
                port=os.environ.get('DB_PORT', 5432)
            )
            return conn
            
    except Exception as e:
        logging.error(f"❌ PostgreSQL connection failed: {e}")
        return None

# Initialize PERMANENT database tables
def init_database():
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        with conn.cursor() as cursor:
            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id SERIAL PRIMARY KEY,
                    username VARCHAR(80) UNIQUE NOT NULL,
                    email VARCHAR(120) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    keystroke_model TEXT
                )
            """)
            
            # User activities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_activities (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(user_id),
                    activity_type VARCHAR(50),
                    domain VARCHAR(255),
                    details TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Security events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(user_id),
                    domain VARCHAR(255),
                    event_type VARCHAR(100),
                    verdict VARCHAR(100),
                    details TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Websites table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS websites (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(user_id),
                    domain VARCHAR(255),
                    keystrokes_protected INTEGER DEFAULT 0,
                    phishing_attempts_blocked INTEGER DEFAULT 0,
                    last_visited TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # User activity stats table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_activity_stats (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(user_id),
                    keystrokes_protected INTEGER DEFAULT 0,
                    websites_checked INTEGER DEFAULT 0,
                    phishing_blocked INTEGER DEFAULT 0,
                    threats_detected INTEGER DEFAULT 0,
                    last_updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
        
        conn.commit()
        conn.close()
        logging.info("✅ PERMANENT database tables created successfully!")
        return True
        
    except Exception as e:
        logging.error(f"❌ Database initialization failed: {e}")
        return False

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    conn = get_db_connection()
    if conn:
        conn.close()
        return jsonify({
            'status': 'healthy', 
            'database': 'PostgreSQL connected',
            'message': 'PERMANENT solution running!'
        })
    return jsonify({'status': 'unhealthy', 'database': 'disconnected'}), 503

# Database setup endpoint
@app.route('/setup-db', methods=['GET'])
def setup_database_route():
    if init_database():
        return jsonify({'success': True, 'message': 'PERMANENT database initialized!'})
    return jsonify({'success': False, 'message': 'Database initialization failed'}), 500

# PERMANENT Registration endpoint
@app.route('/api/register', methods=['POST'])
def register():
    logging.info("📝 Registration attempt received")
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400

        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400

        # Initialize database
        init_database()

        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'message': 'Database unavailable'}), 503

        with conn.cursor() as cursor:
            # Check if user exists
            cursor.execute(
                "SELECT user_id FROM users WHERE username = %s OR email = %s", 
                (username, email)
            )
            if cursor.fetchone():
                conn.close()
                return jsonify({'success': False, 'message': 'Username or email already exists'}), 400

            # Create user
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING user_id",
                (username, email, password_hash)
            )
            
            user_id = cursor.fetchone()[0]
            conn.commit()
            conn.close()

        logging.info(f"✅ User registered successfully: {username} (ID: {user_id})")
        return jsonify({
            'success': True, 
            'message': 'Registration successful!',
            'user_id': user_id
        }), 201

    except Exception as e:
        logging.error(f"❌ Registration error: {e}")
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500

# PERMANENT Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'message': 'Database unavailable'}), 503

        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT user_id, username, password_hash FROM users WHERE username = %s", 
                (username,)
            )
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

            # Verify password
            if not bcrypt.check_password_hash(user[2], password):  # password_hash is index 2
                conn.close()
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

            # Generate JWT token
            token = jwt.encode({
                'user_id': user[0],  # user_id is index 0
                'username': user[1], # username is index 1
                'exp': datetime.now(timezone.utc).timestamp() + 86400  # 24 hours
            }, app.config['SECRET_KEY'], algorithm='HS256')

            conn.close()

            return jsonify({
                'success': True,
                'message': 'Login successful!',
                'token': token,
                'username': user[1],
                'requires_enrollment': False
            })

    except Exception as e:
        logging.error(f"❌ Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

# Main endpoint
@app.route('/')
def home():
    return jsonify({'message': 'KeyShield PERMANENT PostgreSQL API is LIVE! 🚀'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
