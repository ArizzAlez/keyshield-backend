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

# CORS
CORS(app, origins=[
    "https://keyshield.my",
    "https://www.keyshield.my", 
    "http://localhost:3000",
    "http://127.0.0.1:3000"
])

bcrypt = Bcrypt(app)

# PostgreSQL Connection
def get_db_connection():
    try:
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            conn = psycopg.connect(database_url)
            logging.info("✅ PostgreSQL connected successfully!")
            return conn
        return None
    except Exception as e:
        logging.error(f"❌ Database connection failed: {e}")
        return None

# Initialize database
def init_database():
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id SERIAL PRIMARY KEY,
                    username VARCHAR(80) UNIQUE NOT NULL,
                    email VARCHAR(120) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
        conn.commit()
        conn.close()
        logging.info("✅ Database tables created!")
        return True
    except Exception as e:
        logging.error(f"❌ Database init failed: {e}")
        return False

# Health check
@app.route('/health', methods=['GET'])
def health_check():
    conn = get_db_connection()
    if conn:
        conn.close()
        return jsonify({'status': 'healthy', 'database': 'PostgreSQL connected'})
    return jsonify({'status': 'unhealthy'}), 503

# Database setup
@app.route('/setup-db', methods=['GET'])
def setup_database():
    if init_database():
        return jsonify({'success': True, 'message': 'Database ready!'})
    return jsonify({'success': False, 'message': 'Database setup failed'}), 500

# Registration
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400

        init_database()
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'message': 'Database unavailable'}), 503

        with conn.cursor() as cursor:
            cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                conn.close()
                return jsonify({'success': False, 'message': 'User already exists'}), 400

            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING user_id",
                (username, email, password_hash)
            )
            user_id = cursor.fetchone()[0]
            conn.commit()
            conn.close()

        return jsonify({
            'success': True, 
            'message': 'Registration successful!',
            'user_id': user_id
        }), 201

    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/')
def home():
    return jsonify({'message': 'KeyShield API LIVE with PostgreSQL! 🚀'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
