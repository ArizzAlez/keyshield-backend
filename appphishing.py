import os
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import psycopg2
from psycopg2 import sql

# Setup
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')

# CORS
CORS(app)

bcrypt = Bcrypt(app)

# Database connection
def get_db():
    try:
        # Railway provides DATABASE_URL
        conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
        logging.info("✅ Database connected!")
        return conn
    except Exception as e:
        logging.error(f"❌ Database connection failed: {e}")
        return None

# Initialize database
def init_db():
    conn = get_db()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Users table
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
        cursor.close()
        conn.close()
        logging.info("✅ Database initialized!")
        return True
    except Exception as e:
        logging.error(f"❌ Database init failed: {e}")
        return False

# Health check
@app.route('/health', methods=['GET'])
def health():
    if init_db():
        return jsonify({'status': 'healthy', 'database': 'connected'})
    return jsonify({'status': 'unhealthy'}), 500

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

        # Initialize DB
        init_db()

        conn = get_db()
        if not conn:
            return jsonify({'success': False, 'message': 'Database unavailable'}), 503

        cursor = conn.cursor()

        # Check existing user
        cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'User already exists'}), 400

        # Create user
        pwd_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING user_id",
            (username, email, pwd_hash)
        )
        
        user_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
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
    return jsonify({'message': 'KeyShield API running on Railway!'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
