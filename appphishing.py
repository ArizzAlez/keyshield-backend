import logging
import os
import json
import re
from datetime import datetime, timedelta, timezone 
from flask import Flask, request, jsonify, render_template, make_response
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import jwt
import mysql.connector.pooling
from functools import wraps
import random 
from urllib.parse import urlparse
from dotenv import load_dotenv  # ADD THIS LINE

# Load environment variables from .env file
load_dotenv()

# --- Configuration from Environment Variables ---
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-secret-key-change-in-production')
DOMAIN = os.environ.get('DOMAIN', 'https://keyshield.my')
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# --- Database Configuration from Environment Variables ---
db_pool_config = {
    "host": os.environ.get('DB_HOST', 'localhost'),
    "user": os.environ.get('DB_USER', 'keyshiel_ajiz'),
    "password": os.environ.get('DB_PASSWORD', 'Harris@2005'),
    "database": os.environ.get('DB_NAME', 'keyshiel_keyshield'),
    "pool_name": "mypool",
    "pool_size": 5
}

DB_NAME = os.environ.get('DB_NAME', 'keyshiel_keyshield')

# --- Phishing Detection Configuration ---
TRUSTED_DOMAINS = [
    "maybank2u.com.my",
    "www.maybank2u.com.my", 
    "cimbclicks.com.my",
    "www.cimbclicks.com.my",
    "rhbgroup.com",
    "www.rhbgroup.com",
    "publicbank.com.my",
    "www.publicbank.com.my",
    "hongleongconnect.my",
    "www.hongleongconnect.my",
]

def is_trusted_domain(hostname):
    return hostname.lower() in TRUSTED_DOMAINS

def is_ip(host):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) is not None

def analyze_url(url):
    """Comprehensive URL analysis for phishing detection"""
    reasons = []
    url = (url or "").strip()
    if not url:
        return 'suspicious', 'empty input'

    if not re.match(r'^https?://', url, flags=re.I):
        parsed_for_host = 'http://' + url
    else:
        parsed_for_host = url

    p = urlparse(parsed_for_host)
    scheme = (p.scheme or 'http').lower()
    host = p.hostname or ''
    
    # Skip HTTPS check for trusted domains
    if scheme != 'https' and not is_trusted_domain(host):
        reasons.append(f"No HTTPS (scheme: {scheme})")

    if not host:
        reasons.append("No host detected")
    else:
        if is_ip(host):
            reasons.append("Host is an IP address")
        if host.count('.') >= 4:
            reasons.append("Too many subdomains")
        
        # Only check for suspicious keywords on NON-trusted domains
        if not is_trusted_domain(host):
            suspicious_keywords = ['login','secure','bank','verify','account','update','confirm','paypal','ebay','apple']
            for w in suspicious_keywords:
                if w in host.lower():
                    reasons.append(f"Suspicious keyword: '{w}'")
                    break

    path = p.path or ''
    if '@' in path:
        reasons.append("Contains '@' in path")
    
    # Skip long URL check for trusted domains
    if not is_trusted_domain(host) and len(url) > 100:
        reasons.append("Very long URL")
        
    if re.search(r'%[0-9A-Fa-f]{2}', url):
        reasons.append("Contains URL-encoded characters")

    verdict = 'suspicious' if reasons else 'safe'
    return verdict, '; '.join(reasons)

# --- App Initialization ---
app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = SECRET_KEY

# --- CORS Configuration for Production ---
CORS(app, origins=[
    DOMAIN,
    "https://www.keyshield.my",
    "chrome-extension://*"  # Allow all Chrome extensions temporarily
])

bcrypt = Bcrypt(app)

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname)s in %(filename)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# --- Database Connection Pool Setup ---
db_pool = None

try:
    init_pool = mysql.connector.pooling.MySQLConnectionPool(**db_pool_config)
    logging.info("MySQL Initial Connection Pool (for setup) initialized.")

    def initialize_database(init_pool):
        """Only ensure database exists and insert test user"""
        conn = None
        try:
            conn = init_pool.get_connection()
            cursor = conn.cursor()

            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
            cursor.execute(f"USE {DB_NAME}") 
            logging.info(f"Database '{DB_NAME}' ensured and selected.")

            # Insert default test user if it doesn't exist
            test_username = "testuser"
            test_password = "testpassword"
            test_password_hash = bcrypt.generate_password_hash(test_password).decode('utf-8')

            cursor.execute("SELECT user_id FROM users WHERE username = %s", (test_username,))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash)
                    VALUES (%s, %s, %s)
                """, (test_username, "test@example.com", test_password_hash))
                conn.commit()
                logging.info(f"Default user '{test_username}' created.")
            else:
                logging.info(f"Default user '{test_username}' already exists.")

            cursor.close()
            
        except mysql.connector.Error as err:
            logging.error(f"Error during database initialization: {err}")
            raise
        finally:
            if conn:
                conn.close()

    initialize_database(init_pool)

    # Re-initialize the final connection pool with the database name
    db_pool_config['database'] = DB_NAME
    db_pool = mysql.connector.pooling.MySQLConnectionPool(**db_pool_config)
    logging.info(f"Final MySQL Connection Pool configured for database '{DB_NAME}'.")

except mysql.connector.Error as err:
    logging.error(f"FATAL: MySQL Connection initialization failed. Error: {err}")
    db_pool = None
except Exception as e:
    logging.error(f"FATAL: Database initialization failed: {e}")
    db_pool = None

def get_db_connection():
    """Retrieves a connection from the pool."""
    if db_pool:
        try:
            return db_pool.get_connection()
        except mysql.connector.Error as err:
            logging.error(f"Error getting connection from pool: {err}")
    return None

# --- JWT Decorator for protected routes ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                auth_header = request.headers['Authorization']
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token missing or badly formatted!'}), 401

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)
    return decorated

# --- Route for REGISTRATION ---
@app.route('/api/register', methods=['POST'])
def register():
    """Handle user registration for website dashboard"""
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'message': 'Missing username or password'}), 400

    username = request.json['username']
    email = request.json.get('email', '')
    password = request.json['password']
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor()
    try:
        # Check if user already exists
        cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", 
                      (username, email))
        if cursor.fetchone():
            return jsonify({'message': 'Username or email already exists'}), 400

        # Create new user
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute("""
            INSERT INTO users (username, email, password_hash)
            VALUES (%s, %s, %s)
        """, (username, email, password_hash))
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful'}), 201
        
    except mysql.connector.Error as err:
        logging.error(f"MySQL Error during registration: {err}")
        return jsonify({'message': 'Registration failed'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

# --- Route for LOGIN ---
@app.route('/api/login', methods=['POST'])
def api_login():
    """Unified login endpoint - accepts both username AND email with keystroke dynamics"""
    if not request.json or 'password' not in request.json:
        return jsonify({'message': 'Missing credentials'}), 400

    # Accept either username or email
    username = request.json.get('username', '')
    email = request.json.get('email', '')
    password = request.json['password']
    keystroke_timings = request.json.get('keystrokeTimings', [])
    current_speed = request.json.get('current_speed', 0)
    
    if not username and not email:
        return jsonify({'message': 'Please provide username or email'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor(dictionary=True)
    try:
        # Find user by username OR email
        if username:
            cursor.execute("SELECT user_id, username, password_hash, keystroke_model FROM users WHERE username = %s", (username,))
        else:
            cursor.execute("SELECT user_id, username, password_hash, keystroke_model FROM users WHERE email = %s", (email,))
            
        user = cursor.fetchone()

        if not user:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        # Verify password
        if not bcrypt.check_password_hash(user['password_hash'], password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        # Check if keystroke enrollment is needed
        requires_enrollment = False
        keystroke_model = user.get('keystroke_model')
        keystroke_valid = True  # Default to True if no model exists
        
        if keystroke_model:
            try:
                model_data = json.loads(keystroke_model)
                avg_speed = model_data.get('avg_speed', 0)
                tolerance = model_data.get('tolerance', 0.3)
                
                if avg_speed > 0 and current_speed > 0:
                    speed_variation = abs(current_speed - avg_speed) / avg_speed
                    is_speed_valid = speed_variation <= tolerance
                    
                    if not is_speed_valid:
                        logging.warning(f"Typing speed anomaly for user {user['username']}: {speed_variation*100:.1f}% variation (current: {current_speed:.2f}ms, expected: {avg_speed:.2f}ms)")
                        # BLOCK login for suspicious typing pattern
                        return jsonify({
                            'success': False, 
                            'message': 'Suspicious typing pattern detected. Please try again with your normal typing speed.',
                            'requires_enrollment': False
                        }), 401
                    else:
                        logging.info(f"Keystroke validation passed for user {user['username']}: {speed_variation*100:.1f}% variation")
                    
            except json.JSONDecodeError:
                logging.warning(f"Invalid keystroke model for user {user['username']}")
                requires_enrollment = True
        else:
            requires_enrollment = True

        # Generate JWT Token
        payload = {
            'user_id': user['user_id'],
            'username': user['username'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
        
        logging.info(f"Login successful for user: {user['username']}")
        
        return jsonify({
            'success': True, 
            'message': 'Login successful!', 
            'token': token,
            'username': user['username'],
            'requires_enrollment': requires_enrollment
        }), 200

    except mysql.connector.Error as err:
        logging.error(f"MySQL Error during login: {err}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

# --- ENROLLMENT ENDPOINT ---
@app.route('/api/enroll-keystroke', methods=['POST'])
@token_required
def enroll_keystroke():
    """Enroll user in keystroke dynamics for extension login"""
    user_id = request.user_id
    data = request.get_json()
    
    password = data.get('password')
    average_speed = data.get('average_speed')
    timing_samples = data.get('timing_samples', [])
    keystroke_data = data.get('keystroke_data', [])
    enrollment_times = data.get('enrollment_times', [])
    
    if not password or not average_speed:
        return jsonify({'success': False, 'message': 'Missing required data'}), 400

    # Verify password is correct
    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT password_hash FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user or not bcrypt.check_password_hash(user['password_hash'], password):
            return jsonify({'success': False, 'message': 'Password verification failed'}), 401
        
        # Store keystroke model
        keystroke_model = json.dumps({
            'avg_speed': average_speed,
            'samples': timing_samples,
            'enrolled_at': datetime.now(timezone.utc).isoformat(),
            'tolerance': 0.3,  # 30% tolerance
            'speed_unit': 'milliseconds'
        })
        
        cursor.execute("UPDATE users SET keystroke_model = %s WHERE user_id = %s", 
                      (keystroke_model, user_id))
        conn.commit()
        
        # Enhanced logging for keystroke enrollment
        logging.info(f"Keystroke enrollment for user_id: {user_id} - Avg speed: {average_speed:.2f}ms, "
                    f"Timing samples: {len(timing_samples)}, Keystroke data: {len(keystroke_data)}, "
                    f"Enrollment steps: {len(enrollment_times)}")
        
        return jsonify({'success': True, 'message': 'Keystroke protection enabled'}), 200
        
    except mysql.connector.Error as err:
        logging.error(f"MySQL Error during keystroke enrollment: {err}")
        return jsonify({'message': 'Enrollment failed'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

# --- DASHBOARD ENDPOINTS ---

@app.route('/api/stats', methods=['GET'])
@token_required
def get_user_stats():
    """Get user protection statistics for dashboard - USING REAL DATA FROM TABLES"""
    user_id = request.user_id
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor(dictionary=True, buffered=True)
    try:
        # REAL DATA: Total keystrokes protected from user_activities
        cursor.execute("""
            SELECT COUNT(*) as total_keystrokes 
            FROM user_activities 
            WHERE user_id = %s AND activity_type = 'keystrokes_protected'
        """, (user_id,))
        keystrokes_result = cursor.fetchone()
        total_keystrokes = keystrokes_result['total_keystrokes'] if keystrokes_result else 0

        # REAL DATA: Phishing attempts blocked (from phishing_reports + suspicious security_events)
        cursor.execute("""
            SELECT COUNT(*) as phishing_blocked 
            FROM phishing_reports 
            WHERE reporter = %s
        """, (user_id,))
        phishing_reports_result = cursor.fetchone()
        phishing_from_reports = phishing_reports_result['phishing_blocked'] if phishing_reports_result else 0

        # Also count suspicious security events as phishing attempts blocked
        cursor.execute("""
            SELECT COUNT(*) as suspicious_events 
            FROM security_events 
            WHERE user_id = %s AND (verdict = 'suspicious' OR verdict != 'safe')
        """, (user_id,))
        suspicious_result = cursor.fetchone()
        phishing_from_events = suspicious_result['suspicious_events'] if suspicious_result else 0

        total_phishing_blocked = phishing_from_reports + phishing_from_events

        # REAL DATA: Threats detected (from security_events with non-safe verdicts)
        cursor.execute("""
            SELECT COUNT(*) as threats_detected 
            FROM security_events 
            WHERE user_id = %s AND verdict != 'safe'
        """, (user_id,))
        threats_result = cursor.fetchone()
        threats_detected = threats_result['threats_detected'] if threats_result else 0

        # REAL DATA: Safe sessions (websites checked that were safe + website visits)
        cursor.execute("""
            SELECT COUNT(*) as safe_checks 
            FROM security_events 
            WHERE user_id = %s AND verdict = 'safe'
        """, (user_id,))
        safe_checks_result = cursor.fetchone()
        safe_checks = safe_checks_result['safe_checks'] if safe_checks_result else 0

        # Also count website visits as safe sessions
        cursor.execute("""
            SELECT COUNT(*) as website_visits 
            FROM user_activities 
            WHERE user_id = %s AND activity_type = 'website_visit'
        """, (user_id,))
        visits_result = cursor.fetchone()
        website_visits = visits_result['website_visits'] if visits_result else 0

        total_safe_sessions = safe_checks + website_visits

        # Get username
        cursor.execute("SELECT username FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        
        # Update user_activity_stats table with the real calculated values
        cursor.execute("""
            INSERT INTO user_activity_stats (user_id, keystrokes_protected, websites_checked, phishing_blocked, threats_detected)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
                keystrokes_protected = VALUES(keystrokes_protected),
                websites_checked = VALUES(websites_checked),
                phishing_blocked = VALUES(phishing_blocked),
                threats_detected = VALUES(threats_detected)
        """, (user_id, total_keystrokes, total_safe_sessions, total_phishing_blocked, threats_detected))
        
        conn.commit()
        
        dashboard_stats = {
            'username': user['username'] if user else 'User',
            'keystrokesProtected': total_keystrokes,
            'phishingAttemptsBlocked': total_phishing_blocked,
            'threatsDetected': threats_detected,
            'safeSessions': total_safe_sessions,
            'encryptionStrength': 95
        }
        
        print(f"📊 REAL Dashboard stats for user {user_id}: {dashboard_stats}")
        print(f"   - Keystrokes: {total_keystrokes} from user_activities")
        print(f"   - Phishing Blocked: {total_phishing_blocked} (reports: {phishing_from_reports}, events: {phishing_from_events})")
        print(f"   - Threats: {threats_detected} from security_events")
        print(f"   - Safe Sessions: {total_safe_sessions} (checks: {safe_checks}, visits: {website_visits})")
        
        return jsonify({'stats': dashboard_stats}), 200
        
    except mysql.connector.Error as err:
        logging.error(f"MySQL Error fetching user stats: {err}")
        return jsonify({'message': 'Failed to fetch stats'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/api/websites', methods=['GET'])
@app.route('/websites', methods=['GET'])
@token_required
def get_user_websites():
    """Get user's website security status for dashboard"""
    user_id = request.user_id
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor(dictionary=True)
    try:
        # Get websites data from websites table
        cursor.execute("""
            SELECT 
                domain,
                keystrokes_protected,
                phishing_attempts_blocked,
                last_visited
            FROM websites 
            WHERE user_id = %s
            ORDER BY last_visited DESC
            LIMIT 10
        """, (user_id,))
        websites = cursor.fetchall()
        
        print(f"🔍 DEBUG: Found {len(websites)} websites for user {user_id}")
        
        # Format the response to match Dashboard expectations
        formatted_websites = []
        for site in websites:
            print(f"🔍 DEBUG Website: {site['domain']} - Keystrokes: {site['keystrokes_protected']}")
            
            # Calculate risk level based on phishing attempts and activity
            risk_level = 5  # Default safe
            security_status = 'safe'
            
            if site['phishing_attempts_blocked'] and site['phishing_attempts_blocked'] > 0:
                risk_level = 80
                security_status = 'danger'
            elif site['keystrokes_protected'] and site['keystrokes_protected'] > 10:
                risk_level = min(20 + (site['keystrokes_protected'] // 10), 50)
                security_status = 'warning' if risk_level > 20 else 'safe'
            
            formatted_websites.append({
                'domain': site['domain'],
                'securityStatus': security_status,
                'lastVisited': site['last_visited'].strftime('%Y-%m-%d %H:%M:%S') if site['last_visited'] else 'Unknown',
                'keystrokesProtected': site['keystrokes_protected'] or 0,
                'riskLevel': risk_level
            })
        
        print(f"📊 DEBUG: Returning {len(formatted_websites)} formatted websites")
        
        return jsonify({'websites': formatted_websites}), 200
        
    except mysql.connector.Error as err:
        logging.error(f"MySQL Error fetching user websites: {err}")
        return jsonify({'message': 'Failed to fetch websites'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/api/events', methods=['GET'])
@app.route('/events', methods=['GET'])
@token_required
def get_user_events():
    """Get user's security events for dashboard"""
    user_id = request.user_id
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor(dictionary=True)
    try:
        # Get both phishing reports and security events
        cursor.execute("""
            (SELECT 
                id, subject as url, reported_type as type, reason, created_at,
                'report' as source
             FROM phishing_reports 
             WHERE reporter = %s)
            UNION ALL
            (SELECT 
                id, domain as url, event_type as type, details as reason, created_at,
                'security_scan' as source
             FROM security_events 
             WHERE user_id = %s)
            ORDER BY created_at DESC 
            LIMIT 20
        """, (user_id, user_id))
        
        events = cursor.fetchall()
        
        formatted_events = []
        for event in events:
            formatted_events.append({
                'id': event['id'],
                'url': event['url'],
                'type': event['type'] or 'security_scan',
                'reason': event['reason'] or 'Security scan performed',
                'reported_at': event['created_at'].strftime('%Y-%m-%d %H:%M:%S') if event['created_at'] else 'Unknown'
            })
        
        return jsonify({'events': formatted_events}), 200
        
    except mysql.connector.Error as err:
        logging.error(f"MySQL Error fetching user events: {err}")
        return jsonify({'message': 'Failed to fetch events'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/api/dashboard-events', methods=['GET'])
@token_required
def get_dashboard_events():
    """Get user activities for dashboard events"""
    user_id = request.user_id
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor(dictionary=True)
    try:
        # Get recent activities
        cursor.execute("""
            SELECT activity_type, domain, details, created_at
            FROM user_activities 
            WHERE user_id = %s 
            ORDER BY created_at DESC 
            LIMIT 10
        """, (user_id,))
        activities = cursor.fetchall()
        
        # Also get phishing reports as events
        cursor.execute("""
            SELECT subject as domain, reason, reported_type, created_at
            FROM phishing_reports 
            WHERE reporter = %s 
            ORDER BY created_at DESC 
            LIMIT 10
        """, (user_id,))
        reports = cursor.fetchall()
        
        # Combine and format events
        formatted_events = []
        
        # Add activities
        for activity in activities:
            formatted_events.append({
                'id': len(formatted_events) + 1,
                'type': activity['activity_type'],
                'severity': 'medium',  # Default severity
                'message': f"Activity: {activity['activity_type']}",
                'website': activity['domain'] or 'Unknown',
                'timestamp': activity['created_at'].isoformat() if activity['created_at'] else '',
                'resolved': False
            })
        
        # Add phishing reports
        for report in reports:
            formatted_events.append({
                'id': len(formatted_events) + 1,
                'type': 'phishing',
                'severity': 'high',
                'message': f"Reported: {report['reason']}",
                'website': report['domain'],
                'timestamp': report['created_at'].isoformat() if report['created_at'] else '',
                'resolved': False
            })
        
        return jsonify({'events': formatted_events}), 200
        
    except mysql.connector.Error as err:
        logging.error(f"MySQL Error fetching dashboard events: {err}")
        return jsonify({'message': 'Failed to fetch events'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

# --- TRACKING ENDPOINTS FOR EXTENSION INTEGRATION ---

@app.route('/api/track_website_visit', methods=['POST'])
@token_required
def track_website_visit():
    """Track when user visits/checks a website - IMPROVED VERSION"""
    data = request.get_json()
    user_id = request.user_id
    url = data.get('url')
    action = data.get('action', 'visit')
    
    if not url:
        return jsonify({'message': 'URL is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor()
    try:
        domain = urlparse(url).netloc
        
        # Track as website visit activity
        cursor.execute("""
            INSERT INTO user_activities (user_id, activity_type, domain, details)
            VALUES (%s, %s, %s, %s)
        """, (user_id, 'website_visit', domain, json.dumps({'url': url, 'action': action})))
        
        # Update websites table
        cursor.execute("""
            INSERT INTO websites (user_id, domain, last_visited)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            last_visited = VALUES(last_visited)
        """, (user_id, domain, datetime.now()))
        
        conn.commit()
        logging.info(f"Tracked website {action}: {domain} by user {user_id}")
        return jsonify({'success': True}), 200
        
    except Exception as e:
        logging.error(f"Error tracking website visit: {e}")
        return jsonify({'message': 'Tracking failed'}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/api/track_security_event', methods=['POST'])
@token_required
def track_security_event():
    """Track security scan results - IMPROVED VERSION"""
    data = request.get_json()
    user_id = request.user_id
    url = data.get('url')
    verdict = data.get('verdict', 'unknown')
    reasons = data.get('reasons', '')
    event_type = data.get('event_type', 'security_scan')
    
    if not url:
        return jsonify({'message': 'URL is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor()
    try:
        domain = urlparse(url).netloc
        
        # Track the security event
        cursor.execute("""
            INSERT INTO security_events (user_id, domain, event_type, verdict, details)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, domain, event_type, verdict, reasons))
        
        # Update websites table with phishing attempts if suspicious
        if 'suspicious' in verdict.lower() or verdict != 'safe':
            cursor.execute("""
                INSERT INTO websites (user_id, domain, phishing_attempts_blocked, last_visited)
                VALUES (%s, %s, 1, %s)
                ON DUPLICATE KEY UPDATE 
                phishing_attempts_blocked = COALESCE(phishing_attempts_blocked, 0) + 1,
                last_visited = VALUES(last_visited)
            """, (user_id, domain, datetime.now()))
            
            print(f"🚨 Tracked suspicious event for {domain} - verdict: {verdict}")
        
        conn.commit()
        logging.info(f"Tracked security event: {verdict} for {domain} by user {user_id}")
        return jsonify({'success': True}), 200
        
    except Exception as e:
        logging.error(f"Error tracking security event: {e}")
        return jsonify({'message': 'Event tracking failed'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
            
@app.route('/api/track-keystrokes', methods=['POST', 'OPTIONS'])
def track_keystrokes():
    """Track keystrokes for a user on a specific domain"""
    if request.method == 'OPTIONS':
        response = make_response('', 200)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response

    try:
        # Get token from header for user identification
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"success": False, "message": "Missing or invalid token"}), 401
            
        token = auth_header.split(" ")[1]
        
        # Decode token to get user_id
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = data['user_id']
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Invalid token"}), 401

        data = request.get_json()
        count = data.get('count', 0)
        domain = data.get('domain', '')
        timestamp = data.get('timestamp')

        print(f"🎯 DEBUG TRACK-KEYSTROKES START:")
        print(f"   User: {user_id}, Count: {count}, Domain: {domain}")

        if not user_id or count <= 0:
            print(f"❌ DEBUG: Invalid data - user_id: {user_id}, count: {count}")
            return jsonify({"success": False, "message": "Invalid data"}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Track as user activity
        cursor.execute("""
            INSERT INTO user_activities (user_id, activity_type, domain, details)
            VALUES (%s, %s, %s, %s)
        """, (user_id, 'keystrokes_protected', domain, json.dumps({
            'count': count,
            'timestamp': timestamp or datetime.now().isoformat()
        })))
        
        # 2. Update user_activity_stats table - INCREMENT the count
        cursor.execute("""
            INSERT INTO user_activity_stats (user_id, keystrokes_protected, websites_checked, phishing_blocked, threats_detected)
            VALUES (%s, %s, 0, 0, 0)
            ON DUPLICATE KEY UPDATE 
                keystrokes_protected = keystrokes_protected + %s
        """, (user_id, count, count))
        
        # 3. Update websites table with keystrokes protected - INCREMENT the count
        cursor.execute("""
            INSERT INTO websites (user_id, domain, keystrokes_protected, last_visited)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
                keystrokes_protected = keystrokes_protected + %s,
                last_visited = VALUES(last_visited)
        """, (user_id, domain, count, datetime.now(), count))
        
        conn.commit()
        print(f"✅ DEBUG: Tracked {count} keystrokes for user {user_id} on {domain}")

        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": f"Tracked {count} keystrokes",
            "count": count
        })

    except Exception as e:
        app.logger.error(f"Error tracking keystrokes: {str(e)}")
        print(f"❌ ERROR in track-keystrokes: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/track-activity', methods=['POST'])
@token_required
def track_user_activity():
    """Track user activities for dashboard"""
    user_id = request.user_id
    data = request.get_json()
    
    activity_type = data.get('activity_type')
    domain = data.get('domain')
    details = data.get('details', {})
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 503

    cursor = conn.cursor()
    try:
        # Insert activity
        cursor.execute("""
            INSERT INTO user_activities (user_id, activity_type, domain, details)
            VALUES (%s, %s, %s, %s)
        """, (user_id, activity_type, domain, json.dumps(details)))
        
        # Update stats based on activity type
        if activity_type == 'website_check':
            cursor.execute("""
                INSERT INTO user_activity_stats (user_id, websites_checked) 
                VALUES (%s, 1)
                ON DUPLICATE KEY UPDATE websites_checked = websites_checked + 1
            """, (user_id,))
        elif activity_type == 'website_reported':
            cursor.execute("""
                INSERT INTO user_activity_stats (user_id, phishing_blocked) 
                VALUES (%s, 1)
                ON DUPLICATE KEY UPDATE phishing_blocked = phishing_blocked + 1
            """, (user_id,))
            
        conn.commit()
        return jsonify({'success': True}), 200
        
    except mysql.connector.Error as err:
        logging.error(f"MySQL Error tracking activity: {err}")
        return jsonify({'message': 'Failed to track activity'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

# --- PHISHING ANALYSIS ENDPOINTS ---

@app.route('/check_url', methods=['POST'])
def check_url():
    """Check URL for phishing"""
    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({'verdict': 'suspicious', 'reasons': ['Empty URL provided']}), 400

    # Use the comprehensive analysis function
    verdict, reasons = analyze_url(url)

    return jsonify({
        'verdict': verdict, 
        'reasons': reasons.split('; ') if reasons else ['URL appears safe']
    }), 200

@app.route('/api/analyze_url', methods=['POST'])
@token_required
def analyze_url_api():
    """Comprehensive URL analysis with user tracking"""
    user_id = request.user_id
    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Perform comprehensive analysis
    verdict, reasons = analyze_url(url)

    # Track the analysis in database
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO phishing_checks (user_id, input_text, input_type, verdict, reasons, checked_at) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, url, "url", verdict, reasons, datetime.utcnow().isoformat()))
            conn.commit()
            
            # Also track as user activity
            cursor.execute("""
                INSERT INTO user_activities (user_id, activity_type, domain, details)
                VALUES (%s, %s, %s, %s)
            """, (user_id, 'website_check', urlparse(url).netloc, 
                  json.dumps({'verdict': verdict, 'reasons': reasons})))
            conn.commit()
            
        except mysql.connector.Error as err:
            logging.error(f"Error saving phishing check: {err}")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return jsonify({
        'url': url, 
        'verdict': verdict, 
        'reasons': reasons.split('; ') if reasons else ['URL appears safe']
    }), 200

@app.route('/analyze', methods=['POST'])
def analyze():
    """Simple phishing analysis endpoint for form submissions"""
    raw = request.form.get('input', '')
    verdict, reasons = analyze_url(raw)

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            # For non-authenticated checks, use user_id 1 (test user)
            cursor.execute("""
                INSERT INTO phishing_checks (user_id, input_text, input_type, verdict, reasons, checked_at) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (1, raw, "url", verdict, reasons, datetime.utcnow().isoformat()))
            conn.commit()
        except mysql.connector.Error as err:
            logging.error(f"Error saving phishing check: {err}")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return jsonify({'verdict': verdict, 'reasons': reasons})

@app.route('/report_api', methods=['POST'])
def report_api():
    """Report API endpoint for extension reports"""
    data = request.get_json()
    url = data.get('url', '')

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            # For extension reports, use user_id 1
            cursor.execute("""
                INSERT INTO phishing_reports (reporter, subject, reason, reported_type, created_at) 
                VALUES (%s, %s, %s, %s, %s)
            """, (1, url, "Reported via extension", "url", datetime.utcnow().isoformat()))
            conn.commit()
            return jsonify({'message': 'Report saved successfully!'})
        except mysql.connector.Error as err:
            logging.error(f"Error saving report: {err}")
            return jsonify({'message': 'Failed to save report'}), 500
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
    
    return jsonify({'message': 'Database connection failed'}), 500

# --- ADMIN PANEL ROUTE ---
@app.route('/admin/reports')
def admin_reports():
    """Admin panel to view reports and checks"""
    conn = get_db_connection()
    if not conn:
        return "Database connection failed", 500

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM phishing_reports ORDER BY created_at DESC")
        reports = cursor.fetchall()
        
        cursor.execute("SELECT * FROM phishing_checks ORDER BY checked_at DESC")
        checks = cursor.fetchall()
        
        return render_template('admin_reports.html', reports=reports, checks=checks)
        
    except mysql.connector.Error as err:
        logging.error(f"Error loading admin reports: {err}")
        return f"Error loading reports: {err}", 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# --- EXISTING ROUTES ---

@app.route('/', methods=['GET'])
def home():
    """Simple health check endpoint."""
    return jsonify({'message': 'KeyShield API is running!'}), 200

@app.route('/report_keystroke_data', methods=['POST'])
@token_required
def report_keystroke_data():
    """Endpoint for receiving keystroke data for model training/updates."""
    user_id = request.user_id
    data = request.get_json()
    timings = data.get('keystrokeTimings', [])
    
    if timings:
        logging.info(f"Received {len(timings)} keystroke events for training from user {user_id}.")
        return jsonify({'success': True, 'message': 'Keystroke data received for processing.'}), 200
    
    return jsonify({'success': False, 'message': 'No data provided.'}), 400

# --- Run the App ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=DEBUG)