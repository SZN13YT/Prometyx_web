"""
pip install flask bcrypt pyjwt flask_limiter dotenv mysql-connector-python
Vue a frontend hez
https://dev.mysql.com/downloads/file/?id=544662
"""
from flask import Flask, request, jsonify, make_response
import os, mysql.connector, bcrypt, uuid, jwt, datetime, re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from dotenv import load_dotenv

app = Flask(__name__)
limiter = Limiter(key_func=get_remote_address)



load_dotenv()
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
if not app.config['SECRET_KEY']:
    raise ValueError("A SECRET_KEY környezeti változó nincs megadva!")

secret_key = app.config["SECRET_KEY"]

def get_db_connection():
    conn = mysql.connector.connect(
        host="localhost",
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME")
    )
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    tables = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            action VARCHAR(255) NOT NULL,
            admin_name VARCHAR(255) DEFAULT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS blacklist (
            id INT AUTO_INCREMENT PRIMARY KEY,
            token VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS special_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            token VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action VARCHAR(255) NOT NULL
        )"""
    ]

    for q in tables:
        cursor.execute(q)

    cursor.execute("INSERT INTO users (username, password, email, admin) VALUES (%s, %s, %s, %s)",
                   ('admin', bcrypt.hashpw(os.getenv('DB_ADMINPASS').encode('utf-8'), bcrypt.gensalt()), os.getenv('DB_ADMINEMAIL'), True))
    conn.commit()
    conn.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']    
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, secret_key, algorithms=["HS256"])
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE id = %s", (data['user_id'],))
            current_user = cursor.fetchone()
            conn.close()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return jsonify({'message': 'Missing fields!'}), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'message': 'Invalid email format!'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, password, email) VALUES (%s, %s, %s)", (username, hashed_password, email))
        user_id = cursor.lastrowid
        cursor.execute("INSERT INTO logs (user_id, action) VALUES (%s, 'User registered')", (user_id,))
        conn.commit()
    except mysql.connector.Error as err:
        conn.rollback()
        if err.errno == mysql.connector.errorcode.ER_DUP_ENTRY:
            return jsonify({'message': "Ez az email cím vagy felhasználónév már foglalt!"}), 500
        return jsonify({'message': f"Database error: {err}"}), 500
    finally:
        cursor.close()
        conn.close()

    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/admin_register', methods=['POST'])
@token_required
def admin_register(current_user):
    if not current_user['admin']:
        return jsonify({'message': 'Admin privileges required!'}), 403
    data = request.get_json()
    username = data.get('username')
    current_password = data.get('current_password')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (current_user['id'],))
    admin_user = cursor.fetchone()

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    if not bcrypt.checkpw(current_password.encode('utf-8'), admin_user['password'].encode('utf-8')):
        return jsonify({'message': 'Wrong password!'}), 401
    if user['admin']:
        return jsonify({'message': 'User is already an admin!'}), 400
    cursor.execute("UPDATE users SET admin = TRUE WHERE id = %s", (user['id'],))
    cursor.execute("INSERT INTO logs (user_id, action) VALUES (%s, 'User promoted to admin')", (user['id'],))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'User promoted to admin successfully!'}), 200

@app.route("/login", methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username and not email or not password:
        return jsonify({'message': 'Missing fields!'}), 400
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    if not username:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    else:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
       return jsonify({'message': 'User not found!'}), 404
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        cursor.execute("INSERT INTO logs (user_id, action) VALUES (%s, 'Failed login attempt')", (user['id'],))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Wrong password!'}), 401

    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'admin': user['admin']
    }, secret_key, algorithm="HS256")

    refresh_token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
        'admin': user['admin']
    }, secret_key, algorithm="HS256")

    cursor.execute("INSERT INTO tokens (user_id, token) VALUES (%s, %s)", (user['id'], token))
    cursor.execute("INSERT INTO special_tokens (token, action) VALUES (%s, 'Refresh Token')", (refresh_token,))
    cursor.execute("INSERT INTO logs (user_id, action) VALUES (%s, 'User logged in')", (user['id'],))
    
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'token': token, 'refresh_token' :refresh_token, 'message': 'Login was success.'}), 200


@app.route("/logout", methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers.get('Authorization')
    refresh_token = request.headers.get('refresh_token')

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("INSERT INTO blacklist (token) VALUES (%s)", (token,))
    cursor.execute("INSERT INTO blacklist (token) VALUES (%s)", (refresh_token,))

    cursor.execute("DELETE FROM tokens WHERE token = %s", (token,))
    cursor.execute("INSERT INTO logs (user_id, action) VALUES (%s, 'User logged out')", (current_user['id'],))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({'message': 'Logged out successfully!'}), 200

@app.route("/change-password", methods=['PUT'])
@token_required
def change_password(current_user):
    data = request.get_json()
    new_password = data.get('new_password')
    current_password = data.get('current_password')

    if not new_password or not current_password:
        return jsonify({'message': 'Missing fields!'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM users WHERE id = %s", (current_user['id'],))
    user = cursor.fetchone()

    if not bcrypt.checkpw(current_password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Wrong password!'}), 401
    if bcrypt.checkpw(new_password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'New password cannot be the same as the old one!'}), 400
    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, current_user['id']))
    cursor.execute("INSERT INTO logs (user_id, action) VALUES (%s, 'Password changed')", (current_user['id'],))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({'message': 'Password changed successfully!'}), 200

@app.route("/refresh-token", methods=['POST'])
@token_required
def refresh_token(current_user):
    refresh_token = request.headers.get('refresh_token')
    
    if not refresh_token:
        return jsonify({'message': 'Refresh token is missing!'}), 401

    try:
        data = jwt.decode(refresh_token, secret_key, algorithms=["HS256"])
        if data['user_id'] != current_user['id']:
            return jsonify({'message': 'Invalid refresh token!'}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token has expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token!'}), 401

    new_token = jwt.encode({
        'user_id': current_user['id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'admin': current_user['admin']
    }, secret_key, algorithm="HS256")

    return jsonify({'token': new_token, 'message': 'Token refreshed successfully!'}), 200

@app.route("/change-password", methods=['PUT'])
@token_required
def change_password(current_user):
    data = request.get_json()
    new_password = data.get('n_pass')
    current_password = data.get('c_pass')

    if not new_password or not current_password:
        return jsonify({'message': 'Missing fields!'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM users WHERE id = %s", (current_user['id'],))
    user = cursor.fetchone()

    if not bcrypt.checkpw(current_password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'Wrong password!'}), 401
    if bcrypt.checkpw(new_password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'message': 'New password cannot be the same as the old one!'}), 400
    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, current_user['id']))
    cursor.execute("INSERT INTO logs (user_id, action) VALUES (%s, 'Password changed')", (current_user['id'],))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({'message': 'Password changed successfully!'}), 200

@app.route("/forgotten-password", methods=['POST'])
def forgotten_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required!'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'message': 'User not found!'}), 404

    reset_token = str(uuid.uuid4(expires=datetime.datetime.utcnow() + datetime.timedelta(hours=1)))
    cursor.execute("DELETE FROM special_tokens WHERE action = 'Password Reset' AND token IN (SELECT token FROM special_tokens WHERE user_id = %s)", (user['id'],))
    cursor.execute("INSERT INTO special_tokens (token, action) VALUES (%s, 'Password Reset')", (reset_token,))

    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({'message': 'Password reset token generated!', 'reset_token': reset_token}), 200

@app.route("/reset-password", methods=['POST'])
def reset_password():
    data = request.get_json()
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')

    if not reset_token or not new_password:
        return jsonify({'message': 'Missing fields!'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM special_tokens WHERE token = %s AND action = 'Password Reset'", (reset_token,))
    token_data = cursor.fetchone()

    if not token_data:
        return jsonify({'message': 'Invalid or expired reset token!'}), 401

    cursor.execute("SELECT * FROM users WHERE id = %s", (token_data['user_id'],))
    user = cursor.fetchone()

    if not user:
        return jsonify({'message': 'User not found!'}), 404

    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, user['id']))
    cursor.execute("INSERT INTO logs (user_id, action) VALUES (%s, 'Password reset')", (user['id'],))
    
    cursor.execute("DELETE FROM special_tokens WHERE token = %s", (reset_token,))
    
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': 'Password reset successfully!'}), 200

if __name__ == '__main__':
    conn = mysql.connector.connect(
        host="localhost",
        user=os.getenv("DB_ROOTN"),
        password=os.getenv("DB_ROOT")
    )
    cursor = conn.cursor()
    cursor.execute(f"DROP DATABASE IF EXISTS {os.getenv('DB_NAME')}")
    cursor.execute(f"SHOW DATABASES LIKE '{os.getenv('DB_NAME')}'")
    if not cursor.fetchone():
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {os.getenv('DB_NAME')}")
        cursor.execute(f"CREATE USER IF NOT EXISTS '{os.getenv('DB_USER')}'@'localhost' IDENTIFIED BY '{os.getenv('DB_PASS')}'")
        cursor.execute(f"GRANT ALL PRIVILEGES ON {os.getenv('DB_NAME')}.* TO '{os.getenv('DB_USER')}'@'localhost'")
        cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        conn.close()
        init_db()
    app.run(debug=True, port=5001)