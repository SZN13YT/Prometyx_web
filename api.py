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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            action VARCHAR(255) NOT NULL,
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
        """
    ]

    for q in tables:
        cursor.execute(q)

    conn.commit()
    conn.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
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
if __name__ == '__main__':
    conn = mysql.connector.connect(
        host="localhost",
        user=os.getenv("DB_ROOTN"),
        password=os.getenv("DB_ROOT")
    )
    cursor = conn.cursor()
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