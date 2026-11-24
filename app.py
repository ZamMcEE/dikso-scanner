from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)
app.secret_key = 'your_unique_secret_key_here'

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# HOME ROUTE: Shows the website/dashboard to EVERYONE first
@app.route('/')
def home():
    return render_template('template.html')

# User Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('register.html', error="All fields are required.")
            
        hashed_password = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="Username already exists.")
            
    return render_template('register.html')

# User Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error="Invalid username or password.")
            
    return render_template('login.html')

# User Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Scanner API Endpoint (Requires Login to run actual scans)
@app.route('/api/scan', methods=['POST'])
def run_scan():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Authentication required! Please log in to run scans."}), 401
        
    data = request.json
    target_url = data.get('url')
    
    if not target_url:
        return jsonify({"status": "error", "message": "No target URL provided."}), 400
        
    logs = [f"[*] Starting vulnerability scan against: {target_url}"]
    
    try:
        payload = "<script>alert(1)</script>"
        params = {"input": payload}
        res = requests.get(target_url, params=params, timeout=5)
        
        if payload in res.text:
            logs.append(f"[!] Vulnerability Found (Reflected XSS): {target_url}")
        else:
            logs.append(f"[-] No vulnerability reflected for payload: {payload}")
            
    except requests.exceptions.RequestException as e:
        logs.append(f"[x] Connection error: {str(e)}")
        
    return jsonify({"status": "success", "logs": logs})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)