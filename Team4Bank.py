from flask import Flask, request, redirect, url_for, make_response, jsonify
import sqlite3

app = Flask(__name__)
app.secret_key = "thisIsSupposeToBeSomethingRandomButLetsDoItForNow"
sessions = {}

def get_db_connection():
    conn = sqlite3.connect('banking.db')
    conn.row_factory = sqlite3.Row  # This enables column access by name: row['column_name']
    return conn

@app.route('/register', methods=['GET'])
def register():
    user = request.args.get('user')
    password = request.args.get('pass')
    conn = get_db_connection()
    c = conn.cursor()
    if not user or not password:
        return jsonify({"error": "Both user and pass parameters are required"}), 400
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (user, password))
        conn.commit()
    except sqlite3.IntegrityError:
        return "User already exists", 400
    finally:
        conn.close()
    return "User registered successfully", 200


@app.route('/login', methods=['GET'])
def login():
    user = request.args.get('user')
    password = request.args.get('pass')
    if not user or not password:
        return "Missing username or password", 400
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (user,))
    user = c.fetchone()
    conn.close()
    if user and user['password'] == password:  # Hashing Needed
        sessions['user'] = user
        return "Logged in successfully", 200
    else:
        return "Invalid username or password", 401.

@app.route('/logout', methods=['GET'])
def logout():
    sessions.pop('user', None)
    return "Logged out successfully", 200

if __name__ == '__main__':
    app.run(debug=True)
