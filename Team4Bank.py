from flask import Flask, request, redirect, url_for, make_response, jsonify, session
import sqlite3
import bcrypt

app = Flask(__name__)
hash = ""
app.secret_key = "thisIsSupposeToBeSomethingRandomButLetsDoItForNow"

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
        bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(bytes, salt)
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (user, hash))
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
    user_record = c.fetchone()
    conn.close()
    
    if user_record:
        stored_password_hash = user_record['password']
        password_bytes = password.encode('utf-8')
        pw_match = bcrypt.checkpw(password_bytes, stored_password_hash)
        if pw_match:
            # Assuming you meant to use the username as the key for the session
            session['username'] = user
            return "Logged in successfully", 200
        else:
            return "Invalid username or password", 401
    else:
        return "Invalid username or password", 401
    
    
@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)  # Clear the logged-in user's session
    return "Logged out successfully", 200

@app.route('/manage', methods=['GET'])
def manage():
    # Ensure the user is logged in
    username = session.get('username')
    if not username:
        return "Unauthorized", 401
    action = request.args.get('action')
    amount = request.args.get('amount', type=float, default=0)  # Convert amount to float; default to 0

    conn = get_db_connection()
    c = conn.cursor()
    # Fetch the user record from the database to get the current balance
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user_record = c.fetchone()

    if not user_record:
        conn.close()
        return "User not found", 404
    
    if action == 'deposit':
        # TODO: Check the input variable to avoid injection
        new_balance = user_record['balance'] + amount
        c.execute('UPDATE users SET balance = ? WHERE username = ?', (new_balance, username))
        conn.commit()
        conn.close()
        return "deposit successfully", 200
    elif action == 'withdraw':
        if user_record['balance'] >= amount:
            new_balance = user_record['balance'] - amount
            c.execute('UPDATE users SET balance = ? WHERE username = ?', (new_balance, username))
            print(user_record['balance'])
            conn.commit()
            conn.close()
            return "withdraw successfully", 200
        else:
            conn.close()
            return "Insufficient funds", 400
    elif action == 'balance':
        conn.close()
        return jsonify({"balance": user_record['balance']}), 200
    elif action == 'close':
        c.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        session.pop('username', None)
        return "close successfully", 200
    else:
        conn.close()
        return "Invalid action", 400
    
    
@app.route('/db_contents', methods=['GET'])
def db_contents():
    # Optional: Add authentication check here to secure this endpoint

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM users')
    users = c.fetchall()
    conn.close()

    # Generate HTML content
    html_content = '<h1>Database Contents: Users Table</h1>'
    html_content += '<table border="1">'
    html_content += '<tr><th>ID</th><th>Username</th><th>Password (hashed)</th><th>Balance</th></tr>'
    for user in users:
        html_content += f'<tr><td>{user["id"]}</td><td>{user["username"]}</td><td>{user["password"]}</td><td>{user["balance"]}</td></tr>'
    html_content += '</table>'

    return html_content




if __name__ == '__main__':
    app.run(debug=True)