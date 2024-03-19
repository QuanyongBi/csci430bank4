import sqlite3

def init_db():
    conn = sqlite3.connect('banking.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    balance REAL DEFAULT 0
                )''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
