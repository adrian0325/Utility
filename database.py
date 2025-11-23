import sqlite3
import hashlib

def create_database():
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    """)

    # Create default admin user
    default_username = "admin"
    default_password = "admin123"
    hashed_pw = hashlib.sha256(default_password.encode()).hexdigest()

    # Insert only if not existing
    cursor.execute("SELECT * FROM users WHERE username=?", (default_username,))
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO users VALUES (?, ?)", (default_username, hashed_pw))

    connection.commit()
    connection.close()
    print("Database ready. Default login = admin / admin123")

if __name__ == "__main__":
    create_database()
