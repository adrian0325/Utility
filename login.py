import sqlite3
import hashlib

def verify_login(username, password):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    hashed = hashlib.sha256(password.encode()).hexdigest()

    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed))
    result = cursor.fetchone()

    connection.close()

    if result:
        return True
    return False
