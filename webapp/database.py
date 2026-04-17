"""Database module - SQL Injection vulnerability (PASS CASE).

This is a simple, clear SQL injection that should be fixed on first attempt.
"""

import sqlite3


def get_user_by_id(user_id):
    """Get user by ID - VULNERABLE to SQL injection."""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result


def create_user(name, email):
    """Create a new user - safe implementation."""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        (name, email)
    )

    conn.commit()
    conn.close()
