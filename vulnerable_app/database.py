"""Database module with SQL injection vulnerability for testing."""

import sqlite3


def get_user(user_id):
    """Get user by ID - VULNERABLE to SQL injection."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result


def get_user_by_name(name):
    """Get user by name - VULNERABLE to SQL injection."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result


if __name__ == "__main__":
    # Test the functions
    print(get_user(1))
    print(get_user_by_name("Alice"))
