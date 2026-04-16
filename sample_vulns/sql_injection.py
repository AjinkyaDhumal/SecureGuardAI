"""
Sample vulnerable file: SQL Injection

This file contains intentional SQL injection vulnerabilities for testing.
DO NOT use this code in production!
"""

import sqlite3


def get_user_vulnerable(user_id):
    """
    VULNERABLE: SQL injection via string formatting.
    
    This function is vulnerable because it directly embeds user input
    into the SQL query using f-string formatting.
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # VULNERABLE: String formatting in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()


def get_user_by_name_vulnerable(username):
    """
    VULNERABLE: SQL injection via string concatenation.
    
    This function is vulnerable because it concatenates user input
    directly into the SQL query.
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # VULNERABLE: String concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    return cursor.fetchone()


def search_users_vulnerable(search_term):
    """
    VULNERABLE: SQL injection via % formatting.
    
    This function is vulnerable because it uses % formatting
    to embed user input into the SQL query.
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # VULNERABLE: % formatting in SQL query
    query = "SELECT * FROM users WHERE name LIKE '%%%s%%'" % search_term
    cursor.execute(query)
    
    return cursor.fetchall()


# ============ SAFE VERSIONS FOR COMPARISON ============

def get_user_safe(user_id):
    """
    SAFE: Parameterized query.
    
    This function is safe because it uses parameterized queries
    where user input is passed as a separate parameter.
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    return cursor.fetchone()


def get_user_by_name_safe(username):
    """
    SAFE: Parameterized query with named parameter.
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # SAFE: Named parameter
    query = "SELECT * FROM users WHERE username = :username"
    cursor.execute(query, {"username": username})
    
    return cursor.fetchone()
