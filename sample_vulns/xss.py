"""
Sample vulnerable file: Cross-Site Scripting (XSS)

This file contains intentional XSS vulnerabilities for testing.
DO NOT use this code in production!
"""

from flask import Flask, request, render_template_string


app = Flask(__name__)


@app.route('/greet_vulnerable')
def greet_vulnerable():
    """
    VULNERABLE: Reflected XSS via direct output.

    User input is directly embedded in HTML without escaping.
    """
    name = request.args.get('name', 'Guest')

    # VULNERABLE: Direct embedding without escaping
    return f"<h1>Hello, {name}!</h1>"


@app.route('/search_vulnerable')
def search_vulnerable():
    """
    VULNERABLE: XSS via template string.

    User input is rendered in a template without proper escaping.
    """
    query = request.args.get('q', '')

    # VULNERABLE: User input in template without escaping
    template = f"<p>Search results for: {query}</p>"
    return render_template_string(template)


@app.route('/profile_vulnerable')
def profile_vulnerable():
    """
    VULNERABLE: Stored XSS simulation.

    User-provided bio is displayed without sanitization.
    """
    bio = request.args.get('bio', '')

    # VULNERABLE: Unsanitized user content
    html = f"""
    <div class="profile">
        <h2>User Profile</h2>
        <div class="bio">{bio}</div>
    </div>
    """
    return html


# ============ SAFE VERSIONS FOR COMPARISON ============

import html as html_module


@app.route('/greet_safe')
def greet_safe():
    """
    SAFE: HTML escaped output.
    """
    name = request.args.get('name', 'Guest')

    # SAFE: HTML escaping
    safe_name = html_module.escape(name)
    return f"<h1>Hello, {safe_name}!</h1>"


@app.route('/search_safe')
def search_safe():
    """
    SAFE: Using Jinja2 auto-escaping.
    """
    query = request.args.get('q', '')

    # SAFE: Jinja2 with auto-escaping (default in Flask)
    return render_template_string(
        "<p>Search results for: {{ query }}</p>",
        query=query
    )
