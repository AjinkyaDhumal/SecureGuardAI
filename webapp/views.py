"""Views module - XSS vulnerability (RETRY CASE).

This XSS vulnerability is more complex and may require retry attempts.
The fix needs to handle HTML escaping properly in a template context.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/search')
def search():
    """Search endpoint - VULNERABLE to XSS."""
    query = request.args.get('q', '')

    html = f"""
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results for: {query}</h1>
        <p>You searched for: {query}</p>
        <form action="/search" method="get">
            <input type="text" name="q" value="{query}">
            <button type="submit">Search</button>
        </form>
    </body>
    </html>
    """

    return html


@app.route('/profile/<username>')
def profile(username):
    """Profile page - VULNERABLE to XSS via URL parameter."""
    return f"<h1>Welcome, {username}!</h1><p>This is your profile page.</p>"


@app.route('/comment', methods=['POST'])
def add_comment():
    """Add comment - VULNERABLE to stored XSS."""
    comment = request.form.get('comment', '')

    response = f"""
    <div class="comment">
        <p>{comment}</p>
        <small>Posted just now</small>
    </div>
    """

    return response


if __name__ == '__main__':
    app.run(debug=True)
