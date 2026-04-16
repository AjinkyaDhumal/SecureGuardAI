"""Request handlers module - XSS vulnerability."""

from flask import Flask, request, Markup

app = Flask(__name__)


def render_user_input(user_input):
    """Render user input - VULNERABLE to XSS."""
    html_output = Markup("<div>" + user_input + "</div>")
    return html_output


def render_search_results(query):
    """Render search results - VULNERABLE to XSS."""
    return f"<h1>Results for: {query}</h1>"


def render_comment(comment_text):
    """Render comment - VULNERABLE to XSS."""
    output = "<p class='comment'>" + comment_text + "</p>"
    return output
