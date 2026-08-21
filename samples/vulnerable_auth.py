# Sample Vulnerable Target File for SentinelAI Security Audit
import os
import sqlite3
import flask

app = flask.Flask(__name__)

# SECURITY FLAW 1: Hardcoded Secret Key (CWE-798)
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY_EXPOSED"
DATABASE_PASSWORD = "AdminPassword123!"

@app.route('/login', methods=['POST'])
def login():
    username = flask.request.form.get('username')
    password = flask.request.form.get('password')

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # SECURITY FLAW 2: SQL Injection via String Format (CWE-89)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return flask.jsonify({"status": "success", "token": AWS_SECRET_ACCESS_KEY})
    return flask.jsonify({"status": "failed"}), 401

@app.route('/user_profile', methods=['GET'])
def user_profile():
    name = flask.request.args.get('name', '')
    
    # SECURITY FLAW 3: Cross-Site Scripting (XSS) via Unescaped HTML Output (CWE-79)
    html_response = f"<h1>Welcome to Sentinel Portal, {name}!</h1>"
    return html_response

@app.route('/read_log', methods=['GET'])
def read_log():
    filename = flask.request.args.get('file')
    
    # SECURITY FLAW 4: Unsanitized File Access / Path Traversal (CWE-22)
    with open("/var/logs/" + filename, "r") as f:
        content = f.read()
    return content

if __name__ == '__main__':
    app.run(port=5000)

# Added JWT test pattern
