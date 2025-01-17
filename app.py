from flask import Flask, request, render_template_string
import sqlite3
from setup_db import setup_db  # Ensure this script exists to initialize the database
import os

app = Flask(__name__)

# Initialize the database
def setup_db():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create users table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)
    # Insert default user if table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")

    conn.commit()
    conn.close()

# Home route
@app.route("/")
def home():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Welcome</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="text-center">
                <h1 class="display-4">Welcome to the Vulnerable Web App</h1>
                <p class="lead">This app is intentionally vulnerable for training purposes.</p>
                <a href="/login" class="btn btn-primary btn-lg mt-3">Go to Login Page</a>
            </div>
        </div>
    </body>
    </html>
    '''

# Vulnerable login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect("example.db")
        cursor = conn.cursor()

        # Vulnerable query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        result = cursor.execute(query).fetchall()
        conn.close()

        if result:
            return '''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <title>Login Successful</title>
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-success text-center">
                        <h4 class="alert-heading">Login Successful!</h4>
                        <p>Welcome, <b>{username}</b>!</p>
                        <a href="/" class="btn btn-primary">Back to Home</a>
                    </div>
                </div>
            </body>
            </html>
            '''.format(username=username)
        else:
            return '''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <title>Login Failed</title>
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-danger text-center">
                        <h4 class="alert-heading">Login Failed</h4>
                        <p>Invalid username or password.</p>
                        <a href="/login" class="btn btn-danger">Try Again</a>
                    </div>
                </div>
            </body>
            </html>
            '''

    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Login</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <h1 class="text-center">Login</h1>
            <div class="card mx-auto mt-4" style="max-width: 400px;">
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Default to port 5000 for local testing
    app.run(host="0.0.0.0", port=port, debug=True)
