from flask import Flask, request, render_template_string, redirect, url_for, make_response
import sqlite3
import os
import uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Required for session handling

# Simulated token-to-user mapping (in-memory storage)
token_to_user = {}

# Initialize the database
def setup_db():
    db_path = "example.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create users table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    # Insert default users if they don't already exist
    users = [
        ('admin', 'password123'),
        ('joel', 'joel123'),
        ('alice', 'alice123')
    ]
    for username, password in users:
        cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", (username, password))

    # Debug: Print all users in the database
    cursor.execute("SELECT * FROM users")
    print("Current users in the database:", cursor.fetchall())

    conn.commit()
    conn.close()

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
                <h1 class="display-4">Programa de Entrenamiento en Seguridad con Enfoque DAST                                                                                                                                                                                                                                                                                 </h1>
                <p class="lead">Estos ejercicios demuestran vulnerabilidades con fines educativos.</p>
                <a href="/login" class="btn btn-primary btn-lg mt-3"> Ejercicio de SQL Injection </a>
                <a href="/exercise-token" class="btn btn-secondary btn-lg mt-3">Ejercicios de exposicion de tokens</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        conn = sqlite3.connect("example.db")
        cursor = conn.cursor()

        # Authenticate user
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        result = cursor.execute(query, (username, password)).fetchone()
        conn.close()

        if result:
            token = str(uuid.uuid4())
            last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Store token-to-user mapping
            token_to_user[token] = {"username": username, "last_login": last_login}

            # Set HttpOnly and Secure cookies
            response = make_response(redirect(url_for("remediated_dashboard")))
            response.set_cookie("session", token, httponly=True, secure=True, path="/")
            return response
        else:
            return render_template_string('''
                <h1>Inicio de sesion incorrecto</h1>
                <p>Usuario o contraseña no valido.</p>
                <a href="/login">Try Again</a>
            ''')

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
                            <label for="Usuario" class="form-label">Usuario</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="Contraseña" class="form-label">Contraseña</label>
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

@app.route("/login-remediated", methods=["GET", "POST"])
def login_remediated():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        conn = sqlite3.connect("example.db")
        cursor = conn.cursor()

        # Authenticate user
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        result = cursor.execute(query, (username, password)).fetchone()
        conn.close()

        if result:
            token = str(uuid.uuid4())
            last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Store token-to-user mapping
            token_to_user[token] = {"username": username, "last_login": last_login}
            print(f"[DEBUG] User {username} logged in. Token: {token}")

            # Set HttpOnly and Secure cookies
            response = make_response(redirect(url_for("remediated_dashboard")))
            response.set_cookie("session", token, httponly=True, secure=True, path="/")
            print(f"[DEBUG] Cookie set with token: {token}")
            return response
        else:
            print("[DEBUG] Login failed.")
            return render_template_string('''
                <h1>Inicio de sesion incorrecto</h1>
                <p>Invalid username or password.</p>
                <a href="/login-remediated">Intentelo de nuevo</a>
            ''')

    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Login Seguro</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <h1 class="text-center">Secure Login</h1>
            <div class="card mx-auto mt-4" style="max-width: 400px;">
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Usuario</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Contraseña</label>
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

@app.route("/login-expose-dashboard", methods=["GET", "POST"])
def login_expose_dashboard():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        conn = sqlite3.connect("example.db")
        cursor = conn.cursor()

        # Authenticate user
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        result = cursor.execute(query, (username, password)).fetchone()
        conn.close()

        if result:
            token = str(uuid.uuid4())
            last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Store token-to-user mapping
            token_to_user[token] = {"username": username, "last_login": last_login}

            # Redirect with token in URL (vulnerable practice)
            return redirect(url_for("expose_dashboard", token=token))
        else:
            return render_template_string('''
                <h1>Inicio de sesion incorrecto</h1>
                <p>Usuario o contraseña invalido.</p>
                <a href="/login-expose-dashboard">Intentar de nuevo</a>
            ''')

    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Vulnerable Login</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <h1 class="text-center">Inicio de Sesión (Token Expuesto)</h1>
            <div class="card mx-auto mt-4" style="max-width: 400px;">
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Nombre de Usuario</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Contraseña</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-danger w-100">Iniciar Sesión</button>
                    </form>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route("/expose-dashboard", methods=["GET"])
def expose_dashboard():
    token = request.args.get("token")
    if not token or token not in token_to_user:
        return "<h1>Error</h1><p>Invalid token or session expired.</p>", 403

    user_data = token_to_user[token]
    username = user_data["username"]
    last_login = user_data["last_login"]

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Exposed Dashboard</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-danger text-white">
                    <h3 class="text-center">Panel de Usuario Expuesto</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Bienvenido, <b>{username}</b>!</p>
                    <p><strong>Último inicio de sesión:</strong> {last_login}</p>
                    <p><strong>Tu token de sesión:</strong> {token}</p>
                </div>
                <div class="card-footer text-center">
                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

@app.route("/exercise-token")
def exercise_token():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Ejercicio de Exposición de Tokens</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="text-center">
                <h1 class="display-4">Token Exposure Exercise</h1>
                <p class="lead">Explora cómo la exposición de tokens de sesión puede llevar a vulnerabilidades.</p>
                <a href="/login-expose-dashboard" class="btn btn-danger btn-lg mt-3">Ir al Panel de Control Expuesto</a>
                <a href="/remediation-info" class="btn btn-info btn-lg mt-3">Ver Información de Remediación</a>
            </div>
        </div>
    </body>
    </html>
    '''


@app.route("/remediation-info")
def remediation_info():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Remediation for Exposed Tokens</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-info text-white">
                    <h3 class="text-center">Remediación para la Exposición de Tokens</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Para prevenir la exposición de tokens de sesión en las URLs, sigue estas mejores prácticas:</p>
                    <ul>
                        <li>Usa <strong>cookies</strong> con los atributos <code>HttpOnly</code> y <code>Secure</code> en lugar de colocar tokens en las URLs.</li>
                        <li>Valida las sesiones del lado del servidor para garantizar la autenticidad del token y evitar su mal uso</li>
                        <li>Implementa tiempos de expiración cortos para los tokens de sesión y regénéralos con frecuencia..</li>
                        <li>Restringe la exposición de datos sensibles a través de parámetros de la URL..</li>
                    </ul>
                    <p class="mt-3">Al implementar estos pasos, puedes mejorar la seguridad de tu aplicación contra el secuestro de sesiones y vulnerabilidades de exposición de tokens.</p>
                    <a href="/login-secure" class="btn btn-success btn-lg mt-3">Nuevo Login Seguro</a>
                </div>
                <div class="card-footer text-center">
                

                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''


@app.route("/remediated-dashboard", methods=["GET"])
def remediated_dashboard():
    token = request.cookies.get("session")  # Updated cookie name
    print(f"[DEBUG] Retrieved token from cookie: {token}")
    print(f"[DEBUG] token_to_user mapping: {token_to_user}")

    if not token or token not in token_to_user:
        print("[DEBUG] Session Invalida o expirada.")
        return "<h1>Error</h1><p>Session Invalida o expirada.</p>", 403

    user_data = token_to_user[token]
    username = user_data["username"]
    last_login = user_data["last_login"]

    print(f"[DEBUG] Valid session for user: {username}")
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Secure Dashboard</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-success text-white">
                    <h3 class="text-center">Secure User Dashboard</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Bienvenido, <b>{username}</b>!</p>
                    <p><strong>Último inicio de sesión:</strong> {last_login}</p>
                    <p>Tu sesión está protegida con cookies HttpOnly y Secure.</p>
                </div>
                <div class="card-footer text-center">
                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
##Session Token remediation##
@app.route("/secure-dashboard", methods=["GET"])
def secure_dashboard():
    token = request.cookies.get("secure_session")
    print(f"[DEBUG] Token retrieved from cookie: {token}")

    if not token:
        print("[DEBUG] No token found in cookie. Cookie might not be set or sent by the client.")
        return "<h1>Error</h1><p>Sesión inválida o expirada.</p>", 403

    if token not in token_to_user:
        print("[DEBUG] Token not found in mapping or session expired.")
        return "<h1>Error</h1><p>Sesión inválida o expirada.</p>", 403

    user_data = token_to_user[token]
    username = user_data["username"]
    last_login = user_data["last_login"]

    print(f"[DEBUG] Valid session for user: {username}")
    return f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Panel Seguro</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-success text-white">
                    <h3 class="text-center">Panel de Usuario Seguro</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Bienvenido, <b>{username}</b>!</p>
                    <p><strong>Último inicio de sesión:</strong> {last_login}</p>
                    <p>Tu sesión está protegida con cookies HttpOnly y Secure.</p>
                </div>
                <div class="card-footer text-center">
                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

@app.route("/login-secure", methods=["GET", "POST"])
def login_secure():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        conn = sqlite3.connect("example.db")
        cursor = conn.cursor()

        # Authenticate user
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        result = cursor.execute(query, (username, password)).fetchone()
        conn.close()

        if result:
            token = str(uuid.uuid4())
            last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Store token-to-user mapping
            token_to_user[token] = {"username": username, "last_login": last_login}
            print(f"[DEBUG] User {username} authenticated. Token generated: {token}")
            print(f"[DEBUG] Current token-to-user mapping: {token_to_user}")

            # Set HttpOnly and Secure cookies
            response = make_response(redirect(url_for("secure_dashboard")))
            response.set_cookie("secure_session", token, httponly=True, path="/")  # Remove `secure=True` for local testing
            print(f"[DEBUG] Cookie set with token: {token}")
            return response
        else:
            print("[DEBUG] Login failed.")
            return render_template_string('''
                <h1>Inicio de Sesión Fallido</h1>
                <p>Usuario o contraseña inválidos.</p>
                <a href="/login-secure">Intentar de nuevo</a>
            ''')

    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Inicio de Sesión Seguro</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <h1 class="text-center">Inicio de Sesión Seguro</h1>
            <div class="card mx-auto mt-4" style="max-width: 400px;">
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Usuario</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Contraseña</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-success w-100">Iniciar Sesión</button>
                    </form>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

if __name__ == "__main__":
    setup_db()  # Ensure the database is properly initialized
    port = int(os.environ.get("PORT", 5000))  # Default to port 5000 for local testing
    app.run(host="0.0.0.0", port=port, debug=True)
