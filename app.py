from flask import Flask, jsonify, request, render_template_string, redirect, url_for, make_response
import sqlite3
import os
import uuid
from datetime import datetime
from flask_restful import Api, Resource  
from flask_swagger_ui import get_swaggerui_blueprint

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
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Grupo Babel - Programa de Entrenamiento</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #ffffff;
                color: #212529;
            }
            .navbar {
                background-color: #000000;
                border-bottom: 2px solid #000000;
            }
            .navbar-brand {
                color: #ffffff;
                font-weight: bold;
            }
            .navbar-brand:hover {
                color: #FF6F00;
            }
            .btn-primary {
                background-color: #FF6F00;
                border-color: #FF6F00;
            }
            .btn-primary:hover {
                background-color: #FF8C32;
                border-color: #FF8C32;
            }
            .btn-warning {
                background-color: #FFB000;
                border-color: #FFB000;
            }
            .btn-warning:hover {
                background-color: #FFC233;
                border-color: #FFC233;
            }
            .footer {
                background-color: #000000;
                color: #FF6F00;
                padding: 10px 0;
                text-align: center;
                margin-top: 30px;
            }
            .card {
                border: none;
                transition: transform 0.3s;
            }
            .card:hover {
                transform: scale(1.05);
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
            }
            .logo {
                height: 50px;
                margin-right: 10px;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg">
            <div class="container">
                <a class="navbar-brand" href="/">
                    <img src="https://babelgroup.com/wp-content/uploads/2024/04/logotipo-babel.svg" alt="Grupo Babel" class="logo">
                </a>
            </div>
        </nav>

        <div class="container mt-5">
            <div class="text-center mb-4">
                <h1 class="display-5" style="color: #FF6F00;">Programa de Entrenamiento en Seguridad con Enfoque DAST</h1>
                <p class="lead">Explora y aprende sobre vulnerabilidades comunes y cómo mitigarlas.</p>
            </div>

            <!-- Sección de SQL Injection -->
            <div class="section mb-5">
                <h2 class="text-center" style="color: #FF6F00;">Ejercicios de SQL Injection</h2>
                <div class="row justify-content-center">
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Vulnerable</h5>
                                <p class="card-text">Explora cómo funciona un ataque de SQL Injection en un entorno inseguro.</p>
                                <a href="/login-sqli" class="btn btn-danger">Probar SQL Injection</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Mitigada</h5>
                                <p class="card-text">Aprende cómo prevenir ataques de SQL Injection mediante consultas parametrizadas.</p>
                                <a href="/login-mitigated" class="btn btn-success">Probar SQL Injection Mitigado</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Sección de Exposición de Tokens -->
            <div class="section mb-5">
                <h2 class="text-center" style="color: #FFB000;">Ejercicios de Exposición de Tokens</h2>
                <div class="row justify-content-center">
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Vulnerable</h5>
                                <p class="card-text">Descubre cómo la exposición de tokens en URLs puede comprometer la seguridad.</p>
                                <a href="/login-expose-dashboard" class="btn btn-warning">Probar Exposición de Tokens</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Mitigada</h5>
                                <p class="card-text">Aprende a proteger los tokens de sesión usando cookies seguras.</p>
                                <a href="/login-secure" class="btn btn-info">Probar Mitigación de Tokens</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Sección de jQuery -->
            <div class="section mb-5">
                <h2 class="text-center" style="color: #FF6F00;">Ejercicios de jQuery</h2>
                <div class="row justify-content-center">
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Vulnerable</h5>
                                <p class="card-text">Explora cómo una versión desactualizada de jQuery puede generar vulnerabilidades.</p>
                                <a href="/jquery-vulnerable" class="btn btn-primary">Probar jQuery Vulnerable</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Mitigada</h5>
                                <p class="card-text">Aprende cómo una versión actualizada de jQuery previene vulnerabilidades conocidas.</p>
                                <a href="/jquery-secure" class="btn btn-success">Probar jQuery Seguro</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Sección de Content-Security-Policy (CSP) -->
            <div class="section mb-5">
                <h2 class="text-center" style="color: #FF6F00;">Ejercicios de Content-Security-Policy (CSP)</h2>
                <div class="row justify-content-center">
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Vulnerable</h5>
                                <p class="card-text">Explora cómo la falta de CSP puede llevar a ataques XSS.</p>
                                <a href="/csp-vulnerable" class="btn btn-danger">Probar CSP Vulnerable</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Mitigada</h5>
                                <p class="card-text">Aprende a configurar una política de CSP para evitar ataques XSS.</p>
                                <a href="/csp-secure" class="btn btn-success">Probar CSP Seguro</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Sección de Manejo de Cookies -->
            <div class="section mb-5">
                <h2 class="text-center" style="color: #FF6F00;">Ejercicios de Manejo de Cookies</h2>
                <div class="row justify-content-center">
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Vulnerable</h5>
                                <p class="card-text">Descubre cómo el mal manejo de cookies puede ser inseguro.</p>
                                <a href="/cookies-vulnerable" class="btn btn-danger">Probar Cookies Vulnerables</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-5">
                        <div class="card bg-light">
                            <div class="card-body text-center">
                                <h5 class="card-title">Versión Segura</h5>
                                <p class="card-text">Aprende a configurar cookies seguras con flags esenciales.</p>
                                <a href="/cookies-secure" class="btn btn-success">Probar Cookies Seguras</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        

        <!-- Seccion API -->
            <div class="section mb-5">
            <h2 class="text-center" style="color: #FF6F00;">Ejercicios de Gestion de APIs</h2>
                <div class="row justify-content-center">
                <div class="col-md-5">
                    <div class="card bg-light">
                        <div class="card-body text-center">
                            <h5 class="card-title text-danger">Versión Vulnerable</h5>
                            <p class="card-text">Explora cómo una API mal configurada puede exponer datos sensibles.</p>
                            <a href="/exercise-api-vulnerable" class="btn btn-danger">Probar API Vulnerable</a>
                        </div>
                    </div>
                </div>
                <div class="col-md-5">
                    <div class="card bg-light">
                        <div class="card-body text-center">
                            <h5 class="card-title text-success">Versión Segura</h5>
                            <p class="card-text">Aprende cómo mitigar la exposición de datos y mejorar la seguridad.</p>
                            <a href="/exercise-api-secure" class="btn btn-success">Probar API Segura</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>  

        <footer class="footer">
            <p>&copy; 2025 Grupo Babel. Todos los derechos reservados. | Creado por Joel Leiton, Penetration and Vulnerability Tester</p>
        </footer>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''



@app.route("/login-sqli", methods=["GET", "POST"])
def login_sqli():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        conn = sqlite3.connect("example.db")
        cursor = conn.cursor()

        # Consulta vulnerable
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"[DEBUG] Consulta ejecutada: {query}")
        result = cursor.execute(query).fetchone()
        conn.close()

        if result:
            return f'''
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <title>Inicio de Sesión Exitoso</title>
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-success text-center">
                        <h4 class="alert-heading">¡Inicio de sesión exitoso!</h4>
                        <p>Bienvenido, <b>{username}</b>.</p>
                        <p><strong>Contraseña ingresada:</strong> {password}</p>
                        <a href="/" class="btn btn-primary">Volver al inicio</a>
                    </div>
                </div>
            </body>
            </html>
            '''
        else:
            return '''
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <title>Inicio de Sesión Fallido</title>
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-danger text-center">
                        <h4 class="alert-heading">Inicio de sesión fallido</h4>
                        <p>Usuario o contraseña incorrectos.</p>
                        <a href="/login-sqli" class="btn btn-danger">Intentar de nuevo</a>
                    </div>
                </div>
            </body>
            </html>
            '''

    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Inicio de Sesión Vulnerable</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <h1 class="text-center">Inicio de Sesión Vulnerable (SQL Injection)</h1>
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
                        <button type="submit" class="btn btn-primary w-100">Iniciar Sesión</button>
                        <button type="button" class="btn btn-secondary w-100 mt-2" data-bs-toggle="modal" data-bs-target="#helpModal">Ayuda</button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Modal de Ayuda -->
        <div class="modal fade" id="helpModal" tabindex="-1" aria-labelledby="helpModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="helpModalLabel">Ejemplos de Payloads para SQL Injection</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>Prueba los siguientes payloads:</p>
                        <ul>
                            <li><code>' OR '1'='1</code></li>
                            <li><code>admin' --</code></li>
                            <li><code>' UNION SELECT 1, 'hacked', '12345'</code></li>
                            <li><code>' OR 1=1 --</code></li>
                        </ul>
                        <p>Nota: Estos ejemplos son solo para fines educativos.</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''
@app.route("/login-mitigated", methods=["GET", "POST"])
def login_mitigated():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        conn = sqlite3.connect("example.db")
        cursor = conn.cursor()

        # Consulta parametrizada
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        print(f"[DEBUG] Consulta parametrizada ejecutada con: {username}, {password}")
        result = cursor.execute(query, (username, password)).fetchone()
        conn.close()

        if result:
            # Mostrar página de inicio exitoso con la explicación de mitigación
            return f'''
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
                    <div class="alert alert-success text-center">
                        <h4 class="alert-heading">¡Inicio de sesión exitoso!</h4>
                        <p>Bienvenido, <b>{username}</b>.</p>
                        <a href="/" class="btn btn-primary">Volver al inicio</a>
                    </div>
                    <div class="card mt-4">
                        <div class="card-header bg-success text-white">
                            <h5>Explicación de la Mitigación</h5>
                        </div>
                        <div class="card-body">
                            <p>En la versión vulnerable, el ataque SQL Injection fue posible porque las consultas SQL se generaron dinámicamente concatenando datos del usuario. Esto permitió a un atacante inyectar comandos maliciosos en la consulta SQL.</p>
                            <p>En la versión mitigada, se utilizan <strong>consultas parametrizadas</strong>, que separan los datos del usuario del comando SQL, evitando así la ejecución de código malicioso.</p>
                            <h6>Consulta Vulnerable:</h6>
                            <pre style="background-color: #f8d7da; padding: 10px; border-radius: 5px;">
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                            </pre>
                            <h6>Consulta Segura:</h6>
                            <pre style="background-color: #d4edda; padding: 10px; border-radius: 5px;">
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))
                            </pre>
                            <p>El uso de consultas parametrizadas garantiza que los datos proporcionados por el usuario se traten como valores literales, no como comandos SQL.</p>
                        </div>
                    </div>
                </div>
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
            '''
        else:
            # Mostrar mensaje de error
            return '''
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <title>Inicio de Sesión Fallido</title>
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-danger text-center">
                        <h4 class="alert-heading">Inicio de sesión fallido</h4>
                        <p>Usuario o contraseña incorrectos.</p>
                        <a href="/login-mitigated" class="btn btn-danger">Intentar de nuevo</a>
                    </div>
                </div>
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
            '''

    # Formulario de inicio de sesión
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
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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

##JQUERY Excercise##

@app.route("/jquery-vulnerable")
def jquery_vulnerable():
    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>jQuery Vulnerable</title>
        <script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-danger text-white">
                    <h3 class="text-center">Ejercicio: jQuery Vulnerable</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Explora cómo una versión desactualizada de jQuery puede generar vulnerabilidades de seguridad.</p>
                    <div class="mb-3">
                        <label for="userInput" class="form-label">Introduce un valor:</label>
                        <input type="text" id="userInput" class="form-control" placeholder="Escribe algo aquí">
                    </div>
                    <button id="vulnerableButton" class="btn btn-danger">Insertar en la Página</button>
                    <div id="vulnerableOutput" class="mt-3 p-3 border bg-white"></div>
                </div>
                <div class="card-footer text-center">
                    <button type="button" class="btn btn-secondary" data-bs-toggle="modal" data-bs-target="#helpModal">Ver Ayuda</button>
                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
            </div>

            <!-- Modal de Ayuda -->
            <div class="modal fade" id="helpModal" tabindex="-1" aria-labelledby="helpModalLabel" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="helpModalLabel">Ayuda: jQuery Vulnerable</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>
                        </div>
                        <div class="modal-body">
                            <p>Ejemplos de vulnerabilidades que puedes probar:</p>
                            <ul>
                                <li><strong>Payload XSS:</strong> <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                                <li><strong>Manipulación del DOM:</strong> Uso inseguro de <code>html()</code> o <code>append()</code>.</li>
                            </ul>
                            <p><strong>Recomendación:</strong> Actualiza a la versión más reciente de jQuery para evitar estos problemas.</p>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            $(document).ready(function() {
                $('#vulnerableButton').click(function() {
                    let userInput = $('#userInput').val();
                    $('#vulnerableOutput').html(userInput); // Vulnerable to XSS
                });
            });
        </script>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''

@app.route("/jquery-secure")
def jquery_secure():
    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>jQuery Seguro</title>
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-success text-white">
                    <h3 class="text-center">Ejercicio: jQuery Seguro</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Aprende cómo las versiones actualizadas de jQuery pueden prevenir vulnerabilidades comunes.</p>
                    <div class="mb-3">
                        <label for="userInputSecure" class="form-label">Introduce un valor:</label>
                        <input type="text" id="userInputSecure" class="form-control" placeholder="Escribe algo aquí">
                    </div>
                    <button id="secureButton" class="btn btn-success">Insertar en la Página</button>
                    <div id="secureOutput" class="mt-3 p-3 border bg-white"></div>
                    <p class="mt-3 text-muted">Mitigación: Validación adecuada y uso seguro de funciones para evitar XSS.</p>
                </div>
                <div class="card-footer text-center">
                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
            </div>
        </div>

        <script>
            $(document).ready(function() {
                $('#secureButton').click(function() {
                    let userInput = $('<div>').text($('#userInputSecure').val()).html(); // Escapando caracteres
                    $('#secureOutput').html(userInput); // Uso seguro
                });
            });
        </script>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''

@app.route("/csp-vulnerable")
def csp_vulnerable():
    # Sin configuraciones de CSP
    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Ejercicio CSP Vulnerable</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card shadow-sm">
                <div class="card-header bg-danger text-white text-center">
                    <h3>Ejemplo Vulnerable: Falta de CSP</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Este sitio no tiene una política de CSP definida, lo que permite la ejecución de scripts maliciosos.</p>
                    <div class="alert alert-danger">Ejemplo de XSS: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></div>
                    <button id="runScriptButton" class="btn btn-danger">Ejecutar Script</button>
                    <a href="/csp-secure" class="btn btn-success">Ver versión segura</a>
                    <button class="btn btn-info" data-bs-toggle="modal" data-bs-target="#explanationModal">¿Por qué es vulnerable?</button>
                </div>
                                <div class="card-footer text-center">
                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
            </div>
        </div>

        <!-- Modal de explicación -->
        <div class="modal fade" id="explanationModal" tabindex="-1" aria-labelledby="explanationModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="explanationModalLabel">Explicación: Falta de CSP</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>La falta de una política CSP permite que cualquier script, incluso malicioso, se ejecute en el navegador del usuario.</p>
                        <p><strong>Herramientas de Validación:</strong></p>
                        <ul>
                            <li>Utiliza DevTools del navegador para verificar los encabezados HTTP y simular ataques.</li>
                            <li>Inspecciona el código fuente para identificar scripts no confiables.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <script>
            document.getElementById('runScriptButton').addEventListener('click', function() {
                const script = "alert('Este es un script malicioso ejecutado sin restricciones.');";
                eval(script);
            });
        </script>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''

@app.route("/csp-secure")
def csp_secure():
    # Aplicando configuraciones seguras de CSP
    response = make_response('''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Ejercicio CSP Seguro</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card shadow-sm">
                <div class="card-header bg-success text-white text-center">
                    <h3>Ejemplo Seguro: Configuración de CSP</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Este sitio tiene una política CSP que permite la carga de scripts confiables como Bootstrap, previniendo ataques XSS.</p>
                    <div class="alert alert-success">
                        <strong>Ejemplo de CSP aplicado:</strong>
                        <div style="background-color: #d4edda; padding: 10px; border-radius: 5px; font-weight: bold;">default-src 'self' https://cdn.jsdelivr.net;</div>
                    </div>
                    <p>Con esta configuración, solo se permite la ejecución de scripts desde el dominio propio y recursos confiables como CDNs.</p>
                    <div class="text-center">
                        <a href="/csp-vulnerable" class="btn btn-danger me-2">Ver versión vulnerable</a>
                        <button class="btn btn-info" data-bs-toggle="modal" data-bs-target="#explanationModal">¿Cómo se mitigó?</button>
                    </div>
                </div>
                                <div class="card-footer text-center">
                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
                </div>
            </div>
        </div>

        <!-- Modal de explicación -->
        <div class="modal fade" id="explanationModal" tabindex="-1" aria-labelledby="explanationModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="explanationModalLabel">Explicación: Configuración de CSP</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>La vulnerabilidad se mitigó implementando un encabezado Content-Security-Policy (CSP), que restringe las fuentes desde las cuales el navegador puede cargar recursos.</p>
                        <p><strong>Mitigación aplicada:</strong></p>
                        <ul>
                            <li>Se definió una política CSP con <code>default-src 'self' https://cdn.jsdelivr.net;</code>, permitiendo solo recursos confiables.</li>
                            <li>Esto previene la ejecución de scripts inyectados o maliciosos desde fuentes externas no confiables.</li>
                        </ul>
                        <p><strong>Beneficios:</strong></p>
                        <ul>
                            <li>Evita que scripts maliciosos cargados desde dominios externos no confiables se ejecuten.</li>
                            <li>Permite el uso de recursos externos confiables, como CDNs, para librerías comunes.</li>
                        </ul>
                        <p><strong>Herramientas de Validación:</strong></p>
                        <ul>
                            <li>Verifica la política CSP con DevTools en el navegador (Pestaña "Network" → Encabezados).</li>
                            <li>Usa herramientas de seguridad específicas para comprobar encabezados HTTP.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    ''')
    response.headers["Content-Security-Policy"] = "default-src 'self' https://cdn.jsdelivr.net;"
    return response

# Ejercicio 2: Manejo seguro de cookies
@app.route("/cookies-vulnerable")
def cookies_vulnerable():
    response = make_response('''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Cookies Vulnerables</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card shadow-sm">
                <div class="card-header bg-danger text-white text-center">
                    <h3>Ejemplo de Cookies Vulnerables</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Esta cookie no está configurada con Secure ni HttpOnly, lo que la hace susceptible a ataques.</p>
                    <div class="alert alert-danger">Cookie creada: <code>vulnerable_cookie=valor_inseguro</code></div>
                    <div class="text-center">
                        <button class="btn btn-warning" id="attackButton">Simular Ataque</button>
                        <a href="/cookies-secure" class="btn btn-success">Ver versión segura</a>
                        <button class="btn btn-info" data-bs-toggle="modal" data-bs-target="#explanationModal">¿Por qué es vulnerable?</button>
                    </div>
                                                    <div class="card-footer text-center">
                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
            </div>
        </div>

        <!-- Modal de explicación -->
        <div class="modal fade" id="explanationModal" tabindex="-1" aria-labelledby="explanationModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="explanationModalLabel">Explicación: Cookies Vulnerables</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>Las cookies sin los flags <code>Secure</code> y <code>HttpOnly</code> pueden ser interceptadas o manipuladas, comprometiendo la seguridad.</p>
                        <p><strong>Ejemplo de ataque:</strong> Un atacante podría ejecutar un script malicioso para leer las cookies en el navegador del usuario, como este:</p>
                        <div class="alert alert-danger">
                            <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
                        </div>
                        <p>Presiona el botón "Simular Ataque" para ver cómo un script puede acceder a las cookies.</p>
                        <p><strong>Herramientas de Validación:</strong></p>
                        <ul>
                            <li>Utiliza DevTools para inspeccionar las cookies.</li>
                            <li>Prueba con herramientas de análisis de seguridad para verificar la configuración insegura.</li>
                        </ul>
                    </div>
                </div>
                </div>
            </div>
        </div>

        <script>
            document.getElementById('attackButton').addEventListener('click', function() {
                alert('Simulación de ataque: Las cookies accesibles son: ' + document.cookie);
            });
        </script>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    ''')
    response.set_cookie("vulnerable_cookie", "valor_inseguro")
    return response

@app.route("/cookies-secure")
def cookies_secure():
    response = make_response('''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Cookies Seguras</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card shadow-sm">
                <div class="card-header bg-success text-white text-center">
                    <h3>Ejemplo de Cookies Seguras</h3>
                </div>
                <div class="card-body">
                    <p class="lead">Esta cookie está configurada con Secure y HttpOnly, lo que mejora significativamente la seguridad.</p>
                    <div class="alert alert-success">Cookie creada: <code>secure_cookie=valor_seguro</code></div>
                    <div class="text-center">
                        <button class="btn btn-warning" id="attackButton">Simular Ataque</button>
                        <a href="/cookies-vulnerable" class="btn btn-danger">Ver versión vulnerable</a>
                        <button class="btn btn-info" data-bs-toggle="modal" data-bs-target="#explanationModal">¿Por qué es seguro?</button>
                    </div>
                                                    <div class="card-footer text-center">
                    <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                </div>
            </div>
        </div>

        <!-- Modal de explicación -->
        <div class="modal fade" id="explanationModal" tabindex="-1" aria-labelledby="explanationModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="explanationModalLabel">Explicación: Cookies Seguras</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>La configuración segura de cookies utiliza los flags <code>Secure</code> y <code>HttpOnly</code>, evitando accesos no autorizados.</p>
                        <p><strong>Mitigación aplicada:</strong></p>
                        <ul>
                            <li>El flag <code>HttpOnly</code> asegura que las cookies no sean accesibles mediante JavaScript.</li>
                            <li>El flag <code>Secure</code> garantiza que las cookies solo se transmitan a través de conexiones HTTPS.</li>
                        </ul>
                        <p><strong>Simulación de ataque:</strong> Al presionar el botón "Simular Ataque", se intenta acceder a las cookies mediante JavaScript. En este caso, no será posible debido a la configuración segura.</p>
                        <p><strong>Herramientas de Validación:</strong></p>
                        <ul>
                            <li>Verifica los atributos de las cookies con DevTools.</li>
                            <li>Utiliza herramientas de análisis de seguridad para confirmar las configuraciones seguras.</li>
                        </ul>
                    </div>
                </div>
                </div>
            </div>
        </div>

        <script>
            document.getElementById('attackButton').addEventListener('click', function() {
                try {
                    alert('Simulación de ataque: Las cookies accesibles son: ' + document.cookie);
                } catch (e) {
                    alert('No se pueden acceder a las cookies debido a la configuración segura.');
                }
            });
        </script>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    ''')
    response.set_cookie("secure_cookie", "valor_seguro", httponly=True, secure=True)
    return response

#API testing----------------------------------------------------|
# Simulación de base de datos con datos sensibles
users = [
    {"id": 1, "username": "admin", "password": "admin123", "email": "admin@example.com", "token": "abc123"},
    {"id": 2, "username": "joel", "password": "joel123", "email": "joel@example.com", "token": "xyz789"},
    {"id": 3, "username": "alice", "password": "alice123", "email": "alice@example.com", "token": "def456"}
]

@app.route('/api-vulnerable', methods=['GET'])
def api_vulnerable():
    return jsonify(users)  # Devuelve datos sensibles sin autorización

@app.route("/exercise-api-vulnerable")
def exercise_api_vulnerable():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>API Vulnerable - Exposición de Datos</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-danger text-white text-center">
                    <h3>Ejercicio: API Vulnerable</h3>
                </div>
                <div class="card-body">
                    <h5 class="text-danger">Descripción del Problema</h5>
                    <p>Esta API presenta una vulnerabilidad grave debido a la **exposición de datos sensibles** y **falta de control de acceso**. 
                    Actualmente, cualquier usuario puede acceder a la lista completa de usuarios junto con información confidencial, como contraseñas y tokens de autenticación.</p>
                    
                    <h5 class="text-danger">Causas de la Vulnerabilidad</h5>
                    <ul>
                        <li><strong>Ausencia de Autenticación y Autorización:</strong> No hay ninguna validación que restrinja el acceso a los datos.</li>
                        <li><strong>Exposición de Datos Sensibles:</strong> La API devuelve información como contraseñas y tokens en texto plano.</li>
                        <li><strong>Enumeración de Usuarios:</strong> Un atacante puede extraer datos de todos los usuarios sin restricciones.</li>
                    </ul>

                    <h5 class="text-danger">Exploit: Cómo probar la falla</h5>
                    <p>Ejecuta el siguiente comando en tu terminal para acceder a los datos sensibles:</p>
                    <code>curl -X GET https://bncr-entrenamiento-9c003bd7c275.herokuapp.com/api-vulnerable</code>
                    <p>Esto devolverá la lista completa de usuarios, incluyendo contraseñas y tokens.</p>

                    <div class="alert alert-warning">
                        <strong>Impacto:</strong> Un atacante podría robar credenciales, realizar secuestro de sesiones y comprometer la seguridad del sistema.
                    </div>

                    <div class="text-center mt-4">
                        <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                        <a href="/exercise-api-secure" class="btn btn-success">Ver Versión Segura</a>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''')


# Simulación de base de datos segura
users_secure = {
    "abc123": {"id": 1, "username": "admin", "email": "admin@example.com"},
    "xyz789": {"id": 2, "username": "joel", "email": "joel@example.com"},
    "def456": {"id": 3, "username": "alice", "email": "alice@example.com"}
}

@app.route('/api-secure', methods=['GET'])
def api_secure():
    token = request.headers.get('Authorization')

    if not token or token not in users_secure:
        return jsonify({"error": "Acceso no autorizado"}), 403

    return jsonify(users_secure[token])  # Retorna solo la información del usuario autenticado

@app.route("/exercise-api-secure")
def exercise_api_secure():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>API Segura - Protección de Datos</title>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-success text-white text-center">
                    <h3>Ejercicio: API Segura</h3>
                </div>
                <div class="card-body">
                    <h5 class="text-success">Solución y Mitigación</h5>
                    <p>Se han implementado mejoras de seguridad para mitigar las vulnerabilidades presentes en la versión anterior.</p>
                    
                    <h5 class="text-success">Mejoras Implementadas</h5>
                    <ul>
                        <li><strong>Autenticación Requerida:</strong> Se requiere un token válido para acceder a los datos.</li>
                        <li><strong>Restricción de Acceso:</strong> Cada usuario solo puede acceder a su propia información.</li>
                        <li><strong>Protección de Datos Sensibles:</strong> No se devuelven contraseñas ni tokens en la respuesta.</li>
                    </ul>

                    <h5 class="text-success">Cómo Probar la Versión Segura</h5>
                    <p>Ejecuta el siguiente comando para acceder a la API con autenticación:</p>
                    <code>curl -X GET http://localhost:5000/api-secure -H "Authorization: xyz789"</code>
                    <p>Solo se devolverán los datos del usuario autenticado.</p>

                    <div class="alert alert-info">
                        <strong>Beneficio:</strong> Ahora la API protege la información del usuario y evita fugas de datos confidenciales.
                    </div>

                    <div class="text-center mt-4">
                        <a href="/" class="btn btn-secondary">Volver al Inicio</a>
                        <a href="/exercise-api-vulnerable" class="btn btn-danger">Ver Versión Vulnerable</a>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''')
# Swagger UI setup
SWAGGER_URL = "/api/docs"  # URL for accessing Swagger UI
API_URL = "/swagger.json"   # URL for OpenAPI JSON file

swagger_ui_blueprint = get_swaggerui_blueprint(SWAGGER_URL, API_URL)
app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)

class SecureAPI(Resource):
    def get(self):
        """
        API Secure Endpoint
        ---
        tags:
          - Secure API
        summary: Get user details with authentication
        parameters:
          - in: header
            name: Authorization
            schema:
              type: string
            required: true
            description: Bearer Token for authentication
        responses:
          200:
            description: User information
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    id:
                      type: integer
                      example: 2
                    username:
                      type: string
                      example: "joel"
                    email:
                      type: string
                      example: "joel@example.com"
          403:
            description: Unauthorized access
        """
        token = request.headers.get("Authorization")

        if not token or token not in users_secure:
            return jsonify({"error": "Acceso no autorizado"}), 403

        return jsonify(users_secure[token])

# Register the API route
api.add_resource(SecureAPI, "/api-secure")

@app.route("/swagger.json")
def swagger_json():
    """
    OpenAPI JSON file for Swagger UI
    """
    return jsonify({
        "openapi": "3.0.0",
        "info": {
            "title": "Secure API",
            "version": "1.0",
            "description": "API with authentication and security best practices"
        },
        "paths": {
            "/api-secure": {
                "get": {
                    "tags": ["Secure API"],
                    "summary": "Get user details with authentication",
                    "parameters": [
                        {
                            "in": "header",
                            "name": "Authorization",
                            "schema": {"type": "string"},
                            "required": True,
                            "description": "Bearer Token for authentication"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User information",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer", "example": 2},
                                            "username": {"type": "string", "example": "joel"},
                                            "email": {"type": "string", "example": "joel@example.com"}
                                        }
                                    }
                                }
                            }
                        },
                        "403": {
                            "description": "Unauthorized access"
                        }
                    }
                }
            }
        }
    })



if __name__ == "__main__":
    setup_db()  # Ensure the database is properly initialized
    port = int(os.environ.get("PORT", 5000))  # Default to port 5000 for local testing
    app.run(host="0.0.0.0", port=port, debug=True)
