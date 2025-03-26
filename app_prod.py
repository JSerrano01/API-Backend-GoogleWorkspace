from flask import Flask, request, jsonify
from flask_cors import CORS
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pandas as pd
import os
import pymysql
from concurrent.futures import ThreadPoolExecutor
import ssl
import jwt
from datetime import datetime, timedelta, timezone
from werkzeug.utils import secure_filename
import uuid

# Configurar SSL context seguro
context = ssl.create_default_context()

# ------------------INICIALIZACION DE APLICACION FLASK---------------
app = Flask(__name__)
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:5173"
            ],  # Asegúrate que coincida con tu URL de frontend
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Authorization", "Content-Type"],
            "supports_credentials": True,
            "max_age": 86400,
        }
    },
)
app.secret_key = "API_SECRET_COLMAYOR"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["ALLOWED_EXTENSIONS"] = {"xlsx"}

# Configuración de Google Workspace
SERVICE_ACCOUNT_FILE = os.path.join(
    app.root_path, "static", "api-encuesta-conosolas-d26a05ee1ee3.json"
)
SCOPES = ["https://www.googleapis.com/auth/admin.directory.user"]
ADMIN_EMAIL = "api.workspace@colmayor.edu.co"
SECRET_KEY = "tu_clave_secreta_jwt"
DEFAULT_PASSWORD = "Colmayor1946"


# ---------------------FUNCIONES DE UTILIDAD-------------------------
def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
    )


def verify_token():
    token = request.headers.get("Authorization")
    if not token:
        return None, (jsonify({"success": False, "message": "Token faltante"}), 401)

    try:
        if token.startswith("Bearer "):
            token = token[7:]

        # Verificar expiración
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        exp_timestamp = decoded.get("exp")
        if exp_timestamp is None:
            raise jwt.InvalidTokenError("Token sin fecha de expiración")

        now = datetime.now(timezone.utc).timestamp()
        if now > exp_timestamp:
            raise jwt.ExpiredSignatureError("Token expirado")

        return decoded["user_id"], None

    except jwt.ExpiredSignatureError:
        return None, (jsonify({"success": False, "message": "Token expirado"}), 401)
    except jwt.InvalidTokenError:
        return None, (jsonify({"success": False, "message": "Token inválido"}), 401)
    except Exception as e:
        print(f"Error al decodificar token: {e}")
        return None, (
            jsonify({"success": False, "message": "Error al procesar token"}),
            401,
        )


# ---------------------CONEXIONES------------------------------------
def conectar_google_service(reintentos=3):
    intento = 0
    while intento < reintentos:
        try:
            credentials = service_account.Credentials.from_service_account_file(
                SERVICE_ACCOUNT_FILE, scopes=SCOPES
            )
            delegated_credentials = credentials.with_subject(ADMIN_EMAIL)
            service = build("admin", "directory_v1", credentials=delegated_credentials)
            print("Conexión exitosa a Google Workspace")
            return service
        except ssl.SSLError as e:
            print(f"Error SSL: {e}, reintentando ({intento + 1}/{reintentos})")
            intento += 1
    print(
        "No se pudo establecer la conexión con Google Workspace después de varios intentos."
    )
    return None


def conectar_base_datos():
    try:
        if os.getenv("ENV") == "PROD":
            db_host = os.getenv("DDBB_HOST")
            db_user = os.getenv("DDBB_USER")
            db_password = os.getenv("DDBB_PASSWORD")
        else:
            db_host = "localhost"
            db_user = "root"
            db_password = ""

        db_name = "api_workspace"
        connection = pymysql.connect(
            host=db_host, user=db_user, password=db_password, database=db_name
        )
        print("Conexión exitosa a la base de datos")
        return connection
    except pymysql.Error as e:
        print(f"Error al conectar a la base de datos: {e}")
        return None

# ----------------------FUNCIONES LOCALES-----------------------------


@app.route("/api/auth/change-password", methods=["PUT"])
def change_password():
    # 1. Verificar token de autenticación
    user_id, error_response = verify_token()
    if error_response:
        return error_response

    # 2. Obtener datos del request
    data = request.get_json()
    current_password = data.get("currentPassword")
    new_password = data.get("newPassword")

    if not current_password or not new_password:
        return jsonify({"success": False, "message": "Datos incompletos"}), 400

    # 3. Conectar a la base de datos
    connection = conectar_base_datos()
    if not connection:
        return (
            jsonify(
                {"success": False, "message": "Error de conexión a la base de datos"}
            ),
            500,
        )

    try:
        with connection.cursor() as cursor:
            # 4. Verificar contraseña actual
            cursor.execute("SELECT password FROM usuarios WHERE id = %s", (user_id,))
            result = cursor.fetchone()

            if not result:
                return (
                    jsonify({"success": False, "message": "Usuario no encontrado"}),
                    404,
                )

            stored_password = result[0]

            if stored_password != current_password:
                return (
                    jsonify(
                        {"success": False, "message": "Contraseña actual incorrecta"}
                    ),
                    401,
                )

            # 5. Actualizar contraseña
            cursor.execute(
                "UPDATE usuarios SET password = %s WHERE id = %s",
                (new_password, user_id),
            )
            connection.commit()

            return jsonify(
                {"success": True, "message": "Contraseña actualizada exitosamente"}
            )

    except Exception as e:
        print(f"Error al cambiar contraseña: {e}")
        return (
            jsonify({"success": False, "message": "Error al cambiar contraseña"}),
            500,
        )
    finally:
        connection.close()


@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    user_id, error_response = verify_token()
    if error_response:
        return error_response

    # Verificar permisos de admin
    token = request.headers.get("Authorization")[7:]  # Eliminar "Bearer "
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if "admin" not in decoded.get("permisos", []):
            return jsonify({"success": False, "message": "Acceso no autorizado"}), 403
    except Exception as e:
        return (
            jsonify({"success": False, "message": "Error al verificar permisos"}),
            500,
        )

    # Obtener usuarios de la base de datos
    connection = conectar_base_datos()
    if not connection:
        return (
            jsonify(
                {"success": False, "message": "Error de conexión a la base de datos"}
            ),
            500,
        )

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, nombre, apellido, email, permisos FROM usuarios")
            users = cursor.fetchall()

            user_list = []
            for user in users:
                user_list.append(
                    {
                        "id": user[0],
                        "nombre": user[1],
                        "apellido": user[2],
                        "email": user[3],
                        "permisos": user[4],
                    }
                )

            return jsonify({"success": True, "users": user_list})
    except Exception as e:
        print(f"Error al listar usuarios: {e}")
        return jsonify({"success": False, "message": "Error al listar usuarios"}), 500
    finally:
        connection.close()


@app.route("/api/admin/users/<int:user_id>", methods=["GET"])
def admin_get_user(user_id):
    # Verificar token y permisos
    _, error_response = verify_token()
    if error_response:
        return error_response

    # Verificar permisos de admin
    token = request.headers.get("Authorization")[7:]  # Eliminar "Bearer "
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if "admin" not in decoded.get("permisos", []):
            return jsonify({"success": False, "message": "Acceso no autorizado"}), 403
    except Exception as e:
        return (
            jsonify({"success": False, "message": "Error al verificar permisos"}),
            500,
        )

    # Obtener usuario de la base de datos
    connection = conectar_base_datos()
    if not connection:
        return (
            jsonify(
                {"success": False, "message": "Error de conexión a la base de datos"}
            ),
            500,
        )

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, nombre, apellido, email, permisos FROM usuarios WHERE id = %s",
                (user_id,),
            )
            user = cursor.fetchone()

            if user:
                return jsonify(
                    {
                        "success": True,
                        "user": {
                            "id": user[0],
                            "nombre": user[1],
                            "apellido": user[2],
                            "email": user[3],
                            "permisos": user[4],
                        },
                    }
                )
            else:
                return (
                    jsonify({"success": False, "message": "Usuario no encontrado"}),
                    404,
                )
    except Exception as e:
        print(f"Error al obtener usuario: {e}")
        return jsonify({"success": False, "message": "Error al obtener usuario"}), 500
    finally:
        connection.close()


@app.route("/api/admin/users/<int:user_id>", methods=["PUT"])
def admin_update_user(user_id):
    # Verificar token y permisos
    _, error_response = verify_token()
    if error_response:
        return error_response

    # Verificar permisos de admin
    token = request.headers.get("Authorization")[7:]  # Eliminar "Bearer "
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if "admin" not in decoded.get("permisos", []):
            return jsonify({"success": False, "message": "Acceso no autorizado"}), 403
    except Exception as e:
        return (
            jsonify({"success": False, "message": "Error al verificar permisos"}),
            500,
        )

    # Obtener datos del request
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Datos no proporcionados"}), 400

    # Campos permitidos para actualización
    update_fields = {
        "nombre": data.get("nombre"),
        "apellido": data.get("apellido"),
        "email": data.get("email"),
        "permisos": data.get("permisos"),
    }

    # Filtrar campos nulos
    update_fields = {k: v for k, v in update_fields.items() if v is not None}

    if not update_fields:
        return (
            jsonify(
                {"success": False, "message": "No hay datos válidos para actualizar"}
            ),
            400,
        )

    # Actualizar en base de datos
    connection = conectar_base_datos()
    if not connection:
        return (
            jsonify(
                {"success": False, "message": "Error de conexión a la base de datos"}
            ),
            500,
        )

    try:
        with connection.cursor() as cursor:
            set_clause = ", ".join([f"{field} = %s" for field in update_fields.keys()])
            values = list(update_fields.values())
            values.append(user_id)

            query = f"UPDATE usuarios SET {set_clause} WHERE id = %s"
            cursor.execute(query, values)
            connection.commit()

            return jsonify(
                {"success": True, "message": "Usuario actualizado exitosamente"}
            )
    except Exception as e:
        print(f"Error al actualizar usuario: {e}")
        connection.rollback()
        return (
            jsonify({"success": False, "message": "Error al actualizar usuario"}),
            500,
        )
    finally:
        connection.close()

@app.route("/api/admin/users/<int:user_id>/reset-password", methods=["POST", "OPTIONS"])
def admin_reset_password(user_id):
    if request.method == "OPTIONS":
        # Manejar la solicitud preflight CORS
        response = jsonify({"success": True})
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:5173")
        response.headers.add("Access-Control-Allow-Headers", "Authorization, Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST")
        return response

    # Verificar token y permisos
    _, error_response = verify_token()
    if error_response:
        return error_response

    # Verificar permisos de admin
    token = request.headers.get("Authorization")[7:]  # Eliminar "Bearer "
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if "admin" not in decoded.get("permisos", []):
            return jsonify({"success": False, "message": "Acceso no autorizado"}), 403
    except Exception as e:
        return jsonify({"success": False, "message": "Error al verificar permisos"}), 500

    # Obtener la nueva contraseña del request
    data = request.get_json()
    if not data or 'newPassword' not in data:
        return jsonify({"success": False, "message": "Nueva contraseña no proporcionada"}), 400

    new_password = data['newPassword']

    # Resetear contraseña
    connection = conectar_base_datos()
    if not connection:
        return jsonify({"success": False, "message": "Error de conexión a la base de datos"}), 500

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE usuarios SET password = %s WHERE id = %s",
                (new_password, user_id))
            connection.commit()

            return jsonify({
                "success": True,
                "message": "Contraseña actualizada exitosamente"
            })
    except Exception as e:
        print(f"Error al resetear contraseña: {e}")
        return jsonify({"success": False, "message": "Error al resetear contraseña"}), 500
    finally:
        connection.close()


# ---------------------FUNCIONES DE GOOGLE WORKSPACE-----------------
def listar_usuarios(service):
    usuarios = []
    try:
        page_token = None
        while True:
            results = (
                service.users()
                .list(customer="my_customer", maxResults=500, pageToken=page_token)
                .execute()
            )
            usuarios.extend(results.get("users", []))
            page_token = results.get("nextPageToken")
            if not page_token:
                break
    except HttpError as error:
        print(f"Error al listar los usuarios: {error}")
    return usuarios


def buscar_usuario(
    service, email=None, employee_id=None, given_name=None, family_name=None
):
    usuarios = listar_usuarios(service)

    # Verificar por email
    if email:
        email_lower = str(email).lower()
        for usuario in usuarios:
            if usuario["primaryEmail"].lower() == email_lower:
                return usuario["primaryEmail"], "Email"

    # Verificar por nombre y apellido
    if given_name and family_name:
        given_name_lower = str(given_name).lower()
        family_name_lower = str(family_name).lower()
        for usuario in usuarios:
            if (
                usuario["name"]["givenName"].lower() == given_name_lower
                and usuario["name"]["familyName"].lower() == family_name_lower
            ):
                return usuario["primaryEmail"], "Nombre y Apellido"

    # Verificar por employee_id (pero no retornamos aquí para permitir ID duplicado)
    if employee_id:
        employee_id_str = str(employee_id)
        for usuario in usuarios:
            if "externalIds" in usuario:
                for ext_id in usuario["externalIds"]:
                    if str(ext_id["value"]) == employee_id_str:
                        return usuario["primaryEmail"], "Employee ID"

    return None, None


def crear_usuario(service, email, given_name, family_name, employee_id):
    user_body = {
        "primaryEmail": email,
        "name": {"givenName": given_name, "familyName": family_name},
        "password": DEFAULT_PASSWORD,
        "changePasswordAtNextLogin": True,
        "externalIds": [{"type": "organization", "value": employee_id}],
    }

    try:
        result = service.users().insert(body=user_body).execute()
        return True, f'Usuario creado: {result["primaryEmail"]}'
    except HttpError as error:
        error_details = error.content.decode("utf-8")
        return False, f"Error al crear el usuario: {error_details}"
    except Exception as e:
        return False, f"Error inesperado al crear usuario: {str(e)}"


@app.route("/api/users/create-with-existing-id", methods=["POST"])
def create_user_with_existing_id():
    # Solo verifica el token, no los permisos
    user_id, error_response = verify_token()
    if error_response:
        return error_response

    data = request.get_json()
    service = conectar_google_service()
    if not service:
        return (
            jsonify(
                {"success": False, "message": "Error al conectar con Google Workspace"}
            ),
            500,
        )

    email = data.get("email")
    given_name = data.get("given_name")
    family_name = data.get("family_name")
    employee_id = data.get("employee_id")

    # Verificar si el correo ya existe
    existing_email, _ = buscar_usuario(service, email=email)
    if existing_email:
        return (
            jsonify(
                {
                    "success": False,
                    "exists": True,
                    "email": existing_email,
                    "reason": "Email",
                }
            ),
            400,
        )

    # Verificar si el nombre y apellido ya existen
    existing_name, _ = buscar_usuario(
        service, given_name=given_name, family_name=family_name
    )
    if existing_name:
        return (
            jsonify(
                {
                    "success": False,
                    "exists": True,
                    "email": existing_name,
                    "reason": "Nombre y Apellido",
                }
            ),
            400,
        )

    # Crear el usuario (permite Employee ID existente)
    success, message = crear_usuario(
        service, email, given_name, family_name, employee_id
    )

    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 400


@app.route("/api/users/search", methods=["GET"])
def search_users():
    # Verificar token
    _, error_response = verify_token()
    if error_response:
        return error_response

    # Obtener parámetros de búsqueda
    search_type = request.args.get("type")  # 'name', 'email' o 'employee_id'
    search_value = request.args.get("value")

    if not search_type or not search_value:
        return (
            jsonify({"success": False, "message": "Parámetros de búsqueda inválidos"}),
            400,
        )

    service = conectar_google_service()
    if not service:
        return (
            jsonify(
                {"success": False, "message": "Error al conectar con Google Workspace"}
            ),
            500,
        )

    try:
        users = listar_usuarios(service)
        results = []

        for user in users:
            match = False
            reason = ""

            # Búsqueda por email
            if search_type == "email" and "primaryEmail" in user:
                if search_value.lower() in user["primaryEmail"].lower():
                    match = True
                    reason = "Email"

            # Búsqueda por nombre y apellido
            elif search_type == "name" and "name" in user:
                full_name = f"{user['name'].get('givenName', '')} {user['name'].get('familyName', '')}"
                if search_value.lower() in full_name.lower():
                    match = True
                    reason = "Nombre"

            # Búsqueda por employee ID
            elif search_type == "employee_id" and "externalIds" in user:
                for ext_id in user["externalIds"]:
                    if (
                        ext_id["type"] == "organization"
                        and search_value == ext_id["value"]
                    ):
                        match = True
                        reason = "Employee ID"
                        break

            if match:
                results.append(
                    {
                        "id": user.get("id"),
                        "email": user.get("primaryEmail"),
                        "nombre": user.get("name", {}).get("givenName"),
                        "apellido": user.get("name", {}).get("familyName"),
                        "employeeId": next(
                            (
                                ext["value"]
                                for ext in user.get("externalIds", [])
                                if ext["type"] == "organization"
                            ),
                            None,
                        ),
                        "matchReason": reason,
                    }
                )

        return jsonify({"success": True, "results": results, "count": len(results)})

    except Exception as e:
        print(f"Error en búsqueda de usuarios: {e}")
        return jsonify({"success": False, "message": "Error en la búsqueda"}), 500


# ----------------------RUTAS API------------------------------------
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    connection = conectar_base_datos()
    if not connection:
        return (
            jsonify(
                {"success": False, "message": "Error de conexión a la base de datos"}
            ),
            500,
        )

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, nombre, apellido, email, permisos FROM usuarios WHERE email = %s AND password = %s",
                (email, password),
            )
            user = cursor.fetchone()

            if user:
                # Convertir permisos de string a lista
                permisos = user[4].split(",") if user[4] else []

                token = jwt.encode(
                    {
                        "user_id": user[0],
                        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
                        "permisos": permisos,
                    },
                    SECRET_KEY,
                    algorithm="HS256",
                )
                return jsonify(
                    {
                        "success": True,
                        "token": token,
                        "user": {
                            "id": user[0],
                            "nombre": user[1],
                            "apellido": user[2],
                            "email": user[3],
                            "permisos": permisos,
                        },
                    }
                )
            else:
                return (
                    jsonify({"success": False, "message": "Credenciales incorrectas"}),
                    401,
                )
    except Exception as e:
        print(f"Error en login: {e}")
        return jsonify({"success": False, "message": "Error en el servidor"}), 500
    finally:
        connection.close()


@app.route("/api/user/permissions", methods=["GET"])
def get_user_permissions():
    user_id, error_response = verify_token()
    if error_response:
        return error_response

    connection = conectar_base_datos()
    if not connection:
        return (
            jsonify(
                {"success": False, "message": "Error de conexión a la base de datos"}
            ),
            500,
        )

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT permisos FROM usuarios WHERE id = %s",
                (user_id),
            )
            result = cursor.fetchone()

            if result:
                permisos = result[0].split(",") if result[0] else []
                return jsonify({"success": True, "permisos": permisos})
            else:
                return (
                    jsonify({"success": False, "message": "Usuario no encontrado"}),
                    404,
                )
    except Exception as e:
        print(f"Error al obtener permisos: {e}")
        return jsonify({"success": False, "message": "Error en el servidor"}), 500
    finally:
        connection.close()


@app.route("/api/users", methods=["GET"])
def list_users():
    user_id, error_response = verify_token()
    if error_response:
        return error_response

    service = conectar_google_service()
    if not service:
        return (
            jsonify(
                {"success": False, "message": "Error al conectar con Google Workspace"}
            ),
            500,
        )

    try:
        users = listar_usuarios(service)
        simplified_users = [
            {
                "id": user.get("id"),
                "email": user.get("primaryEmail"),
                "nombre": user.get("name", {}).get("givenName"),
                "apellido": user.get("name", {}).get("familyName"),
                "employeeId": next(
                    (
                        ext["value"]
                        for ext in user.get("externalIds", [])
                        if ext["type"] == "organization"
                    ),
                    None,
                ),
            }
            for user in users
        ]

        return jsonify({"success": True, "users": simplified_users})
    except Exception as e:
        print(f"Error al listar usuarios: {e}")
        return jsonify({"success": False, "message": "Error al listar usuarios"}), 500


@app.route("/api/users/check", methods=["POST"])
def check_user():
    user_id, error_response = verify_token()
    if error_response:
        return error_response

    data = request.get_json()
    service = conectar_google_service()
    if not service:
        return (
            jsonify(
                {"success": False, "message": "Error al conectar con Google Workspace"}
            ),
            500,
        )

    email = data.get("email")
    employee_id = data.get("employee_id")
    given_name = data.get("given_name")
    family_name = data.get("family_name")

    existing_email, reason = buscar_usuario(
        service,
        email=email,
        employee_id=employee_id,
        given_name=given_name,
        family_name=family_name,
    )

    if existing_email:
        return jsonify(
            {
                "success": False,
                "exists": True,
                "email": existing_email,
                "reason": reason,
            }
        )
    else:
        return jsonify({"success": True, "exists": False})


@app.route("/api/users/create", methods=["POST"])
def create_user():
    # Solo verifica el token, no los permisos
    user_id, error_response = verify_token()
    if error_response:
        return error_response

    data = request.get_json()
    service = conectar_google_service()
    if not service:
        return (
            jsonify(
                {"success": False, "message": "Error al conectar con Google Workspace"}
            ),
            500,
        )

    email = data.get("email")
    given_name = data.get("given_name")
    family_name = data.get("family_name")
    employee_id = data.get("employee_id")

    # Verificación normal de usuario existente
    existing_email, reason = buscar_usuario(
        service,
        email=email,
        employee_id=employee_id,
        given_name=given_name,
        family_name=family_name,
    )

    if existing_email:
        return (
            jsonify(
                {
                    "success": False,
                    "exists": True,
                    "email": existing_email,
                    "reason": reason,
                }
            ),
            400,
        )

    success, message = crear_usuario(
        service, email, given_name, family_name, employee_id
    )

    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 400


@app.route("/api/users/bulk-create", methods=["POST"])
def bulk_create_users():
    # Verificar token primero
    user_id, error_response = verify_token()
    if error_response:
        return error_response

    # Verificar permisos del usuario
    token = request.headers.get("Authorization")[7:]  # Eliminar "Bearer "
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if "create_user" not in decoded.get("permisos", []):
            return (
                jsonify(
                    {"success": False, "message": "No tienes permisos para esta acción"}
                ),
                403,
            )
    except Exception as e:
        return (
            jsonify({"success": False, "message": "Error al verificar permisos"}),
            500,
        )

    if "file" not in request.files:
        return jsonify({"success": False, "message": "No se encontró el archivo"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "message": "Nombre de archivo vacío"}), 400

    if not allowed_file(file.filename):
        return (
            jsonify({"success": False, "message": "Tipo de archivo no permitido"}),
            400,
        )

    # Crear directorio de uploads si no existe
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])

    # Guardar archivo con nombre único
    filename = secure_filename(f"{uuid.uuid4().hex}.xlsx")
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    try:
        df = pd.read_excel(filepath)
        required_columns = ["Correo", "Nombre", "Apellido", "Employee ID"]

        if not all(col in df.columns for col in required_columns):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"El archivo debe contener las columnas: {', '.join(required_columns)}",
                    }
                ),
                400,
            )

        service = conectar_google_service()
        if not service:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Error al conectar con Google Workspace",
                    }
                ),
                500,
            )

        results = []
        with ThreadPoolExecutor() as executor:
            futures = []
            for _, row in df.iterrows():
                email = row["Correo"]
                given_name = row["Nombre"]
                family_name = row["Apellido"]
                employee_id = str(row["Employee ID"])

                futures.append(
                    executor.submit(
                        crear_usuario,
                        service,
                        email,
                        given_name,
                        family_name,
                        employee_id,
                    )
                )

            for future in futures:
                success, message = future.result()
                results.append({"success": success, "message": message})

        # Eliminar archivo después de procesarlo
        os.remove(filepath)

        return jsonify(
            {
                "success": True,
                "results": results,
                "total": len(results),
                "created": sum(1 for r in results if r["success"]),
            }
        )
    except Exception as e:
        print(f"Error en carga masiva: {e}")
        return (
            jsonify(
                {"success": False, "message": f"Error al procesar el archivo: {str(e)}"}
            ),
            500,
        )


# -------------------INICIAR LA APLICACION FLASK--------------------
if __name__ == "__main__":
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])
    app.run(debug=True, host="0.0.0.0", port=8080)
