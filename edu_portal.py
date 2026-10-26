"""
Dory EDU — Hub Académico y Gateway de Seguridad
Subdominio: edu.dory.mx (y subruta local /edu)
Servicios integrados:
  - BecaFinder (Buscador Académico UDG)
  - TaskHub / Nemo (Gestor unificado de tareas: Classroom & Moodle)
"""
import os
import hmac
import sqlite3
import logging
import secrets
from functools import wraps
from datetime import datetime
import requests
import urllib.parse
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(dotenv_path=None):
        if dotenv_path and os.path.isfile(dotenv_path):
            with open(dotenv_path, "r", encoding="utf-8", errors="ignore") as _f:
                for _ln in _f:
                    _ln = _ln.strip()
                    if _ln and not _ln.startswith("#") and "=" in _ln:
                        _k, _v = _ln.split("=", 1)
                        os.environ.setdefault(_k.strip(), _v.strip().strip("\"'"))
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, flash, Response, send_from_directory, abort, current_app
from edu_moodle_sync import (
    sync_moodle_with_session_cookie,
    start_google_oauth_sync,
    get_google_sync_status
)

logger = logging.getLogger(__name__)

edu_bp = Blueprint('edu_bp', __name__, template_folder='templates')

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
# Cargar variables de entorno desde .env
load_dotenv(os.path.join(APP_ROOT, '.env'))

def _resolve_existing_dir(candidates, fallback):
    for c in candidates:
        if c and os.path.isdir(c):
            return os.path.abspath(c)
    return os.path.abspath(fallback)


ACADEMIC_DB_PATH = os.path.join(APP_ROOT, 'academic.db')
SPLUNKSIM_DIST_DIR = _resolve_existing_dir([
    os.environ.get('SPLUNKSIM_DIST_DIR', ''),
    os.path.join(APP_ROOT, '..', 'SplunkSim', 'dist'),
    r"C:\Users\QB_DESARROLLO\Desktop\03-Orquestador-y-Proyectos-Home\Proyectos_Home\Proyectos\SplunkSim\dist",
    r"C:\Users\CarlosAlbertoAcevesC\Desktop\03-ciberseguridad-soc\splunk-sim\dist",
], os.path.join(APP_ROOT, '..', 'SplunkSim', 'dist'))

CUGDL_GAMES_DIR = _resolve_existing_dir([
    os.environ.get('CUGDL_GAMES_DIR', ''),
    os.path.join(APP_ROOT, '..', 'CUGDL-Juegos-Offline'),
    r"C:\Users\QB_DESARROLLO\Desktop\03-Orquestador-y-Proyectos-Home\Proyectos_Home\Proyectos\CUGDL-Juegos-Offline",
    r"C:\Users\CarlosAlbertoAcevesC\Desktop\04-clientes-y-web\cugdl-juegos-offline",
], os.path.join(APP_ROOT, '..', 'CUGDL-Juegos-Offline'))

# Credenciales de contingencia (SOLO desde .env; sin valores por defecto en el código)
EDU_TEST_USER = os.environ.get('EDU_ADMIN_USER', 'admin')
EDU_TEST_PASS = os.environ.get('EDU_ADMIN_PASS', '')

# Credenciales Google OAuth 2.0 (el secreto SOLO desde .env)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '692349836110-bejf0o3no24g924i847l573col83ode3.apps.googleusercontent.com')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'https://edu.dory.mx/edu/auth/google/callback')

# Secreto compartido Gateway -> microservicios (TaskHub :3001, BecaFinder :3002).
# Los microservicios rechazan cualquier petición que no lo traiga, por lo que nadie puede
# saltarse el Gateway inyectando X-Edu-User directamente.
EDU_GATEWAY_SECRET = os.environ.get('EDU_GATEWAY_SECRET', '')

if not GOOGLE_CLIENT_SECRET:
    logger.error("❌ [DORY EDU] GOOGLE_CLIENT_SECRET no definido en .env: el login con Google fallará.")
if not EDU_TEST_PASS:
    logger.warning("⚠️ [DORY EDU] EDU_ADMIN_PASS no definido en .env: el login local de contingencia queda deshabilitado.")
if not EDU_GATEWAY_SECRET:
    logger.error("❌ [DORY EDU] EDU_GATEWAY_SECRET no definido en .env: los microservicios rechazarán las peticiones proxyadas.")


def _password_matches(provided, expected):
    """Comparación en tiempo constante. Una contraseña esperada vacía nunca coincide."""
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided.encode('utf-8'), expected.encode('utf-8'))


_STATIC_EXTENSIONS = ('.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.map', '.json', '.zip')


def _is_public_static_asset(clean_subpath):
    """Archivos del frontend que pueden servirse sin sesión.
    Nunca aplica a rutas de API o autenticación: antes '/api/workspace/<id>/files/x.png'
    se trataba como 'estático' y se saltaba el login."""
    p = clean_subpath.lower()
    if p in ('api', 'auth') or p.startswith(('api/', 'auth/')):
        return False
    return (
        'assets/' in p or
        p.startswith('vite.svg') or
        p.startswith('favicon') or
        p.endswith(_STATIC_EXTENSIONS)
    )

# Lista de correos administradores
EDU_ADMIN_EMAILS = [
    e.strip().lower() for e in os.environ.get('EDU_ADMIN_EMAILS', 'admin,carlos@dory.mx,carlosalbertoacevesc@gmail.com,carlos.aceves6195@alumnos.udg.mx,225361954').split(',') if e.strip()
]

# Endpoints oficiales Moodle UDG CUGDL
MOODLE_BASE_URL = "https://mi.cugdl.udg.mx"
MOODLE_TOKEN_URL = f"{MOODLE_BASE_URL}/login/token.php"
MOODLE_WS_URL = f"{MOODLE_BASE_URL}/webservice/rest/server.php"


def init_academic_db():
    """Inicializa la base de datos local para tareas, cursos y usuarios beta."""
    try:
        conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=20.0)
        cursor = conn.cursor()
        cursor.execute('PRAGMA journal_mode=WAL;')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS edu_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT,
                picture_url TEXT,
                google_id TEXT,
                role TEXT DEFAULT 'beta_tester',
                status TEXT DEFAULT 'active',
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS edu_courses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                course_id TEXT NOT NULL,
                name TEXT NOT NULL,
                shortname TEXT,
                source TEXT DEFAULT 'moodle',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user, course_id, source)
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS edu_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                course_id TEXT,
                course_name TEXT,
                task_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                due_date TEXT,
                due_timestamp INTEGER,
                status TEXT DEFAULT 'pending',
                source TEXT DEFAULT 'moodle',
                raw_url TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user, task_id, source)
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS edu_settings (
                user TEXT PRIMARY KEY,
                moodle_token TEXT,
                moodle_username TEXT,
                last_sync DATETIME
            );
        ''')
        cursor.execute('PRAGMA synchronous=NORMAL;')
        cursor.execute('PRAGMA busy_timeout=10000;')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_edu_tasks_user_status ON edu_tasks(user, status);')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_edu_courses_user_source ON edu_courses(user, source);')
        conn.commit()
        conn.close()
        logger.info("📦 [DORY EDU] Base de datos local academic.db verificada/inicializada con soporte de usuarios e índices.")
    except Exception as e:
        logger.error(f"Error inicializando academic.db: {e}")

# Asegurar DB al cargar el módulo
init_academic_db()


def get_google_redirect_uri():
    """Calcula dinámicamente la URL de redirección autorizada según el host."""
    configured = os.environ.get('GOOGLE_REDIRECT_URI')
    if configured:
        return configured
    host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or ''
    scheme = request.headers.get('X-Forwarded-Proto') or request.scheme or 'http'
    if 'dory.mx' in host:
        return 'https://edu.dory.mx/edu/auth/google/callback'
    return f"{scheme}://{host}/edu/auth/google/callback"


def edu_auth_required(f):
    """Decorador de seguridad para proteger rutas dentro de edu.dory.mx."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('edu_authenticated'):
            target_next = request.full_path if request.query_string else request.path
            return redirect(url_for('edu_bp.login', next=target_next))
        return f(*args, **kwargs)
    return decorated_function


def edu_admin_required(f):
    """Decorador de seguridad que restringe el acceso exclusivamente a Administradores."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('edu_authenticated'):
            return redirect(url_for('edu_bp.login', next=request.path))
        if session.get('edu_role') != 'admin':
            flash("Acceso restringido: Se requieren privilegios de Administrador para esa función.", "error")
            return redirect(url_for('edu_bp.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


import time as _time


@edu_bp.before_request
def sync_user_session():
    """Mantiene la sesión sincronizada con el estado y rol en academic.db (omitido en assets estáticos y con TTL de 60s)."""
    if _is_public_static_asset(request.path.lstrip('/')):
        return None
    if session.get('edu_authenticated') and session.get('edu_user'):
        now_ts = int(_time.time())
        last_sync_ts = session.get('_edu_sync_ts', 0)
        if now_ts - last_sync_ts < 60 and not request.path.startswith('/edu/admin'):
            return None
        email = session.get('edu_user')
        try:
            conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=5.0)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT role, status, full_name, picture_url FROM edu_users WHERE email = ?", (email,))
            row = c.fetchone()
            conn.close()
            session['_edu_sync_ts'] = now_ts
            if row:
                if row['status'] == 'suspended':
                    session.clear()
                    flash("Tu cuenta beta ha sido suspendida. Contacta al administrador.", "error")
                    return redirect(url_for('edu_bp.login'))
                session['edu_role'] = row['role']
                if row['full_name']:
                    session['edu_name'] = row['full_name']
                if row['picture_url']:
                    session['edu_picture'] = row['picture_url']
            elif email in EDU_ADMIN_EMAILS:
                session['edu_role'] = 'admin'
        except Exception:
            pass


# ==========================================
# RUTAS DE GOOGLE OAUTH 2.0
# ==========================================

@edu_bp.route('/auth/google/login', methods=['GET'])
def google_login():
    """Inicia el flujo de autenticación con Google OAuth 2.0."""
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    next_url = request.args.get('next') or url_for('edu_bp.dashboard')
    session['oauth_next'] = next_url

    redirect_uri = get_google_redirect_uri()
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': (
            'openid email profile '
            'https://www.googleapis.com/auth/classroom.courses.readonly '
            'https://www.googleapis.com/auth/classroom.coursework.me '
            'https://www.googleapis.com/auth/classroom.student-submissions.me.readonly '
            'https://www.googleapis.com/auth/classroom.rosters.readonly '
            'https://www.googleapis.com/auth/drive.readonly'
        ),
        'state': state,
        'prompt': 'select_account consent',
        'access_type': 'offline'
    }
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    logger.info(f"🌐 [GOOGLE OAUTH] Iniciando OAuth hacia Google (redirect_uri: {redirect_uri})")
    return redirect(auth_url)


@edu_bp.route('/auth/google/callback', methods=['GET'])
def google_callback():
    """Maneja el retorno de Google con el código de autorización y crea/actualiza el usuario."""
    error = request.args.get('error')
    if error:
        logger.warning(f"⚠️ [GOOGLE OAUTH] Cancelación devuelta por Google: {error}")
        flash(f"Inicio de sesión con Google cancelado o fallido: {error}", "error")
        return redirect(url_for('edu_bp.login'))

    expected_state = session.pop('oauth_state', None)
    received_state = request.args.get('state')
    if not expected_state or not received_state or not hmac.compare_digest(str(received_state), str(expected_state)):
        logger.warning("⚠️ [GOOGLE OAUTH] Rechazado por state CSRF inválido o ausente.")
        flash("Sesión de autenticación expirada o estado CSRF inválido. Intenta nuevamente.", "error")
        return redirect(url_for('edu_bp.login'))

    code = request.args.get('code')
    if not code:
        flash("No se recibió código de autorización de Google.", "error")
        return redirect(url_for('edu_bp.login'))

    redirect_uri = get_google_redirect_uri()

    try:
        # Intercambiar código por token de acceso
        token_resp = requests.post(
            'https://oauth2.googleapis.com/token',
            data={
                'code': code,
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=15
        )
        token_data = token_resp.json()
        if 'error' in token_data:
            err_desc = token_data.get('error_description', token_data['error'])
            logger.error(f"❌ [GOOGLE OAUTH] Error en canje de token: {err_desc}")
            flash(f"Error de Google OAuth: {err_desc}", "error")
            return redirect(url_for('edu_bp.login'))

        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in')
        expiry_date = int((_time.time() + int(expires_in)) * 1000) if expires_in else None

        # Obtener información del perfil
        profile_resp = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        profile = profile_resp.json()
        email = profile.get('email', '').strip().lower()
        full_name = profile.get('name') or profile.get('given_name') or email.split('@')[0]
        picture = profile.get('picture')
        google_id = profile.get('sub')

        if not email:
            flash("No fue posible obtener el correo electrónico de tu cuenta de Google.", "error")
            return redirect(url_for('edu_bp.login'))

        conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM edu_users WHERE email = ?", (email,))
        user_row = cur.fetchone()

        now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        is_first_login = False
        if user_row:
            if user_row['status'] == 'suspended':
                conn.close()
                logger.warning(f"⛔ [DORY EDU] Acceso bloqueado para usuario suspendido: '{email}'")
                flash("Tu cuenta beta ha sido suspendida. Contacta al administrador.", "error")
                return redirect(url_for('edu_bp.login'))

            cur.execute("""
                UPDATE edu_users 
                SET full_name = ?, picture_url = ?, google_id = ?, last_login = ?
                WHERE email = ?
            """, (full_name, picture, google_id, now_str, email))
            role = user_row['role']
        else:
            is_first_login = True
            role = 'admin' if email in EDU_ADMIN_EMAILS else 'beta_tester'
            cur.execute("""
                INSERT INTO edu_users (email, full_name, picture_url, google_id, role, status, last_login)
                VALUES (?, ?, ?, ?, ?, 'active', ?)
            """, (email, full_name, picture, google_id, role, now_str))
            logger.info(f"✨ [DORY EDU] Nuevo usuario beta registrado: '{email}' (Rol: {role})")

        conn.commit()
        conn.close()

        # Propagar automáticamente el token OAuth a TaskHub (local y nodo hermano HA) para sincronizar Google Classroom sin pasos extra
        for sso_url in _build_failover_urls('http://127.0.0.1:3001/auth/google/sso-token'):
            try:
                requests.post(
                    sso_url,
                    json={
                        'email': email,
                        'full_name': full_name,
                        'access_token': access_token,
                        'refresh_token': refresh_token,
                        'expiry_date': expiry_date,
                    },
                    headers={
                        'X-Gateway-Secret': EDU_GATEWAY_SECRET,
                        'X-Edu-User': email,
                        'X-Edu-Name': (full_name or '').encode('latin-1', errors='ignore').decode('latin-1'),
                        'X-Edu-Role': role,
                    },
                    timeout=2
                )
                logger.info(f"🔄 [DORY EDU -> TASKHUB] Token de Google Classroom vinculado en '{sso_url}' para '{email}'")
            except Exception:
                pass

        # Limpiar cualquier sesión previa en el navegador antes de establecer la nueva identidad
        next_url = session.get('oauth_next') or url_for('edu_bp.dashboard')
        session.clear()

        # Establecer sesión unificada Gateway + TaskHub + BecaFinder
        session['edu_authenticated'] = True
        session['edu_user'] = email
        session['edu_name'] = full_name
        session['edu_picture'] = picture
        session['edu_role'] = role
        session['edu_first_login'] = is_first_login

        # Permisos SSO: dev_authenticated SOLO para administradores
        session['dev_authenticated'] = (role == 'admin')
        session['edu_auth_tareas'] = True
        session['edu_user_tareas'] = email
        session['edu_auth_becas'] = True
        session['edu_user_becas'] = email

        logger.info(f"🔑 [DORY EDU] Sesión iniciada con éxito vía Google para '{email}' ({role})")

        if 'dev.dory.mx' in next_url or '/dev/sso-callback' in next_url:
            if role != 'admin':
                logger.warning(f"⛔ [DORY EDU] Usuario no-admin '{email}' intentó SSO hacia dev.dory.mx; redirigiendo a EDU dashboard.")
                return redirect(url_for('edu_bp.dashboard'))
            import hashlib as _hashlib
            ts = str(int(_time.time()))
            secret_key = (current_app.secret_key or os.environ.get('FLASK_SECRET_KEY') or '').strip()
            if not secret_key:
                logger.error("FLASK_SECRET_KEY ausente; no es posible firmar SSO hacia dev.dory.mx.")
                return redirect(url_for('edu_bp.dashboard'))
            payload = f"{email}|{ts}"
            sig = hmac.new(secret_key.encode('utf-8'), payload.encode('utf-8'), _hashlib.sha256).hexdigest()
            sep = '&' if '?' in next_url else '?'
            next_url = f"{next_url}{sep}email={urllib.parse.quote(email)}&ts={ts}&sig={sig}"
        return redirect(next_url)

    except Exception as e:
        logger.error(f"❌ Error en google_callback: {e}", exc_info=True)
        flash(f"Error procesando autenticación con Google: {str(e)}", "error")
        return redirect(url_for('edu_bp.login'))


# ==========================================
# RUTAS DE ADMINISTRACIÓN DE USUARIOS
# ==========================================

@edu_bp.route('/admin/users', methods=['GET'])
@edu_admin_required
def admin_users():
    """Panel de administración de usuarios beta y roles."""
    conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM edu_users ORDER BY id DESC")
    users = [dict(row) for row in cur.fetchall()]

    cur.execute("SELECT COUNT(*) FROM edu_users")
    total_users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM edu_users WHERE role = 'beta_tester' AND status = 'active'")
    active_beta = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM edu_users WHERE role = 'admin'")
    admins_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM edu_users WHERE status = 'suspended'")
    suspended_count = cur.fetchone()[0]

    conn.close()

    stats = {
        'total': total_users,
        'active_beta': active_beta,
        'admins': admins_count,
        'suspended': suspended_count
    }

    return render_template(
        'edu_admin_users.html',
        users=users,
        stats=stats
    )


@edu_bp.route('/admin/users/update-role', methods=['POST'])
@edu_admin_required
def admin_update_role():
    """Actualiza el rol de un usuario."""
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id')
    role = data.get('role', 'beta_tester')

    if not user_id or role not in ('admin', 'beta_tester', 'student', 'docente'):
        return jsonify({'success': False, 'error': 'Parámetros inválidos.'}), 400

    try:
        conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
        cur = conn.cursor()
        cur.execute("UPDATE edu_users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
        conn.close()
        logger.info(f"🛡️ [ADMIN] Rol de usuario ID {user_id} actualizado a '{role}'")
        return jsonify({'success': True, 'message': 'Rol actualizado correctamente.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@edu_bp.route('/admin/users/toggle-status', methods=['POST'])
@edu_admin_required
def admin_toggle_status():
    """Cambia el estado de un usuario (active / suspended)."""
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id')
    new_status = data.get('status', 'active')

    if not user_id or new_status not in ('active', 'suspended'):
        return jsonify({'success': False, 'error': 'Parámetros inválidos.'}), 400

    try:
        conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
        cur = conn.cursor()
        cur.execute("UPDATE edu_users SET status = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        conn.close()
        logger.info(f"🛡️ [ADMIN] Estado de usuario ID {user_id} cambiado a '{new_status}'")
        return jsonify({'success': True, 'message': f'Estado cambiado a {new_status}.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@edu_bp.route('/admin/users/delete', methods=['POST'])
@edu_admin_required
def admin_delete_user():
    """Elimina un usuario del sistema."""
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'success': False, 'error': 'ID de usuario requerido.'}), 400

    try:
        conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
        cur = conn.cursor()
        cur.execute("DELETE FROM edu_users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        logger.info(f"🗑️ [ADMIN] Usuario ID {user_id} eliminado")
        return jsonify({'success': True, 'message': 'Usuario eliminado.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@edu_bp.route('/admin/users/create', methods=['POST'])
@edu_admin_required
def admin_create_user():
    """Permite al admin dar de alta o pre-registrar un usuario."""
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()
    full_name = data.get('full_name', '').strip()
    role = data.get('role', 'beta_tester')

    if not email or '@' not in email:
        return jsonify({'success': False, 'error': 'Correo electrónico inválido.'}), 400

    try:
        conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
        cur = conn.cursor()
        now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("""
            INSERT INTO edu_users (email, full_name, role, status, created_at)
            VALUES (?, ?, ?, 'active', ?)
            ON CONFLICT(email) DO UPDATE SET role = excluded.role, full_name = COALESCE(excluded.full_name, edu_users.full_name)
        """, (email, full_name or None, role, now_str))
        conn.commit()
        conn.close()
        logger.info(f"✨ [ADMIN] Usuario beta '{email}' dado de alta manualmente como '{role}'")
        return jsonify({'success': True, 'message': 'Usuario registrado exitosamente.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@edu_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Pantalla y lógica de autenticación del Gateway Dory EDU."""
    if request.method == 'GET' and session.get('edu_authenticated') and request.args.get('switch') != '1':
        return redirect(url_for('edu_bp.dashboard'))

    error_msg = None
    next_url = request.args.get('next') or request.form.get('next') or url_for('edu_bp.dashboard')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if username == EDU_TEST_USER and _password_matches(password, EDU_TEST_PASS):
            session.clear()
            session['edu_authenticated'] = True
            session['edu_user'] = username
            session['edu_name'] = 'Master Dev'
            session['edu_role'] = 'admin'
            session['dev_authenticated'] = True
            session['edu_auth_tareas'] = True
            session['edu_user_tareas'] = username
            session['edu_auth_becas'] = True
            session['edu_user_becas'] = username
            logger.info(f"🔑 [DORY EDU] Sesión iniciada con éxito para '{username}' (Admin)")
            return redirect(next_url)
        else:
            logger.warning(f"⚠️ [DORY EDU] Intento fallido de login para '{username}'")
            error_msg = "Usuario o contraseña incorrectos. Verifique sus credenciales de prueba."

    return render_template('edu_login.html', error=error_msg, next_url=next_url)


@edu_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """Cierre de sesión seguro del Gateway."""
    # Limpiar tokens de Moodle para evitar fuga de datos al próximo usuario
    edu_user = session.get('edu_user')
    if edu_user:
        try:
            conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=5.0)
            cur = conn.cursor()
            cur.execute('UPDATE edu_settings SET moodle_token = NULL WHERE user = ?', (edu_user,))
            conn.commit()
            conn.close()
            logger.info(f"🧹 [DORY EDU] Token Moodle limpiado para '{edu_user}' al cerrar sesión.")
        except Exception as e:
            logger.warning(f"⚠️ Error limpiando token Moodle en logout: {e}")
    session.clear()
    logger.info("🔒 [DORY EDU] Sesión cerrada.")
    return redirect(url_for('edu_bp.login'))


@edu_bp.route('/', methods=['GET'])
@edu_auth_required
def dashboard():
    """Hub Central y conmutador de servicios académicos en edu.dory.mx."""
    current_user = session.get('edu_user')
    if not current_user:
        logger.warning("⚠️ [DORY EDU] Sesión sin edu_user en dashboard, redirigiendo a login.")
        return redirect(url_for('edu_bp.login'))
    user_name = session.get('edu_name', current_user)
    user_picture = session.get('edu_picture')
    user_role = session.get('edu_role', 'beta_tester')
    is_admin = (user_role == 'admin')
    first_login = session.pop('edu_first_login', False) or (request.args.get('tour') == '1')
    
    # Consultar estadísticas de tareas locales
    total_tasks = 0
    pending_tasks = 0
    last_sync = None
    try:
        conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM edu_tasks WHERE user = ?", (current_user,))
        total_tasks = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM edu_tasks WHERE user = ? AND status = 'pending'", (current_user,))
        pending_tasks = cursor.fetchone()[0]
        cursor.execute("SELECT last_sync FROM edu_settings WHERE user = ?", (current_user,))
        row = cursor.fetchone()
        if row and row[0]:
            last_sync = row[0]
        conn.close()
    except Exception:
        pass

    return render_template(
        'edu_dashboard.html',
        user=current_user,
        user_name=user_name,
        user_picture=user_picture,
        user_role=user_role,
        is_admin=is_admin,
        first_login=first_login,
        total_tasks=total_tasks,
        pending_tasks=pending_tasks,
        last_sync=last_sync
    )


_PROXY_SESSION = requests.Session()
_proxy_adapter = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=64, max_retries=1)
_PROXY_SESSION.mount('http://', _proxy_adapter)
_PROXY_SESSION.mount('https://', _proxy_adapter)


_LAST_AUTOSTART_TS = {}
_LAST_WOL_TS = {}

# Direcciones MAC físicas de las tarjetas Realtek 2.5GbE para Wake-on-LAN cruzado (.218 <-> .222)
HA_NODE_MACS = {
    '192.168.2.218': 'BC:FC:E7:50:8D:10',
    '192.168.2.222': 'BC:FC:E7:B3:26:70',
}


def send_wol_magic_packet(target_ip: str):
    """Envía un Magic Packet UDP (Wake-on-LAN) al nodo hermano si no responde en la LAN."""
    import socket
    import time
    mac = HA_NODE_MACS.get(target_ip)
    if not mac:
        return
    now = time.time()
    if now - _LAST_WOL_TS.get(target_ip, 0) < 30:
        return
    _LAST_WOL_TS[target_ip] = now
    try:
        clean_mac = mac.replace(':', '').replace('-', '')
        magic_payload = bytes.fromhex('FF' * 6 + clean_mac * 16)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for bcast in ('192.168.2.255', '255.255.255.255'):
                for port in (9, 7):
                    sock.sendto(magic_payload, (bcast, port))
        logger.info(f"⚡ [WAKE-ON-LAN] Magic Packet enviado a {target_ip} ({mac})")
    except Exception as ex:
        logger.warning(f"No se pudo enviar Magic Packet WoL a {target_ip}: {ex}")


def _trigger_microservice_autostart(target_url: str):
    """Dispara en segundo plano el microservicio local si se detecta caído al recibir tráfico."""
    if os.name != 'nt':
        return
    try:
        import subprocess
        import time
        now = time.time()
        if ':3001' in target_url or ':3011' in target_url:
            svc_key = 'taskhub'
            svc_dir = _resolve_existing_dir([
                r"C:\Users\QB_DESARROLLO\Desktop\03-Orquestador-y-Proyectos-Home\Proyectos_Home\Proyectos\Tareas\server",
                r"C:\Users\CarlosAlbertoAcevesC\Desktop\02-plataformas-activas\tareas\server",
            ], r"C:\Users\CarlosAlbertoAcevesC\Desktop\02-plataformas-activas\tareas\server")
        elif ':3012' in target_url or ':3002' in target_url:
            svc_key = 'becafinder'
            svc_dir = _resolve_existing_dir([
                r"C:\Users\QB_DESARROLLO\Desktop\03-Orquestador-y-Proyectos-Home\Proyectos_Home\Proyectos\Buscador_Academico\server",
                r"C:\Users\CarlosAlbertoAcevesC\Desktop\02-plataformas-activas\buscador-academico\server",
            ], r"C:\Users\CarlosAlbertoAcevesC\Desktop\02-plataformas-activas\buscador-academico\server")
        else:
            return

        if now - _LAST_AUTOSTART_TS.get(svc_key, 0) < 20:
            return
        _LAST_AUTOSTART_TS[svc_key] = now

        node_exe = r"C:\Program Files\nodejs\node.exe"
        if not os.path.exists(node_exe):
            node_exe = "node"
        if os.path.isdir(svc_dir):
            logger.info(f"🔄 [AUTO-HEAL] Iniciando microservicio '{svc_key}' bajo demanda en {svc_dir}...")
            subprocess.Popen(
                [node_exe, "src/index.js"],
                cwd=svc_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
            )
    except Exception as ex:
        logger.warning(f"No se pudo auto-iniciar microservicio para {target_url}: {ex}")


def _build_failover_urls(primary_url: str):
    """Construye la lista ordenada de candidatos (local primario -> local alterno -> nodo HA LAN)."""
    parsed = urllib.parse.urlparse(primary_url)
    path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    is_becas = ':3012' in primary_url or ':3002' in primary_url or '/becas' in parsed.path
    if is_becas:
        bases = [
            f"http://{parsed.netloc}",
            "http://127.0.0.1:3012",
            "http://192.168.2.218:3012",
            "http://192.168.2.222:3012",
        ]
    else:
        bases = [
            f"http://{parsed.netloc}",
            "http://127.0.0.1:3001",
            "http://127.0.0.1:3011",
            "http://192.168.2.218:3011",
            "http://192.168.2.222:3001",
        ]
    seen = set()
    urls = []
    for b in bases:
        if b not in seen:
            seen.add(b)
            urls.append(b + path_and_query)
    return urls


def proxy_to_microservice(target_url, extra_headers=None):
    """Reenvía peticiones HTTP al microservicio con Self-Healing y Failover Activo (.218 <-> .222)."""
    excluded_headers = {
        'accept-encoding', 'content-encoding', 'content-length', 'transfer-encoding',
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers', 'upgrade', 'host'
    }
    # Nunca reenviar headers de identidad/confianza enviados por el cliente: solo el Gateway los define.
    headers = {
        k: v for k, v in request.headers
        if k.lower() not in excluded_headers
        and not k.lower().startswith('x-edu-')
        and k.lower() != 'x-gateway-secret'
    }
    headers['Accept-Encoding'] = 'identity'
    
    # Inyectar headers adicionales de identidad del usuario
    if extra_headers:
        headers.update(extra_headers)
    # Prueba de origen para el microservicio (rechaza todo lo que no venga del Gateway)
    if EDU_GATEWAY_SECRET:
        headers['X-Gateway-Secret'] = EDU_GATEWAY_SECRET

    forward_cookies = {
        k: v for k, v in request.cookies.items()
        if k.lower() not in ('session', 'session_id', 'edu_session', 'remember_token')
    }
    req_body = request.get_data()
    candidate_urls = _build_failover_urls(target_url)
    last_error = None

    for idx, candidate in enumerate(candidate_urls):
        try:
            cand_headers = dict(headers)
            cand_netloc = urllib.parse.urlparse(candidate).netloc
            cand_headers['Host'] = cand_netloc
            timeout_sec = 30 if idx == 0 else 4
            resp = _PROXY_SESSION.request(
                method=request.method,
                url=candidate,
                headers=cand_headers,
                data=req_body,
                cookies=forward_cookies,
                params=request.args,
                allow_redirects=False,
                stream=True,
                timeout=timeout_sec
            )

            resp_headers = []
            for name, value in resp.raw.headers.items():
                if name.lower() not in excluded_headers and not name.lower().startswith('access-control-'):
                    resp_headers.append((name, value))

            if idx > 0:
                resp_headers.append(('X-Dory-HA-Failover', cand_netloc))

            # Inyectar headers CORS para permitir llamadas cruzadas autorizadas
            req_origin = request.headers.get('Origin')
            if req_origin and ('udg.mx' in req_origin or 'dory.mx' in req_origin or 'localhost' in req_origin or req_origin.startswith('chrome-extension://')):
                resp_headers.append(('Access-Control-Allow-Origin', req_origin))
                resp_headers.append(('Access-Control-Allow-Credentials', 'true'))
                resp_headers.append(('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With'))
                resp_headers.append(('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS'))

            return Response(
                resp.iter_content(chunk_size=8192),
                status=resp.status_code,
                headers=resp_headers
            )
        except requests.exceptions.RequestException as e:
            last_error = e
            if idx == 0:
                logger.warning(f"⚠️ [SELF-HEAL] Primario local {candidate} no disponible ({e}). Despertando proceso local y probando pool HA...")
                _trigger_microservice_autostart(target_url)
            else:
                cand_host = urllib.parse.urlparse(candidate).hostname
                if cand_host in HA_NODE_MACS:
                    send_wol_magic_packet(cand_host)

    logger.error(f"Error en reverse proxy tras probar pool HA para {target_url}: {last_error}")

    is_becas = ':3012' in target_url or ':3002' in target_url or '/becas' in request.path
    service_name = 'BecaFinder (Crush)' if is_becas else 'TaskHub (Nemo)'
    service_tag = '🐢 CRUSH' if is_becas else '⚡ NEMO'
    accent_color = '#06b6d4' if is_becas else '#6366f1'
    brand_logo = '/static/crush_logo.svg' if is_becas else '/static/nemo_logo.svg'

    # Si es llamada API o probe JSON, devolver JSON con 503
    accept_hdr = request.headers.get('Accept', '')
    if '/api/' in request.path or request.headers.get('X-Dory-Health-Probe') == '1' or (
        'application/json' in accept_hdr and 'text/html' not in accept_hdr
    ):
        return jsonify({
            'error': f'{service_name} se está iniciando o sincronizando automáticamente.',
            'service': service_name,
            'status': 503,
            'retry_after': 3
        }), 503

    # Devolver HTTP 503 (en lugar de 502) para que Cloudflare conserve nuestra página personalizada
    html_body = render_template(
        'error_page.html',
        page_title=f"Reconectando {service_name} — Dory.mx EDU",
        brand_name=service_name.split()[0],
        brand_logo=brand_logo,
        service_tag=service_tag,
        service_name=service_name,
        accent_color=accent_color,
        status_code=503,
        error_code_label='AUTO_HEAL_ACTIVE',
        error_title=f"Iniciando {service_name}...",
        error_message=(
            f"El túnel seguro de Dory.mx y el Gateway EDU están activos. "
            f"Estamos despertando el motor local de {service_name}; tu sesión se abrirá automáticamente en unos segundos."
        ),
        auto_retry=True,
        home_url='/edu',
        timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    )
    return Response(
        html_body,
        status=503,
        content_type='text/html; charset=utf-8',
        headers={'Retry-After': '3', 'Cache-Control': 'no-store, no-cache, must-revalidate'}
    )


# Contraseñas de acceso por servicio: SOLO desde .env. Sin variable definida, ese acceso queda deshabilitado.
EDU_BECAS_USERS = {
    'carlos': os.environ.get('EDU_BECAS_PASS', ''),
    '225361954': os.environ.get('EDU_BECAS_PASS', ''),
    'admin': os.environ.get('EDU_ADMIN_PASS', '')
}

def handle_becas_request(subpath="", prefix="/becas"):
    """Manejo de acceso independiente y reverse proxy para BecaFinder."""
    clean_subpath = subpath.strip('/')
    
    # 1. Rutas de Login y Logout para BecaFinder
    if clean_subpath in ('login', 'login/'):
        error_msg = None
        next_url = request.args.get('next') or request.form.get('next') or f"{prefix}"
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            expected_pass = EDU_BECAS_USERS.get(username)
            if _password_matches(password, expected_pass):
                session.clear()
                session['edu_auth_becas'] = True
                session['edu_user_becas'] = username
                session['edu_role'] = 'admin'
                logger.info(f"🎓 [BECAS] Sesión iniciada con éxito para '{username}'")
                return redirect(next_url)
            else:
                error_msg = "Credenciales incorrectas para BecaFinder. Verifique su código o usuario."
                
        return render_template(
            'edu_login.html',
            service_id='becas',
            service_brand='BecaFinder',
            service_title='Acceso a BecaFinder (Crush)',
            service_tag='🐢 CRUSH',
            service_desc='Control de acceso independiente para el <strong>Buscador Académico y Convocatorias UDG</strong>',
            accent_color='#06b6d4',
            btn_text='Ingresar a BecaFinder (Crush)',
            error=error_msg,
            form_action=f"{prefix}/login",
            next_url=next_url
        )
        
    if clean_subpath in ('logout', 'logout/'):
        session.clear()
        return redirect(f"{prefix}/login")
        
    # 2. Verificación de Autenticación
    is_static_asset = _is_public_static_asset(clean_subpath)

    # Si ya cuenta con sesión Gateway EDU, otorgar sesión Becas automáticamente
    if session.get('edu_authenticated') and session.get('edu_user'):
        session['edu_auth_becas'] = True
        session['edu_user_becas'] = session.get('edu_user')

    edu_user = (session.get('edu_user') or session.get('edu_user_becas') or '').strip()

    if not is_static_asset and (not session.get('edu_auth_becas') or not edu_user):
        if clean_subpath.startswith('api'):
            return jsonify({
                'error': 'Autenticación requerida para BecaFinder',
                'login_url': f"{prefix}/login"
            }), 401
        current_target = request.full_path if request.query_string else request.path
        return redirect(f"{prefix}/login?next={urllib.parse.quote(current_target)}")
        
    # 3. Microservicio BecaFinder en http://127.0.0.1:3012
    # Inyectar identidad del usuario autenticado para perfiles multi-usuario
    if edu_user.lower() in ('carlos', '225361954', 'admin', 'carlos@dory.mx', 'carlosalbertoacevesc@gmail.com'):
        edu_user = 'carlos.aceves6195@alumnos.udg.mx'
    edu_email = edu_user
    edu_name = session.get('edu_name', '') or ('CARLOS ALBERTO ACEVES CABRERA' if edu_user == 'carlos.aceves6195@alumnos.udg.mx' else '')
    edu_name_safe = (edu_name or '').encode('latin-1', errors='ignore').decode('latin-1')
    edu_role = session.get('edu_role', 'beta_tester')
    identity_headers = {
        'X-Edu-User': edu_user,
        'X-Edu-Email': edu_email,
        'X-Edu-Name': edu_name_safe,
        'X-Edu-Role': edu_role,
    }
    beca_port = os.environ.get('BECAFINDER_PORT', '3012')
    target_url = f"http://127.0.0.1:{beca_port}/becas/{subpath.lstrip('/')}" if subpath.strip('/') else f"http://127.0.0.1:{beca_port}/becas/"
    return proxy_to_microservice(target_url, extra_headers=identity_headers)


EDU_TAREAS_USERS = {
    'carlos': os.environ.get('EDU_TAREAS_PASS', ''),
    '225361954': os.environ.get('EDU_TAREAS_PASS', ''),
    'admin': os.environ.get('EDU_ADMIN_PASS', '')
}

def handle_tareas_request(subpath="", prefix="/tareas"):
    """Manejo de acceso independiente y reverse proxy para TaskHub."""
    clean_subpath = subpath.strip('/')
    
    # 1. Rutas de Login y Logout para TaskHub
    if clean_subpath in ('login', 'login/'):
        error_msg = None
        next_url = request.args.get('next') or request.form.get('next') or f"{prefix}"
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            expected_pass = EDU_TAREAS_USERS.get(username)
            if _password_matches(password, expected_pass):
                session.clear()
                session['edu_auth_tareas'] = True
                session['edu_user_tareas'] = username
                session['edu_role'] = 'admin'
                logger.info(f"⚡ [TAREAS] Sesión iniciada con éxito para '{username}'")
                return redirect(next_url)
            else:
                error_msg = "Credenciales incorrectas para TaskHub. Verifique su código o usuario."
                
        return render_template(
            'edu_login.html',
            service_id='tareas',
            service_brand='TaskHub',
            service_title='Acceso a TaskHub (Nemo)',
            service_tag='⚡ NEMO',
            service_desc='Control de acceso independiente para <strong>Gestor de Tareas, Classroom y Moodle</strong>',
            accent_color='#6366f1',
            btn_text='Ingresar a TaskHub (Nemo)',
            error=error_msg,
            form_action=f"{prefix}/login",
            next_url=next_url
        )
        
    if clean_subpath in ('logout', 'logout/'):
        session.clear()
        return redirect(f"{prefix}/login")
        
    # 2. Verificación de Autenticación
    is_static_asset = _is_public_static_asset(clean_subpath)
    is_oauth_callback = clean_subpath == 'auth/google/callback'
    # Bookmarklet 1-Clic: permite sincronizar cuando se envía con token personal (query param o header)
    has_sync_token = bool(request.args.get('token') or request.headers.get('x-sync-token'))
    is_tokenized_sync = clean_subpath in ('api/moodle/sync-payload', 'sync-payload') and has_sync_token

    # Manejar preflight CORS directo
    if request.method == 'OPTIONS':
        resp = Response('', status=204)
        req_origin = request.headers.get('Origin', '*')
        resp.headers['Access-Control-Allow-Origin'] = req_origin
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-Sync-Token'
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        return resp

    # Si ya cuenta con sesión Gateway EDU, otorgar sesión Tareas automáticamente
    if session.get('edu_authenticated') and session.get('edu_user'):
        session['edu_auth_tareas'] = True
        session['edu_user_tareas'] = session.get('edu_user')

    edu_user = (session.get('edu_user') or session.get('edu_user_tareas') or '').strip()

    if not is_static_asset and not is_oauth_callback and not is_tokenized_sync and (not session.get('edu_auth_tareas') or not edu_user):
        if clean_subpath.startswith('api') or clean_subpath.startswith('auth'):
            return jsonify({
                'error': 'Autenticación requerida para TaskHub',
                'login_url': f"{prefix}/login"
            }), 401
        current_target = request.full_path if request.query_string else request.path
        return redirect(f"{prefix}/login?next={urllib.parse.quote(current_target)}")
        
    # 3. Microservicio TaskHub
    # Inyectar identidad del usuario autenticado para aislamiento de datos
    if edu_user.lower() in ('carlos', '225361954', 'admin', 'carlos@dory.mx', 'carlosalbertoacevesc@gmail.com'):
        edu_user = 'carlos.aceves6195@alumnos.udg.mx'
    edu_email = edu_user
    edu_name = session.get('edu_name', '') or ('CARLOS ALBERTO ACEVES CABRERA' if edu_user == 'carlos.aceves6195@alumnos.udg.mx' else '')
    edu_name_safe = (edu_name or '').encode('latin-1', errors='ignore').decode('latin-1')
    edu_role = session.get('edu_role', 'beta_tester')
    identity_headers = {
        'X-Edu-User': edu_user,
        'X-Edu-Email': edu_email,
        'X-Edu-Name': edu_name_safe,
        'X-Edu-Role': edu_role,
    }
    taskhub_port = os.environ.get('TASKHUB_PORT', '3001')
    target_url = f"http://127.0.0.1:{taskhub_port}/tareas/{subpath.lstrip('/')}" if subpath.strip('/') else f"http://127.0.0.1:{taskhub_port}/tareas/"
    return proxy_to_microservice(target_url, extra_headers=identity_headers)


# Blueprint routes for /edu/becas and /edu/tareas (with and without trailing slash)
@edu_bp.route('/becas', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@edu_bp.route('/becas/', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@edu_bp.route('/becas/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def bp_becas(subpath):
    return handle_becas_request(subpath, prefix='/edu/becas')


@edu_bp.route('/tareas', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@edu_bp.route('/tareas/', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@edu_bp.route('/tareas/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def bp_tareas(subpath):
    return handle_tareas_request(subpath, prefix='/edu/tareas')


def handle_splunk_request(subpath="", prefix="/edu/splunk"):
    """Servicio y enrutador estático/SPA para SplunkSim."""
    clean_subpath = subpath.strip('/')
    is_static = (
        clean_subpath.startswith('assets/') or
        clean_subpath.endswith(('.js', '.css', '.svg', '.png', '.ico', '.woff', '.woff2', '.json', '.map'))
    )

    # Permitir assets estáticos sin sesión; requerir autenticación EDU para acceder a la app
    if not is_static and not session.get('edu_authenticated'):
        current_target = request.full_path if request.query_string else request.path
        return redirect(url_for('edu_bp.login', next=current_target))

    if not clean_subpath:
        return send_from_directory(SPLUNKSIM_DIST_DIR, 'index.html')

    file_path = os.path.join(SPLUNKSIM_DIST_DIR, clean_subpath)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return send_from_directory(SPLUNKSIM_DIST_DIR, clean_subpath)

    # Fallback para SPA routing
    return send_from_directory(SPLUNKSIM_DIST_DIR, 'index.html')


@edu_bp.route('/splunk', defaults={'subpath': ''}, methods=['GET'], strict_slashes=False)
@edu_bp.route('/splunk/', defaults={'subpath': ''}, methods=['GET'], strict_slashes=False)
@edu_bp.route('/splunk/<path:subpath>', methods=['GET'], strict_slashes=False)
def bp_splunk(subpath):
    return handle_splunk_request(subpath, prefix='/edu/splunk')


def handle_juegos_request(subpath="", prefix="/edu/juegos"):
    """Servicio y enrutador público para el Portal de Juegos Educativos CUGDL (Libre Acceso)."""
    clean_subpath = subpath.strip('/')

    if not clean_subpath:
        return send_from_directory(CUGDL_GAMES_DIR, 'index.html')

    file_path = os.path.join(CUGDL_GAMES_DIR, clean_subpath)

    # Si es un directorio, forzar trailing slash para que las rutas relativas de scripts y assets resuelvan correctamente
    if os.path.isdir(file_path):
        if not request.path.endswith('/'):
            target_url = request.path + '/'
            if request.query_string:
                target_url += '?' + request.query_string.decode('utf-8')
            return redirect(target_url, code=302)
        return send_from_directory(file_path, 'index.html')

    if os.path.isfile(file_path):
        directory = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        return send_from_directory(directory, filename)

    # Si no existe, devolver 404
    abort(404)


@edu_bp.route('/juegos', defaults={'subpath': ''}, methods=['GET'], strict_slashes=False)
@edu_bp.route('/juegos/', defaults={'subpath': ''}, methods=['GET'], strict_slashes=False)
@edu_bp.route('/juegos/<path:subpath>', methods=['GET'], strict_slashes=False)
def bp_juegos(subpath):
    return handle_juegos_request(subpath, prefix='/edu/juegos')


@edu_bp.route('/api/moodle/test-token', methods=['POST'])
@edu_auth_required
def test_moodle_token():
    """Prueba interactiva del endpoint oficial de Moodle Mobile en mi.cugdl.udg.mx."""
    data = request.get_json(silent=True) or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'error': 'Proporcione código/usuario y contraseña.'}), 400

    try:
        res = requests.post(
            MOODLE_TOKEN_URL,
            data={
                'username': username,
                'password': password,
                'service': 'moodle_mobile_app'
            },
            timeout=10
        )
        res_data = res.json()

        if 'token' in res_data:
            masked_token = res_data['token'][:6] + "..." + res_data['token'][-4:]
            
            # Guardar token en configuración para no requerir contraseña siempre
            current_user = session.get('edu_user')
            if not current_user:
                return jsonify({'success': False, 'error': 'Sesión inválida. Inicie sesión nuevamente.'}), 401
            conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
            cur = conn.cursor()
            cur.execute('''
                INSERT INTO edu_settings (user, moodle_token, moodle_username, last_sync)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user) DO UPDATE SET
                    moodle_token=excluded.moodle_token,
                    moodle_username=excluded.moodle_username,
                    last_sync=CURRENT_TIMESTAMP
            ''', (current_user, res_data['token'], username))
            conn.commit()
            conn.close()

            return jsonify({
                'success': True,
                'message': '¡Autenticación exitosa con Moodle CUGDL!',
                'token_masked': masked_token,
                'full_token': res_data['token'],
                'has_private_token': 'privatetoken' in res_data
            }), 200
        elif 'error' in res_data:
            return jsonify({
                'success': False,
                'error': res_data.get('error', 'Error devuelto por Moodle'),
                'errorcode': res_data.get('errorcode', 'unknown')
            }), 401
        else:
            return jsonify({'success': False, 'raw': res_data}), 500

    except requests.exceptions.RequestException as e:
        logger.error(f"Error conectando a Moodle CUGDL: {e}")
        return jsonify({'success': False, 'error': f'Fallo de conexión con servidor Moodle: {str(e)}'}), 502


@edu_bp.route('/api/moodle/sync', methods=['POST'])
@edu_auth_required
def sync_moodle():
    """Sincroniza en 1 clic materias y tareas desde Moodle CUGDL y las persiste en academic.db."""
    current_user = session.get('edu_user')
    if not current_user:
        return jsonify({'success': False, 'error': 'Sesión inválida. Inicie sesión nuevamente.'}), 401
    data = request.get_json(silent=True) or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')

    token = None
    conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
    cur = conn.cursor()

    # Si proporcionó credenciales, solicitar token fresco
    if username and password:
        try:
            res = requests.post(MOODLE_TOKEN_URL, data={'username': username, 'password': password, 'service': 'moodle_mobile_app'}, timeout=10)
            t_data = res.json()
            if 'token' in t_data:
                token = t_data['token']
                cur.execute('''
                    INSERT INTO edu_settings (user, moodle_token, moodle_username, last_sync)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(user) DO UPDATE SET moodle_token=?, moodle_username=?, last_sync=CURRENT_TIMESTAMP
                ''', (current_user, token, username, token, username))
                conn.commit()
            else:
                conn.close()
                return jsonify({'success': False, 'error': t_data.get('error', 'Credenciales inválidas en Moodle')}), 401
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'error': f'Error solicitando token: {e}'}), 502
    else:
        # Intentar leer token guardado
        cur.execute('SELECT moodle_token, moodle_username FROM edu_settings WHERE user = ?', (current_user,))
        row = cur.fetchone()
        if row and row[0]:
            token = row[0]
            username = row[1] or 'Estudiante'
        else:
            conn.close()
            return jsonify({'success': False, 'error': 'No hay sesión de Moodle guardada. Ingrese Código y Contraseña.'}), 400

    # Ejecutar llamadas WebServices de Moodle
    synced_tasks_count = 0
    synced_courses_count = 0

    try:
        # 1. Obtener información de usuario (Site Info)
        site_info_res = requests.get(
            MOODLE_WS_URL,
            params={
                'wstoken': token,
                'wsfunction': 'core_webservice_get_site_info',
                'moodlewsrestformat': 'json'
            },
            timeout=10
        ).json()

        moodle_userid = site_info_res.get('userid')
        fullname = site_info_res.get('fullname', username)

        # 2. Obtener materias matriculadas
        courses_data = []
        if moodle_userid:
            courses_res = requests.get(
                MOODLE_WS_URL,
                params={
                    'wstoken': token,
                    'wsfunction': 'core_enrol_get_users_courses',
                    'userid': moodle_userid,
                    'moodlewsrestformat': 'json'
                },
                timeout=12
            ).json()

            if isinstance(courses_res, list):
                courses_data = courses_res
                for c in courses_res:
                    c_id = str(c.get('id', ''))
                    c_name = c.get('fullname') or c.get('shortname') or 'Materia'
                    c_short = c.get('shortname', '')
                    cur.execute('''
                        INSERT INTO edu_courses (user, course_id, name, shortname, source)
                        VALUES (?, ?, ?, ?, 'moodle')
                        ON CONFLICT(user, course_id, source) DO UPDATE SET name=excluded.name, shortname=excluded.shortname
                    ''', (current_user, c_id, c_name, c_short))
                synced_courses_count = len(courses_res)

        # 3. Obtener Tareas activas (mod_assign_get_assignments)
        assign_res = requests.get(
            MOODLE_WS_URL,
            params={
                'wstoken': token,
                'wsfunction': 'mod_assign_get_assignments',
                'moodlewsrestformat': 'json'
            },
            timeout=15
        ).json()

        courses_with_assignments = assign_res.get('courses', [])
        for c in courses_with_assignments:
            c_name = c.get('fullname') or c.get('shortname') or 'Curso'
            c_id = str(c.get('id', ''))

            for a in c.get('assignments', []):
                task_id = str(a.get('id', ''))
                title = a.get('name', 'Tarea sin título')
                desc = a.get('intro', '')
                duedate_unix = a.get('duedate', 0)
                duedate_str = datetime.fromtimestamp(duedate_unix).strftime('%Y-%m-%d %H:%M') if duedate_unix > 0 else 'Sin fecha límite'

                cur.execute('''
                    INSERT INTO edu_tasks (user, course_id, course_name, task_id, title, description, due_date, due_timestamp, status, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'moodle')
                    ON CONFLICT(user, task_id, source) DO UPDATE SET
                        course_name=excluded.course_name,
                        title=excluded.title,
                        description=excluded.description,
                        due_date=excluded.due_date,
                        due_timestamp=excluded.due_timestamp,
                        updated_at=CURRENT_TIMESTAMP
                ''', (current_user, c_id, c_name, task_id, title, desc, duedate_str, duedate_unix))
                synced_tasks_count += 1

        # Actualizar timestamp de sincronización
        cur.execute('UPDATE edu_settings SET last_sync = CURRENT_TIMESTAMP WHERE user = ?', (current_user,))
        conn.commit()
        conn.close()

        logger.info(f"✅ [DORY EDU] Sincronización exitosa: {synced_courses_count} materias, {synced_tasks_count} tareas.")
        return jsonify({
            'success': True,
            'message': f'Sincronización completa: {synced_courses_count} materias y {synced_tasks_count} tareas actualizadas.',
            'courses_count': synced_courses_count,
            'tasks_count': synced_tasks_count,
            'fullname': fullname
        }), 200

    except Exception as e:
        conn.close()
        logger.error(f"Error procesando datos de Moodle: {e}")
        return jsonify({'success': False, 'error': f'Error en sincronización WebService: {str(e)}'}), 502


@edu_bp.route('/api/moodle/sync-cookie', methods=['POST'])
@edu_auth_required
def sync_moodle_cookie():
    """Sincroniza materias y tareas utilizando una cookie de sesión MoodleSession."""
    current_user = session.get('edu_user')
    if not current_user:
        return jsonify({'success': False, 'error': 'Sesión inválida. Inicie sesión nuevamente.'}), 401
    data = request.get_json(silent=True) or request.form
    moodle_cookie = data.get('moodle_session', '').strip()

    if not moodle_cookie:
        return jsonify({'success': False, 'error': 'Proporcione el valor de la cookie MoodleSession.'}), 400

    result = sync_moodle_with_session_cookie(moodle_cookie, ACADEMIC_DB_PATH, current_user)
    status_code = 200 if result.get('success') else 400
    return jsonify(result), status_code


@edu_bp.route('/api/moodle/sync-google-start', methods=['POST'])
@edu_auth_required
def sync_google_start():
    """Inicia el asistente interactivo Playwright para inicio con Google OAuth (@alumnos.udg.mx)."""
    current_user = session.get('edu_user')
    if not current_user:
        return jsonify({'success': False, 'error': 'Sesión inválida. Inicie sesión nuevamente.'}), 401
    res = start_google_oauth_sync(current_user, ACADEMIC_DB_PATH)
    return jsonify(res), 200


@edu_bp.route('/api/moodle/sync-google-status', methods=['GET'])
@edu_auth_required
def sync_google_status():
    """Consulta el estado del asistente de Google OAuth."""
    current_user = session.get('edu_user')
    if not current_user:
        return jsonify({'success': False, 'error': 'Sesión inválida.'}), 401
    st = get_google_sync_status(current_user)
    return jsonify(st), 200


@edu_bp.route('/api/task/toggle-status', methods=['POST'])
@edu_auth_required
def toggle_task_status():
    """Permite marcar una tarea como completada o pendiente."""
    current_user = session.get('edu_user')
    if not current_user:
        return jsonify({'success': False, 'error': 'Sesión inválida.'}), 401
    data = request.get_json(silent=True) or request.form
    task_id = data.get('task_id')
    new_status = data.get('status', 'completed')

    if not task_id:
        return jsonify({'success': False, 'error': 'ID de tarea requerido'}), 400

    try:
        conn = sqlite3.connect(ACADEMIC_DB_PATH, timeout=10.0)
        cur = conn.cursor()
        cur.execute(
            'UPDATE edu_tasks SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE user = ? AND (task_id = ? OR id = ?)',
            (new_status, current_user, str(task_id), str(task_id))
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'task_id': task_id, 'new_status': new_status}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@edu_bp.route('/error-preview')
def edu_error_preview():
    """Vista interactiva de prueba para inspeccionar las páginas de error y auto-reconexión."""
    if request.headers.get('X-Dory-Health-Probe') == '1':
        if request.args.get('ready') == '1':
            return jsonify({'status': 'ready'}), 200
        return jsonify({'status': 'simulating_reconnect'}), 503

    svc = (request.args.get('service') or 'nemo').lower()
    code = int(request.args.get('code') or 503)

    if svc == 'crush':
        brand_name = 'BecaFinder'
        service_name = 'BecaFinder (Crush)'
        service_tag = '🐢 CRUSH'
        accent_color = '#06b6d4'
        brand_logo = '/static/crush_logo.svg'
        home_url = '/edu/becas/'
    elif svc == 'edu':
        brand_name = 'Dory EDU'
        service_name = 'Dory EDU'
        service_tag = '🎓 EDU'
        accent_color = '#0284C7'
        brand_logo = '/static/Favicon Gabo 512x512.png'
        home_url = '/edu/'
    else:
        svc = 'nemo'
        brand_name = 'TaskHub'
        service_name = 'TaskHub (Nemo)'
        service_tag = '⚡ NEMO'
        accent_color = '#6366f1'
        brand_logo = '/static/nemo_logo.svg'
        home_url = '/edu/tareas/'

    scenarios = {
        503: (
            'AUTO_HEAL_ACTIVE',
            f'Iniciando {service_name}...',
            f'El túnel seguro de Dory.mx y el Gateway EDU están activos. Estamos despertando el motor local de {service_name}; tu sesión se abrirá automáticamente en unos segundos.',
            True,
            'REINICIANDO',
        ),
        404: (
            'ROUTE_NOT_FOUND',
            f'Ruta no encontrada en {service_name}',
            f"La dirección solicitada dentro de {service_name} no existe o fue movida dentro del ecosistema Dory.",
            False,
            'NO ENCONTRADO',
        ),
        403: (
            'ACCESS_RESTRICTED',
            'Acceso restringido por Dory Security Shield',
            'No cuentas con permisos suficientes para acceder a este recurso o la sesión de seguridad ha expirado.',
            False,
            'RESTRINGIDO',
        ),
        500: (
            'INTERNAL_ENGINE_ERROR',
            f'Incidencia interna en {service_name}',
            'Se produjo una excepción inesperada al procesar tu solicitud. Nuestro sistema de monitoreo ya la registró.',
            False,
            'EXCEPCIÓN',
        ),
    }
    code_label, title, message, auto_retry, node_state_text = scenarios.get(code, scenarios[503])

    html_body = render_template(
        'error_page.html',
        page_title=f"[Preview {code}] {service_name} — Dory.mx EDU",
        brand_name=brand_name,
        brand_logo=brand_logo,
        service_tag=service_tag,
        service_name=service_name,
        accent_color=accent_color,
        status_code=code,
        error_code_label=code_label,
        error_title=title,
        error_message=message,
        auto_retry=auto_retry,
        node_state_text=node_state_text,
        home_url=home_url,
        preview_mode=True,
        preview_service=svc,
        preview_code=code,
        timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    )
    return Response(html_body, status=200, content_type='text/html; charset=utf-8')


