"""
Flask app using HuggingFace Inference API instead of local models.
Ultra-lightweight - no heavy ML libraries loaded locally.
"""
import os
import sys
import site

_USER_SITE = r"C:\Users\CarlosAlbertoAcevesC\AppData\Roaming\Python\Python314\site-packages"
if os.path.isdir(_USER_SITE) and _USER_SITE not in sys.path:
    site.addsitedir(_USER_SITE)

_LIVE_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dory_gateway_live.log")
if sys.stdout is None:
    sys.stdout = open(_LIVE_LOG, "a", encoding="utf-8", buffering=1, errors="replace")
elif hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr is None:
    sys.stderr = open(_LIVE_LOG, "a", encoding="utf-8", buffering=1, errors="replace")
elif hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import re
import time
import hmac
import secrets
import logging
import sqlite3
import json
from datetime import datetime
from contextlib import closing
from flask import Flask, request, render_template, jsonify, session, redirect, url_for, send_from_directory
from functools import wraps, lru_cache
import requests
from urllib.parse import urlparse, quote

# Cargar .env ANTES de leer cualquier variable (antes FLASK_SECRET_KEY se leía antes de que
# edu_portal ejecutara load_dotenv, por lo que siempre se usaba el valor por defecto del código).
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
except ImportError:
    pass

# --- Basic Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# --- Flask App ---
import gzip as _gzip

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 604800  # 7 days cache for static files
_flask_secret = os.environ.get('FLASK_SECRET_KEY')
if not _flask_secret:
    # Sin valor por defecto en el código (estaba publicado en el repo y permitía forjar sesiones).
    _flask_secret = secrets.token_hex(32)
    logger.warning("FLASK_SECRET_KEY no definido: se generó uno aleatorio (las sesiones se invalidan al reiniciar).")
app.secret_key = _flask_secret
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
if os.environ.get('SESSION_COOKIE_SECURE') == '1':
    app.config['SESSION_COOKIE_SECURE'] = True

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

_COMPRESSIBLE_MIMETYPES = {
    'text/html', 'text/css', 'text/plain', 'text/xml', 'text/javascript',
    'application/json', 'application/javascript', 'application/xml', 'image/svg+xml'
}


@app.after_request
def optimize_http_response(response):
    """Apply Gzip compression on text/JSON/HTML payloads and Cache-Control on static assets."""
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')

    if request.path.startswith('/static/'):
        response.headers.setdefault('Cache-Control', 'public, max-age=604800')

    # Skip compression if streaming, already encoded, error status, or small body
    if (
        response.direct_passthrough
        or response.status_code < 200
        or response.status_code >= 300
        or 'Content-Encoding' in response.headers
        or 'gzip' not in request.headers.get('Accept-Encoding', '').lower()
    ):
        return response

    mimetype = (response.mimetype or '').lower()
    if mimetype in _COMPRESSIBLE_MIMETYPES:
        data = response.get_data()
        if len(data) >= 512:
            compressed = _gzip.compress(data, compresslevel=5)
            if len(compressed) < len(data):
                response.set_data(compressed)
                response.headers['Content-Encoding'] = 'gzip'
                response.headers['Content-Length'] = str(len(compressed))
                vary = response.headers.get('Vary', '')
                if 'accept-encoding' not in vary.lower():
                    response.headers['Vary'] = f"{vary}, Accept-Encoding".lstrip(', ')
    return response


# --- Dory EDU Hub & Gateway Registration ---
from edu_portal import edu_bp, handle_becas_request, handle_tareas_request, handle_splunk_request, handle_juegos_request
from dev_workbench import dev_wb_bp, get_allowed_dev_users as _get_allowed_dev_users, is_dev_authorized as _is_dev_portfolio_authorized
app.register_blueprint(edu_bp, url_prefix='/edu')
app.register_blueprint(dev_wb_bp)

# Direct microservice proxy routes for edu.dory.mx and dory.mx
@app.route('/becas', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@app.route('/becas/', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@app.route('/becas/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def direct_becas_proxy(subpath):
    return handle_becas_request(subpath, prefix='/becas')

@app.route('/tareas', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@app.route('/tareas/', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@app.route('/tareas/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def direct_tareas_proxy(subpath):
    return handle_tareas_request(subpath, prefix='/tareas')

@app.route('/splunk', defaults={'subpath': ''}, methods=['GET'], strict_slashes=False)
@app.route('/splunk/', defaults={'subpath': ''}, methods=['GET'], strict_slashes=False)
@app.route('/splunk/<path:subpath>', methods=['GET'], strict_slashes=False)
def direct_splunk_proxy(subpath):
    return handle_splunk_request(subpath, prefix='/splunk')

@app.route('/juegos', defaults={'subpath': ''}, methods=['GET'], strict_slashes=False)
@app.route('/juegos/', defaults={'subpath': ''}, methods=['GET'], strict_slashes=False)
@app.route('/juegos/<path:subpath>', methods=['GET'], strict_slashes=False)
def direct_juegos_proxy(subpath):
    return handle_juegos_request(subpath, prefix='/juegos')

# Transparent API fallbacks for BecaFinder
@app.route('/api/becas', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@app.route('/api/becas/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def fallback_api_becas(subpath):
    target = f"api/becas/{subpath}" if subpath else "api/becas"
    return handle_becas_request(target, prefix='/becas')

@app.route('/api/profile', methods=['GET', 'PUT', 'OPTIONS'], strict_slashes=False)
def fallback_api_profile():
    return handle_becas_request("api/profile", prefix='/becas')

@app.route('/api/kardex', defaults={'subpath': ''}, methods=['GET', 'POST', 'OPTIONS'], strict_slashes=False)
@app.route('/api/kardex/<path:subpath>', methods=['GET', 'POST', 'OPTIONS'], strict_slashes=False)
def fallback_api_kardex(subpath):
    target = f"api/kardex/{subpath}" if subpath else "api/kardex"
    return handle_becas_request(target, prefix='/becas')

@app.route('/api/careerpath', methods=['GET', 'OPTIONS'], strict_slashes=False)
def fallback_api_careerpath():
    return handle_becas_request("api/careerpath", prefix='/becas')

@app.route('/api/aplicaciones', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], strict_slashes=False)
@app.route('/api/aplicaciones/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], strict_slashes=False)
def fallback_api_aplicaciones(subpath):
    target = f"api/aplicaciones/{subpath}" if subpath else "api/aplicaciones"
    return handle_becas_request(target, prefix='/becas')

# Transparent API fallbacks for TaskHub
@app.route('/api/tasks', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@app.route('/api/tasks/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def fallback_api_tasks(subpath):
    target = f"api/tasks/{subpath}" if subpath else "api/tasks"
    return handle_tareas_request(target, prefix='/tareas')

@app.route('/api/courses', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@app.route('/api/courses/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def fallback_api_courses(subpath):
    target = f"api/courses/{subpath}" if subpath else "api/courses"
    return handle_tareas_request(target, prefix='/tareas')

@app.route('/login', methods=['GET', 'POST'])
def root_login():
    return redirect(url_for('edu_bp.login', **request.args))

@app.route('/auth/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def fallback_api_auth(subpath):
    clean = subpath.strip('/')
    if clean == 'google/login' or clean.startswith('google/login/'):
        return redirect(url_for('edu_bp.google_login', **request.args))
    if clean == 'google/callback' or clean.startswith('google/callback/'):
        return redirect(url_for('edu_bp.google_callback', **request.args))
    target = f"auth/{subpath}"
    return handle_tareas_request(target, prefix='/tareas')




@app.before_request
def handle_subdomain_routing():
    """Detecta peticiones desde subdominios dev.dory.mx y edu.dory.mx y las enruta inteligentemente."""
    host = request.host.lower()
    if host.startswith('dev.') or host.startswith('portfolio.'):
        path = request.path
        if path.startswith('/static/') or path in ('/favicon.ico', '/robots.txt', '/dev/login', '/dev/logout', '/dev/sso-callback'):
            return None
        if path == '/login':
            return redirect('/dev/login')
        if not _is_dev_portfolio_authorized():
            return redirect(f"/dev/login?next={quote(request.full_path if request.query_string else path)}")
        if path in ('/', '', '/index.html', '/dev', '/portfolio'):
            return render_template('dev_portfolio.html')
        return None

    if host.startswith('edu.'):
        path = request.path
        # No redirigir si ya va a /becas, /tareas, /splunk, /juegos, /edu, /dev, /portfolio, /vault o /static
        if path.startswith('/becas') or path.startswith('/tareas') or path.startswith('/splunk') or path.startswith('/juegos') or path.startswith('/edu') or path.startswith('/dev') or path.startswith('/portfolio') or path.startswith('/vault') or path.startswith('/static'):
            return None
            
        # Permitir que las APIs directas sean atendidas por sus endpoints
        if path.startswith('/api/') or path.startswith('/auth/'):
            return None

        # Redirigir vistas de BecaFinder si se accede directamente a la raíz
        beca_views = ('/dashboard', '/explorar', '/aplicaciones', '/calendario', '/kardex', '/ruta-carrera', '/perfil')
        for v in beca_views:
            if path == v or path.startswith(v + '/'):
                target = '/becas' + path
                if request.query_string:
                    target += '?' + request.query_string.decode('utf-8')
                return redirect(target)

        # Redirigir vistas de TaskHub si se accede directamente a la raíz
        task_views = ('/calendar', '/courses', '/grades', '/documents', '/settings')
        for v in task_views:
            if path == v or path.startswith(v + '/'):
                target = '/tareas' + path
                if request.query_string:
                    target += '?' + request.query_string.decode('utf-8')
                return redirect(target)

        # Fallback al Hub Académico de Dory EDU
        target = '/edu' + path
        if request.query_string:
            target += '?' + request.query_string.decode('utf-8')
        return redirect(target)

# --- Motor de deteccion (modulo independiente, sin dependencias de Flask) ---
from dory_engine import *  # noqa: F401,F403  (re-export para compatibilidad con scripts existentes)
from dory_engine import (
    GOOGLE_SAFE_BROWSING_API_KEY, predict_phishing_hf, extract_basic_features,
    analyze_single_url, check_urls_with_safe_browsing, LEGIT_DOMAINS,
)


def _warm_up_engine():
    """Precarga modelo ML y caché de Threat Intel (antes el primer correo pagaba ~2 s de arranque en frío)."""
    try:
        from ml_classifier import DoryMLClassifier
        from threat_feed_sync import ThreatIntelligenceFeedManager
        DoryMLClassifier.get_instance()
        ThreatIntelligenceFeedManager.ensure_cache()
    except Exception as e:
        logger.warning(f"Precarga del motor omitida: {e}")


if os.environ.get('DORY_WARMUP', '1').lower() in ('1', 'true', 'yes'):
    import threading as _threading
    _threading.Thread(target=_warm_up_engine, name='DoryWarmUp', daemon=True).start()

# --- Database Configuration ---
DATABASE_PATH = os.path.join(APP_ROOT, 'feedback.db')


def get_db_connection(timeout: float = 15.0) -> sqlite3.Connection:
    """Return a SQLite connection configured with WAL mode and busy_timeout for concurrency."""
    conn = sqlite3.connect(DATABASE_PATH, timeout=timeout)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA synchronous=NORMAL;')
    conn.execute('PRAGMA busy_timeout=10000;')
    return conn


def init_database():
    """Initialize SQLite database for user feedback and reports with WAL mode and indexes."""
    conn = get_db_connection(timeout=30.0)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            email_text TEXT NOT NULL,
            prediction TEXT NOT NULL,
            user_feedback TEXT NOT NULL,
            confidence REAL,
            risk_score TEXT,
            threats_detected TEXT,
            google_safe_browsing_checked BOOLEAN,
            google_safe_browsing_safe BOOLEAN,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incoming_phishing_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            sender_email TEXT NOT NULL,
            recipient_email TEXT,
            subject TEXT,
            email_body TEXT NOT NULL,
            prediction TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            confidence REAL NOT NULL,
            threats_detected TEXT,
            urls_found TEXT,
            reply_sent BOOLEAN DEFAULT 0,
            reply_timestamp DATETIME,
            processing_time_ms REAL,
            raw_headers TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contact_leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            company TEXT,
            team_size TEXT,
            interest TEXT,
            message TEXT,
            ip_address TEXT,
            user_agent TEXT,
            status TEXT DEFAULT 'new'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_consents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            session_id TEXT NOT NULL,
            user_email TEXT,
            consent_type TEXT NOT NULL,
            version TEXT NOT NULL,
            granted BOOLEAN NOT NULL DEFAULT 1,
            scope TEXT DEFAULT 'all',
            ip_address TEXT,
            user_agent TEXT,
            source_url TEXT,
            metadata TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS arco_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            folio TEXT UNIQUE NOT NULL,
            sender_email TEXT NOT NULL,
            subject TEXT,
            body_preview TEXT,
            status TEXT DEFAULT 'recibido',
            deadline_date TEXT,
            ack_sent BOOLEAN DEFAULT 0
        )
    ''')

    # Performance indexes for frequent queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_timestamp ON incoming_phishing_reports(timestamp DESC);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_pred_score ON incoming_phishing_reports(prediction, risk_score);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_feedback_timestamp ON feedback(timestamp DESC);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_consents_granted_type ON user_consents(granted, consent_type);')
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DATABASE_PATH} (WAL mode + indexes enabled)")

# Initialize database on startup
init_database()


# --- SEO, Analytics & Indexing Endpoints ---
@app.context_processor
def inject_seo_and_analytics():
    return {
        'ga_measurement_id': os.environ.get('GA_MEASUREMENT_ID', ''),
        'gsc_verification_code': os.environ.get('GOOGLE_SEARCH_CONSOLE_CODE', '')
    }

@app.route('/robots.txt')
def robots_txt():
    """Directorio de indexación para robots y motores de búsqueda."""
    return send_from_directory(os.path.join(APP_ROOT, 'static'), 'robots.txt', mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap_xml():
    """Mapa del sitio XML oficial para Google Search Console y Bing Webmaster."""
    return send_from_directory(os.path.join(APP_ROOT, 'static'), 'sitemap.xml', mimetype='application/xml')

# --- Routes ---
@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')

@app.route('/preview')
@app.route('/stitch-preview')
def stitch_preview():
    """Render the new Stitch-designed Dory.mx dashboard preview."""
    return render_template('stitch_preview.html')

@app.route('/dev/login', methods=['GET', 'POST'])
def dev_portfolio_login():
    """Zero-Trust Access Gate for dev.dory.mx."""
    next_url = request.args.get('next') or request.form.get('next') or '/'
    if not next_url.startswith('/'):
        next_url = '/'
    if _is_dev_portfolio_authorized():
        return redirect(next_url)

    error = None
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip().lower()
        password = request.form.get('password') or ''
        allowed_users = _get_allowed_dev_users()
        expected_pass = (os.environ.get('DEV_PORTFOLIO_PASS') or '').strip()
        if not expected_pass:
            logger.error('DEV_PORTFOLIO_PASS no configurado en .env; rechazando login por contraseña en /dev/login.')
        matched = bool(expected_pass) and hmac.compare_digest(password.encode('utf-8'), expected_pass.encode('utf-8'))
        if username in allowed_users and matched:
            session['dev_authenticated'] = True
            session['edu_authenticated'] = True
            session['edu_user'] = username
            session['edu_name'] = 'Carlos Aceves (@Charly-bite)' if 'carlos' in username or username in ('admin', '225361954') else username
            logger.info(f"🔐 [DEV.DORY.MX] Acceso autorizado para '{username}'")
            return redirect(next_url)
        error = 'Invalid credentials or access key. Use your institutional account, admin credentials, or Google OAuth 2.0.'

    sso_target = f"https://dev.dory.mx/dev/sso-callback?next={quote(next_url)}"
    google_sso_url = f"https://edu.dory.mx/edu/auth/google/login?next={quote(sso_target)}"
    return render_template('dev_login.html', error=error, next_url=next_url, google_sso_url=google_sso_url)


@app.route('/dev/sso-callback')
def dev_portfolio_sso_callback():
    """Valida el token firmado por Google OAuth en edu.dory.mx y abre sesión en dev.dory.mx."""
    import hashlib as _hashlib
    import time as _time
    email = (request.args.get('email') or '').strip().lower()
    ts = (request.args.get('ts') or '').strip()
    sig = (request.args.get('sig') or '').strip()
    next_url = request.args.get('next') or '/'
    if not next_url.startswith('/'):
        next_url = '/'
    try:
        ts_int = int(ts)
        if abs(int(_time.time()) - ts_int) <= 180 and email and sig:
            if email not in _get_allowed_dev_users():
                logger.warning(f"⛔ [DEV.DORY.MX] Intento de SSO bloqueado para cuenta no autorizada: '{email}'")
                return redirect('/dev/login')
            secret_key = (app.secret_key or os.environ.get('FLASK_SECRET_KEY') or '').strip()
            if not secret_key:
                return redirect('/dev/login')
            payload = f"{email}|{ts}"
            expected_sig = hmac.new(secret_key.encode('utf-8'), payload.encode('utf-8'), _hashlib.sha256).hexdigest()
            if hmac.compare_digest(sig, expected_sig):
                session['dev_authenticated'] = True
                session['edu_authenticated'] = True
                session['edu_user'] = email
                session['edu_role'] = 'admin'
                return redirect(next_url)
    except Exception:
        pass
    return redirect('/dev/login')


@app.route('/dev/logout')
def dev_portfolio_logout():
    """Cierra la sesión en dev.dory.mx y regresa al Zero-Trust Access Gate."""
    session.pop('dev_authenticated', None)
    session.pop('edu_authenticated', None)
    session.pop('edu_user', None)
    return redirect('/dev/login')


@app.route('/dev')
@app.route('/portfolio')
def dev_portfolio_page():
    """Render the Stitch-designed Cyber-Research Dark Glassmorphism Portfolio (dev.dory.mx)."""
    if not _is_dev_portfolio_authorized():
        return redirect(f"/dev/login?next={quote(request.path)}")
    return render_template('dev_portfolio.html')

@app.route('/vault/<doc_type>')
def download_vault_pdf(doc_type):
    """Serve certified Vault PDFs (cv, kardex, carta) directly on dev.dory.mx and dory.mx."""
    if not _is_dev_portfolio_authorized():
        return redirect(f"/dev/login?next={quote(request.path)}")
    candidate_dirs = [
        r'C:\Users\QB_DESARROLLO\Desktop\03-Orquestador-y-Proyectos-Home\Proyectos_Home\Proyectos\Buscador_Academico\server\vault_docs\carlos_aceves6195_alumnos_udg_mx',
        r'C:\Users\CarlosAlbertoAcevesC\Desktop\02-plataformas-activas\buscador-academico\server\vault_docs\carlos_aceves6195_alumnos_udg_mx',
    ]
    vault_dir = next((d for d in candidate_dirs if os.path.isdir(d)), candidate_dirs[-1])
    mapping = {
        'cv': 'CV_Ejecutivo_225361954.pdf',
        'kardex': 'Kardex_Oficial_UDG_225361954.pdf',
        'carta': 'Carta_Motivacion_225361954.pdf',
    }
    filename = mapping.get(doc_type.lower())
    if not filename or not os.path.exists(os.path.join(vault_dir, filename)):
        return jsonify({'error': 'Vault document not found'}), 404
    return send_from_directory(vault_dir, filename, mimetype='application/pdf')

@app.route('/privacidad')
@app.route('/privacy')
def privacy():
    """Render the Privacy Policy and Security page."""
    return render_template('privacy.html')

@app.route('/terminos')
@app.route('/terms')
def terms():
    """Render the Terms of Service page."""
    return render_template('terms.html')

@app.route('/faq')
def faq():
    """Render the Frequently Asked Questions page."""
    return render_template('faq.html')

@app.route('/contacto')
@app.route('/contact')
def contact():
    """Render the Contact and Service Request page."""
    return render_template('contact.html')

@app.route('/anon')
@app.route('/anonimizador')
def anonymizer_page():
    """Render the Dory AI Data Anonymizer & Sanitizer interactive tool."""
    return render_template('anonymizer.html')

@app.route('/como-funciona')
@app.route('/how-it-works')
@app.route('/semaforo')
def como_funciona():
    """Render the explanation of Dory's ML engine and risk traffic light."""
    return render_template('como_funciona.html')

@app.route('/api/anonymize', methods=['POST'])
def api_anonymize():
    """Sanitize text removing PII, financial, and secret data with reversible or blackout mode."""
    try:
        data = request.get_json(silent=True) or {}
        text = data.get('text', '')
        options = data.get('options', None)
        mode = data.get('mode', 'reversible')
        
        from dory_anonymizer import anonymizer_instance
        res = anonymizer_instance.anonymize(text, options=options)
        
        if mode == 'blackout':
            blackout_text = res['anonymized_text']
            for ph in sorted(res['mapping'].keys(), key=lambda k: len(k), reverse=True):
                blackout_text = blackout_text.replace(ph, '████████')
            res['anonymized_text'] = blackout_text

        return jsonify({
            'success': True,
            'anonymized_text': res['anonymized_text'],
            'mapping': res['mapping'] if mode != 'blackout' else {},  # blackout is final: never ship the real values back
            'summary': res['summary'],
            'total_redactions': res['total_redactions']
        }), 200
    except Exception as e:
        logger.error(f"Error in /api/anonymize: {e}", exc_info=True)
        return jsonify({'error': 'No pudimos procesar el texto.'}), 500

@app.route('/api/deanonymize', methods=['POST'])
def api_deanonymize():
    """Restore original sensitive values into an AI-generated response using session mapping."""
    try:
        data = request.get_json(silent=True) or {}
        text = data.get('text', '')
        mapping = data.get('mapping', {})
        
        from dory_anonymizer import anonymizer_instance
        restored = anonymizer_instance.deanonymize(text, mapping)
        return jsonify({
            'success': True,
            'restored_text': restored
        }), 200
    except Exception as e:
        logger.error(f"Error in /api/deanonymize: {e}", exc_info=True)
        return jsonify({'error': 'No pudimos procesar el texto.'}), 500

_CONTACT_HITS = {}  # ip -> recent submit timestamps (per process; each HA node counts its own)
_EMAIL_OK = re.compile(r'^[^@\s]{1,64}@[^@\s]+\.[a-zA-Z]{2,}$')

@app.route('/api/contact', methods=['POST'])
def api_contact():
    """Handle service request / contact form submissions."""
    try:
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        clip = lambda k, n: str(data.get(k) or '').strip()[:n]
        name = clip('name', 120)
        email = clip('email', 200)
        company = clip('company', 160)
        team_size = clip('team_size', 20)
        interest = clip('interest', 40)
        message = clip('message', 4000)

        ip_address = request.headers.get('CF-Connecting-IP') or request.remote_addr
        user_agent = request.headers.get('User-Agent', '')[:400]

        # Honeypot: humans never see the "website" field; bots fill it. Pretend success, store nothing.
        if data.get('website'):
            return jsonify({'success': True, 'message': 'Solicitud registrada exitosamente.'}), 200

        if not name or not email:
            return jsonify({'error': 'Nombre y correo son campos obligatorios.'}), 400
        if not _EMAIL_OK.match(email):
            return jsonify({'error': 'Revisa tu correo: parece incompleto.'}), 400

        # shortcut: in-memory limiter (5 per 10 min per IP), resets on restart; move to Redis/DB if abuse grows.
        now = time.time()
        recent = [t for t in _CONTACT_HITS.get(ip_address, []) if now - t < 600]
        if len(recent) >= 5:
            return jsonify({'error': 'Recibimos varias solicitudes seguidas. Escríbenos a contacto@dory.mx.'}), 429
        _CONTACT_HITS[ip_address] = recent + [now]

        with closing(get_db_connection()) as conn, conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO contact_leads (name, email, company, team_size, interest, message, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, email, company, team_size, interest, message, ip_address, user_agent))
            lead_id = cursor.lastrowid

        logger.info(f"💼 [LEAD DORY] Nueva solicitud #{lead_id} de '{name}' ({company}) - {email} [{interest}]")
        return jsonify({
            'success': True,
            'lead_id': lead_id,
            'message': 'Solicitud registrada exitosamente.'
        }), 200
    except Exception as e:
        logger.error(f"Error registrando lead de contacto: {e}")
        return jsonify({'error': 'No pudimos registrar tu solicitud. Escríbenos a contacto@dory.mx.'}), 500

@app.route('/api/consent', methods=['POST'])
def api_consent():
    """Registra consentimientos de usuarios (cookies, términos, privacidad, análisis)."""
    try:
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        session_id = (data.get('session_id') or '').strip()
        user_email = (data.get('user_email') or '').strip()
        consent_type = (data.get('consent_type') or 'web_privacy_cookies').strip()
        version = (data.get('version') or 'v2.4').strip()
        granted = bool(data.get('granted', True))
        scope = (data.get('scope') or 'all').strip()
        source_url = (data.get('source_url') or request.referrer or '').strip()
        metadata_val = json.dumps(data.get('metadata') or {})
        
        if not session_id and not user_email:
            import uuid
            session_id = str(uuid.uuid4())

        ip_address = request.headers.get('CF-Connecting-IP') or request.remote_addr
        user_agent = request.headers.get('User-Agent', '')

        with closing(get_db_connection()) as conn, conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO user_consents (session_id, user_email, consent_type, version, granted, scope, ip_address, user_agent, source_url, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, user_email, consent_type, version, 1 if granted else 0, scope, ip_address, user_agent, source_url, metadata_val))
            consent_id = cursor.lastrowid

        logger.info(f"📋 [CONSENTIMIENTO DORY] Registrado #{consent_id} [{consent_type} - {scope}] para {user_email or session_id[:12]}")
        return jsonify({
            'success': True,
            'consent_id': consent_id,
            'session_id': session_id,
            'message': 'Consentimiento registrado exitosamente.'
        }), 200
    except Exception as e:
        logger.error(f"Error registrando consentimiento: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/consent/stats', methods=['GET'])
def api_consent_stats():
    """Métricas anónimas de consentimientos registrados."""
    try:
        with closing(get_db_connection()) as conn:
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) FROM user_consents WHERE granted = 1')
            granted_cnt = cur.fetchone()[0]
            cur.execute('SELECT COUNT(*) FROM user_consents WHERE granted = 0')
            revoked_cnt = cur.fetchone()[0]
            cur.execute('SELECT consent_type, COUNT(*) FROM user_consents GROUP BY consent_type')
            by_type = dict(cur.fetchall())
        return jsonify({
            'total_granted': granted_cnt,
            'total_revoked': revoked_cnt,
            'by_type': by_type
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

import time as _time

_HEALTH_CACHE = {'count': 0, 'ts': 0.0}


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for Render and Merlin Orchestrator (cached 60s TTL)."""
    now_ts = _time.monotonic()
    if now_ts - _HEALTH_CACHE['ts'] > 60.0 or _HEALTH_CACHE['ts'] == 0.0:
        try:
            with closing(get_db_connection(timeout=1.5)) as conn:
                cur = conn.cursor()
                cur.execute('SELECT COUNT(*) FROM incoming_phishing_reports')
                _HEALTH_CACHE['count'] = cur.fetchone()[0]
                _HEALTH_CACHE['ts'] = now_ts
        except Exception:
            pass
    reports_count = _HEALTH_CACHE['count']

    return jsonify({
        'status': 'healthy',
        'service': 'dory-phishing-defense',
        'version': '3.5-enterprise-idle',
        'engine': 'calibrated-heuristics-v3.5-submillisecond',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'total_reports_processed': reports_count,
        'features': {
            'enhanced_heuristics': True,
            'attachment_inspection': True,
            'imap_idle_push': True,
            'concurrency_pool': True,
            'google_safe_browsing': bool(GOOGLE_SAFE_BROWSING_API_KEY),
            'bilingual_support': True,
            'user_feedback_system': True,
            'light_dark_theme': True,
            'analysis_history': True
        }
    }), 200

@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict if email is phishing using HuggingFace API.
    
    Accepts both JSON and form data:
    - JSON: {"subject": "...", "body": "..."}
    - Form: subject=...&body=...
    """
    try:
        subject = ''
        data = {}
        # Check if JSON or form data
        if request.is_json:
            # (Se eliminaron los print de depuración: volcaban el correo completo a los logs.)
            data = request.get_json(silent=True) or {}

            # Try to get email_text first (standard for this app)
            if 'email_text' in data:
                full_text = data['email_text'].strip()
            else:
                # Fallback to subject/body (for API compatibility)
                subject = data.get('subject', '')
                body = data.get('body', '')
                full_text = f"{subject}\n{body}".strip()
        else:
            # Handle form data from HTML form
            # The form sends 'email_text' as a single field
            full_text = request.form.get('email_text', '').strip()
            
            # Also check for separate subject/body fields (for API compatibility)
            if not full_text:
                subject = request.form.get('subject', '')
                body = request.form.get('body', '')
                full_text = f"{subject}\n{body}".strip()
        
        if not full_text:
            received_keys = list(data.keys()) if request.is_json and data else list(request.form.keys())
            return jsonify({'error': f'No text provided. Received keys: {received_keys}. Content-Type: {request.content_type}'}), 400
        
        # Check anonymization mode (enabled by default)
        anonymize = True
        if request.is_json and data:
            anonymize = data.get('anonymize', True)
        elif 'anonymize' in request.form:
            anonymize = request.form.get('anonymize', 'true').lower() in ('true', '1', 'yes')

        text_to_analyze = full_text
        privacy_audit = {
            'active': False,
            'has_sensitive_data': False,
            'redacted_entities': [],
            'total_redacted': 0,
            'stats': {}
        }

        if anonymize:
            from privacy_shield import PrivacyShield
            shield_result = PrivacyShield.anonymize_text(full_text)
            text_to_analyze = shield_result['sanitized_text']
            privacy_audit = {
                'active': True,
                'has_sensitive_data': shield_result['has_sensitive_data'],
                'redacted_entities': shield_result['redacted_entities'],
                'total_redacted': shield_result['total_redacted_count'],
                'stats': shield_result['stats'],
                'sanitized_preview': text_to_analyze[:300] if shield_result['has_sensitive_data'] else None
            }
            if shield_result['has_sensitive_data']:
                logger.info(f"🛡️ [PRIVACY SHIELD] Sanitizadas {shield_result['total_redacted_count']} entidades sensibles antes de procesar con IA.")

        logger.info("Processing prediction request...")
        
        # Get optional attachments
        attachments = data.get('attachments', []) if request.is_json and data else []
        if not isinstance(attachments, list):
            attachments = []

        # Asunto explícito -> el motor evalúa las alertas AV solo sobre el asunto real
        email_info = {'subject': subject} if subject else None

        # Get prediction from calibrated engine using sanitized text
        result = predict_phishing_hf(text_to_analyze, attachments=attachments, email_info=email_info)
        
        is_phishing = result['is_phishing']
        confidence = float(result['confidence'])
        risk_score = result['risk_score']
        phishing_prob = round(risk_score / 100.0, 2)
        legitimate_prob = round(1.0 - phishing_prob, 2)
        
        # Threat list directly from engine
        threats_detected = result.get('threats', [])
        
        # Prepare Google Safe Browsing info
        safe_browsing_info = result.get('safe_browsing', {})
        google_verdict = {
            'checked': safe_browsing_info.get('api_available', False),
            'is_safe': safe_browsing_info.get('is_safe', True),
            'malicious_urls': safe_browsing_info.get('malicious_urls', []),
            'threats_found': safe_browsing_info.get('threats_found', [])
        }
        
        response = {
            'prediction': 'PHISHING' if is_phishing else 'LEGITIMATE',
            'is_phishing': is_phishing,
            'category': result['category'],
            'category_label_es': result['category_label_es'],
            'category_label_en': result['category_label_en'],
            'category_color': result['category_color'],
            'risk_score': result['risk_score'],
            'confidence': confidence,
            'probability_phishing': phishing_prob,
            'probability_legitimate': legitimate_prob,
            'threats_detected': threats_detected,
            'google_safe_browsing': google_verdict,
            'l2_deep_inspection': result.get('l2_analysis'),
            'ml_analysis': result.get('ml_analysis'),
            'privacy_shield': privacy_audit,
            'analysis': {
                'text_length': result['features']['length'],
                'word_count': result['features']['word_count'],
                'url_count': result['features']['url_count'],
                'uppercase_ratio': round(result['features']['uppercase_ratio'], 3),
                'exclamation_marks': result['features']['exclamation_count'],
                'question_marks': result['features']['question_count'],
                'emoji_count': result['features']['emoji_count'],
                'phishing_keywords': result['features']['keyword_matches'],
                'risk_score': f"{result['risk_score']}/{result['max_possible_score']}",
                'attachments_analyzed': result['features']['attachment_count'],
                'suspicious_attachments': result['features']['suspicious_attachments']
            },
            'flags': {
                'suspicious_tld': result['features']['has_suspicious_tld'],
                'url_shortener': result['features']['has_url_shortener'],
                'ip_in_url': result['features']['has_ip_in_url'],
                'brand_impersonation': result['features']['has_brand_impersonation'],
                'urgency_tactics': result['features']['has_urgency'],
                'credential_request': result['features']['requests_credentials'],
                'unrealistic_offer': result['features']['has_unrealistic_offer'],
                'brand_typo': result['features']['has_brand_typo'],
                'generic_greeting': result['features']['has_generic_greeting'],
                'fiscal_context': result['features']['has_fiscal_context'],
                'banking_context': result['features']['has_banking_context'],
                'login_path': result['features']['has_login_path'],
                'dangerous_attachment': result['features']['has_dangerous_attachment'],
                'double_extension': result['features']['has_double_extension']
            },
            'model': 'calibrated-heuristics-v3.5-privacy-shield',
            'version': '3.5'
        }
        
        logger.info(f"Prediction: {response['prediction']} (confidence: {confidence:.2f})")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Prediction failed',
            'details': str(e)
        }), 500

# --- Feedback Endpoint ---
@app.route('/feedback', methods=['POST'])
def submit_feedback():
    """Store user feedback about prediction accuracy."""
    try:
        data = request.get_json(silent=True) or {}
        
        # Validate required fields
        required_fields = ['email_text', 'prediction', 'user_feedback']
        if not all(field in data for field in required_fields):
            return jsonify({
                'error': 'Missing required fields',
                'required': required_fields
            }), 400
        
        # Validate user_feedback value
        if data['user_feedback'] not in ['correct', 'incorrect']:
            return jsonify({
                'error': 'Invalid user_feedback value',
                'allowed': ['correct', 'incorrect']
            }), 400
        
        # Get client info
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Store in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO feedback (
                email_text, prediction, user_feedback, confidence, 
                risk_score, threats_detected, google_safe_browsing_checked,
                google_safe_browsing_safe, ip_address, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['email_text'],
            data['prediction'],
            data['user_feedback'],
            data.get('confidence'),
            data.get('risk_score'),
            json.dumps(data.get('threats_detected', [])),
            data.get('google_safe_browsing_checked', False),
            data.get('google_safe_browsing_safe', True),
            ip_address,
            user_agent
        ))
        
        conn.commit()
        feedback_id = cursor.lastrowid
        conn.close()
        
        logger.info(f"Feedback received: {data['user_feedback']} for prediction {data['prediction']}")
        
        return jsonify({
            'status': 'success',
            'message': 'Feedback recorded successfully',
            'feedback_id': feedback_id
        }), 200
        
    except Exception as e:
        logger.error(f"Feedback error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Failed to record feedback',
            'details': str(e)
        }), 500

# --- Admin Dashboard ---
def check_auth(username, password):
    """Check if username/password is valid (comparación en tiempo constante).
    Sin ADMIN_PASSWORD configurado el panel queda deshabilitado (antes: 'dory2024' publicado en el repo)."""
    admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_pass = os.environ.get('ADMIN_PASSWORD', '')
    if not admin_pass or username is None or password is None:
        return False
    user_ok = hmac.compare_digest(str(username).encode(), admin_user.encode())
    pass_ok = hmac.compare_digest(str(password).encode(), admin_pass.encode())
    return user_ok and pass_ok

def authenticate():
    """Send 401 response for authentication."""
    return jsonify({'error': 'Authentication required'}), 401, {
        'WWW-Authenticate': 'Basic realm="Admin Access"'
    }

def requires_auth(f):
    """Decorator for routes that require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/admin/feedback', methods=['GET'])
@requires_auth
def view_feedback():
    """Admin endpoint to view feedback statistics and data."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_feedback,
                SUM(CASE WHEN user_feedback = 'correct' THEN 1 ELSE 0 END) as correct_predictions,
                SUM(CASE WHEN user_feedback = 'incorrect' THEN 1 ELSE 0 END) as incorrect_predictions,
                SUM(CASE WHEN prediction = 'PHISHING' THEN 1 ELSE 0 END) as phishing_predictions,
                SUM(CASE WHEN prediction = 'LEGITIMATE' THEN 1 ELSE 0 END) as legitimate_predictions
            FROM feedback
        ''')
        stats = dict(cursor.fetchone())
        
        # Calculate accuracy
        total = stats['total_feedback']
        if total > 0:
            stats['accuracy'] = round((stats['correct_predictions'] / total) * 100, 2)
        else:
            stats['accuracy'] = 0
        
        # Get recent feedback (last 100)
        cursor.execute('''
            SELECT 
                id, timestamp, email_text, prediction, user_feedback, 
                confidence, risk_score, threats_detected,
                google_safe_browsing_checked, google_safe_browsing_safe
            FROM feedback
            ORDER BY timestamp DESC
            LIMIT 100
        ''')
        
        recent_feedback = []
        for row in cursor.fetchall():
            feedback_item = dict(row)
            # Parse JSON fields
            if feedback_item['threats_detected']:
                try:
                    feedback_item['threats_detected'] = json.loads(feedback_item['threats_detected'])
                except:
                    feedback_item['threats_detected'] = []
            recent_feedback.append(feedback_item)
        
        conn.close()
        
        return jsonify({
            'statistics': stats,
            'recent_feedback': recent_feedback
        }), 200
        
    except Exception as e:
        logger.error(f"Admin feedback error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Failed to retrieve feedback',
            'details': str(e)
        }), 500

@app.route('/admin/feedback/export', methods=['GET'])
@requires_auth
def export_feedback():
    """Export all feedback data as JSON."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM feedback ORDER BY timestamp DESC')
        
        feedback_data = []
        for row in cursor.fetchall():
            feedback_item = dict(row)
            # Parse JSON fields
            if feedback_item['threats_detected']:
                try:
                    feedback_item['threats_detected'] = json.loads(feedback_item['threats_detected'])
                except:
                    feedback_item['threats_detected'] = []
            feedback_data.append(feedback_item)
        
        conn.close()
        
        return jsonify({
            'total_records': len(feedback_data),
            'export_date': datetime.now().isoformat(),
            'data': feedback_data
        }), 200
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Failed to export feedback',
            'details': str(e)
        }), 500

# --- Mail Service API Endpoints ---
@app.route('/api/mail/status', methods=['GET'])
@requires_auth
def mail_status():
    """Get status of the automated email inbox service and database counts."""
    try:
        from mail_service import MailConfig
        cfg = MailConfig()
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            SELECT 
                COUNT(*) as total_reports,
                SUM(CASE WHEN risk_score > 40 OR prediction = 'PHISHING' THEN 1 ELSE 0 END) as phishing_reports,
                SUM(CASE WHEN (risk_score BETWEEN 26 AND 40) OR prediction = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious_reports,
                SUM(CASE WHEN (risk_score <= 25 OR risk_score IS NULL) AND prediction != 'PHISHING' AND prediction != 'SUSPICIOUS' THEN 1 ELSE 0 END) as legitimate_reports,
                SUM(CASE WHEN reply_sent = 1 THEN 1 ELSE 0 END) as replies_sent
            FROM incoming_phishing_reports
        ''')
        row = cur.fetchone()
        conn.close()
        
        return jsonify({
            'status': 'configured' if cfg.is_configured() else 'unconfigured',
            'imap_server': cfg.imap_server,
            'imap_user': cfg.imap_user if cfg.imap_user else None,
            'smtp_server': cfg.smtp_server,
            'poll_interval_seconds': cfg.poll_interval,
            'statistics': {
                'total_reports': row[0] or 0,
                'phishing_reports': row[1] or 0,
                'suspicious_reports': row[2] or 0,
                'legitimate_reports': row[3] or 0,
                'replies_sent': row[4] or 0
            }
        }), 200
    except Exception as e:
        logger.error(f"Error in mail_status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/mail/simulate', methods=['POST'])
@requires_auth
def mail_simulate():
    """Simulate an incoming email and return the generated security report."""
    try:
        data = request.get_json(silent=True) or {}
        sample_key = data.get('sample', 'sat')
        custom_sender = data.get('sender', '')
        custom_text = data.get('body', '')
        
        from mail_service import run_simulation
        res = run_simulation(
            sample_key=sample_key,
            save_html_preview=True,
            custom_text=custom_text if custom_text else None,
            custom_sender=custom_sender if custom_sender else None
        )
        
        return jsonify({
            'success': True,
            'prediction': res['prediction'],
            'report_subject': res['report']['subject'],
            'report_id': res['report']['report_id'],
            'html_preview': res['report']['html'],
            'plain_preview': res['report']['plain'],
            'processing_time_ms': res['processing_time_ms']
        }), 200
    except Exception as e:
        logger.error(f"Error in mail_simulate: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/mail/reports', methods=['GET'])
@requires_auth
def mail_reports():
    """List recent incoming email reports from the corporate phishing corpus."""
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        cur.execute('''
            SELECT id, timestamp, sender_email, subject, prediction, risk_score, confidence, threats_detected, urls_found, reply_sent, processing_time_ms
            FROM incoming_phishing_reports
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        records = []
        for r in cur.fetchall():
            item = dict(r)
            try:
                item['threats_detected'] = json.loads(item['threats_detected']) if item['threats_detected'] else []
            except Exception:
                pass
            try:
                item['urls_found'] = json.loads(item['urls_found']) if item['urls_found'] else []
            except Exception:
                pass
            records.append(item)
            
        conn.close()
        return jsonify({
            'total': len(records),
            'reports': records
        }), 200
    except Exception as e:
        logger.error(f"Error in mail_reports: {e}")
        return jsonify({'error': str(e)}), 500

# Webhook secret for Cloudflare Worker & external tunnels (OBLIGATORIO: sin valor por defecto en el código)
DORY_WEBHOOK_SECRET = os.environ.get('DORY_WEBHOOK_SECRET', '')

# ═══════════════════════════════════════════════════════════════════════
# STALWART LOCAL DELIVERY — Puente Cloudflare → Thunderbird
# ═══════════════════════════════════════════════════════════════════════
# Mapeo de buzones @dory.mx reconocidos por Stalwart local
STALWART_SMTP_HOST = os.environ.get('STALWART_SMTP_HOST', '127.0.0.1')
STALWART_SMTP_PORT = int(os.environ.get('STALWART_SMTP_PORT', 25))
# Credenciales IMAP desde entorno (antes la contraseña estaba escrita 3 veces en el código versionado)
STALWART_IMAP_HOST = os.environ.get('STALWART_IMAP_HOST', '127.0.0.1')
STALWART_IMAP_PORT = int(os.environ.get('STALWART_IMAP_PORT', 993))
STALWART_IMAP_USER = os.environ.get('STALWART_IMAP_USER', 'carlos@dory.mx')
STALWART_IMAP_PASSWORD = os.environ.get('STALWART_IMAP_PASSWORD', '')
# Certificado autofirmado en loopback: verificación desactivable solo de forma explícita
STALWART_IMAP_INSECURE = os.environ.get('STALWART_IMAP_INSECURE', '1').lower() in ('1', 'true', 'yes')
# Carpeta de cuarentena para correos con veredicto PHISHING
DORY_QUARANTINE_FOLDER = os.environ.get('DORY_QUARANTINE_FOLDER', 'Junk')
DORY_MAILBOXES = {
    'carlos@dory.mx', 'contacto@dory.mx', 'soporte@dory.mx',
    'alerta@dory.mx', 'seguridad@dory.mx', 'spam@dory.mx'
}

# Efectos secundarios lentos (copia de reporte, respuesta SMTP/Resend, ARCO) fuera del ciclo
# petición/respuesta: el Worker de Cloudflare ya no espera segundos de SMTP por cada correo.
from concurrent.futures import ThreadPoolExecutor
_BG_EXECUTOR = ThreadPoolExecutor(max_workers=int(os.environ.get('DORY_BG_WORKERS', 2)),
                                  thread_name_prefix='DoryInboundBG')
_MAIL_WORKER = None


def _get_mail_worker():
    """Instancia única de MailMonitorWorker (antes se creaba una, con su propio pool, por petición)."""
    global _MAIL_WORKER
    if _MAIL_WORKER is None:
        from mail_service import MailMonitorWorker
        _MAIL_WORKER = MailMonitorWorker()
    return _MAIL_WORKER


def _quote_imap_folder(folder: str) -> str:
    folder = folder.strip()
    return folder if folder.startswith('"') or folder.upper() == 'INBOX' else f'"{folder}"'


def _get_peer_stalwart_host() -> str:
    import socket
    try:
        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
    except Exception:
        local_ips = []
    if '192.168.2.218' in local_ips:
        return '192.168.2.222'
    return '192.168.2.218'


def _stalwart_imap_connect(host: str = None):
    """Abre una sesión IMAP autenticada contra Stalwart (local o réplica HA)."""
    import imaplib, ssl
    if not STALWART_IMAP_PASSWORD:
        raise RuntimeError('STALWART_IMAP_PASSWORD no configurado')
    target_host = host or STALWART_IMAP_HOST
    ctx = ssl.create_default_context()
    if STALWART_IMAP_INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    cli = imaplib.IMAP4_SSL(target_host, STALWART_IMAP_PORT, ssl_context=ctx, timeout=8)
    try:
        cli.login(STALWART_IMAP_USER, STALWART_IMAP_PASSWORD)
    except Exception:
        try:
            cli.shutdown()
        except Exception:
            pass
        raise
    return cli


def _stalwart_replicate_to_peer(folder: str, raw_bytes: bytes):
    """Replica asíncronamente un mensaje IMAP en el nodo hermano (.218 <-> .222)."""
    import imaplib, time
    peer_host = _get_peer_stalwart_host()
    try:
        with _stalwart_imap_connect(peer_host) as peer_cli:
            _ensure_imap_folder(peer_cli, folder)
            peer_cli.append(folder, '', imaplib.Time2Internaldate(time.time()), raw_bytes)
            logger.info(f"🔄 [STALWART-HA] Mensaje replicado en nodo hermano {peer_host}:993 ({folder})")
    except Exception as ex:
        logger.debug(f"Réplica HA Stalwart ({peer_host}) omitida: {ex}")


def _ensure_imap_folder(cli, folder: str):
    """imaplib.select() devuelve 'NO' (no lanza) si la carpeta no existe: antes el create() nunca corría."""
    typ, _ = cli.select(folder)
    if typ != 'OK':
        cli.create(folder)


def _stamp_dory_headers(raw: bytes, verdict: str, score) -> bytes:
    """Antepone X-Dory-Verdict / X-Dory-Score y elimina copias previas inyectadas por el remitente."""
    sep = raw.find(b'\r\n\r\n')
    if sep == -1:
        sep = raw.find(b'\n\n')
    head, body = (raw[:sep], raw[sep:]) if sep != -1 else (raw, b'')
    head = re.sub(rb'(?im)^x-dory-(?:verdict|score):[^\n]*\n?(?:[ \t][^\n]*\n?)*', b'', head)
    stamp = f"X-Dory-Verdict: {verdict}\r\nX-Dory-Score: {int(score)}\r\n".encode('ascii')
    return stamp + head + body


def handle_arco_request(sender_email: str, subject: str, raw_body_text: str = '') -> str:
    """
    Registra formalmente una solicitud ARCO en la base de datos feedback.db,
    asigna un número de folio único con fecha límite (5 días hábiles) conforme a la LFPDPPP,
    y deposita un Acuse de Recibo formal en la carpeta 'Soporte ARCO' para trazabilidad en Thunderbird.
    """
    import email.utils
    from datetime import datetime, timedelta
    
    now = datetime.now()
    # Folio no predecible (antes random.randint(1000, 9999): colisiones y enumeración triviales)
    folio = f"ARCO-{now.strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
    deadline = (now + timedelta(days=7)).strftime('%d/%m/%Y')
    
    try:
        with closing(get_db_connection()) as conn, conn:
            cur = conn.cursor()
            cur.execute('''
                INSERT INTO arco_requests (folio, sender_email, subject, body_preview, deadline_date, ack_sent)
                VALUES (?, ?, ?, ?, ?, 1)
            ''', (folio, sender_email, subject, raw_body_text[:500], deadline))
        logger.info(f"⚖️ [ARCO RADICADA] Folio {folio} asignado a {sender_email} | Límite: {deadline}")
    except Exception as e:
        logger.error(f"Error guardando solicitud ARCO en DB: {e}")

    try:
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        import imaplib, time

        ack_msg = MIMEMultipart('alternative')
        ack_msg['Subject'] = f"[{folio}] Acuse de Recibo — Solicitud de Derechos ARCO (Dory.mx)"
        ack_msg['From'] = "Dory.mx Privacidad y Cumplimiento <soporte@dory.mx>"
        ack_msg['To'] = sender_email
        ack_msg['Date'] = email.utils.formatdate(localtime=True)

        text_content = f"""Estimado(a) Titular,\n\nHemos recibido formalmente su comunicación en el buzón oficial de soporte@dory.mx solicitando la atención y ejercicio de Derechos ARCO (Acceso, Rectificación, Cancelación y Oposición), en estricto apego a la Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP).\n\n--------------------------------------------------\nNÚMERO DE FOLIO ASIGNADO: {folio}\nFecha de radicación: {now.strftime('%d/%m/%Y %H:%M')}\nFecha límite de resolución legal: {deadline}\n--------------------------------------------------\n\nPRÓXIMOS PASOS EN EL PROCESO:\n1. Cotejo y Verificación: Nuestro Oficial de Privacidad verificará los registros administrativos asociados a su dirección.\n2. Cero Retención de Contenido: Dory no almacena cuerpos de correos analizados; las acciones aplican sobre registros de contacto o remitentes autorizados.\n3. Dictamen Formal: Recibirá la resolución definitiva a esta misma dirección de correo en un plazo no mayor a 5 días hábiles.\n\nAtentamente,\nOficialía de Privacidad y Cumplimiento Normativo\nDory Intelligence — Guadalajara, Jalisco, México\nContacto: soporte@dory.mx\n"""

        html_content = f"""<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1e293b; line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
    <div style="border-bottom: 1px solid #e2e8f0; padding-bottom: 14px; margin-bottom: 18px;">
      <h2 style="margin: 0; color: #0284c7; font-size: 20px;">Dory.mx — Oficialía de Privacidad y Cumplimiento</h2>
    </div>
    <p style="font-size: 15px;">Estimado(a) Titular,</p>
    <p style="font-size: 14px;">Hemos recibido formalmente su comunicación en el buzón oficial de <strong>soporte@dory.mx</strong> solicitando la atención y ejercicio de Derechos ARCO (Acceso, Rectificación, Cancelación y Oposición), en estricto apego a la <em>Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP)</em>.</p>
    
    <div style="background: #f8fafc; border-left: 4px solid #0284c7; padding: 14px 18px; border-radius: 6px; margin: 20px 0;">
      <div style="font-size: 12px; color: #64748b; font-weight: 700; text-transform: uppercase;">Número de Folio Asignado</div>
      <div style="font-size: 20px; font-weight: 800; color: #0f172a; margin-top: 4px; font-family: monospace;">{folio}</div>
      <div style="font-size: 12px; color: #64748b; margin-top: 6px;">Fecha de Radicación: {now.strftime('%d/%m/%Y %H:%M')} | Límite de resolución: {deadline}</div>
    </div>

    <h3 style="font-size: 15px; color: #0f172a; margin-top: 20px;">Próximos Pasos en el Proceso:</h3>
    <ol style="font-size: 13.5px; color: #334155; padding-left: 20px;">
      <li style="margin-bottom: 8px;"><strong>Cotejo y Verificación:</strong> Nuestro Oficial de Privacidad verificará los registros administrativos asociados a su dirección.</li>
      <li style="margin-bottom: 8px;"><strong>Cero Retención de Contenido:</strong> Dory no conserva cuerpos de correos analizados; las cancelaciones aplican sobre registros de contacto o remitentes autorizados.</li>
      <li style="margin-bottom: 8px;"><strong>Dictamen Formal:</strong> Recibirá la resolución definitiva a esta misma cuenta en un plazo no mayor a 5 días hábiles.</li>
    </ol>

    <p style="font-size: 13px; color: #64748b; margin-top: 25px; border-top: 1px solid #f1f5f9; padding-top: 16px;">
      Atentamente,<br>
      <strong>Oficialía de Privacidad y Cumplimiento Normativo</strong><br>
      Dory Intelligence — Guadalajara, Jalisco, México<br>
      Correo oficial: <a href="mailto:soporte@dory.mx" style="color: #0284c7; text-decoration: none;">soporte@dory.mx</a>
    </p>
  </div>
</body>
</html>"""

        ack_msg.attach(MIMEText(text_content, 'plain', 'utf-8'))
        ack_msg.attach(MIMEText(html_content, 'html', 'utf-8'))

        with _stalwart_imap_connect() as imap_cli:
            _ensure_imap_folder(imap_cli, '"Soporte ARCO"')
            imap_cli.append('"Soporte ARCO"', '', imaplib.Time2Internaldate(time.time()), ack_msg.as_bytes())
            logger.info(f"⚖️ [ARCO] Acuse de recibo {folio} generado y depositado en 'Soporte ARCO' para {sender_email}")
    except Exception as e:
        logger.error(f"Error depositando acuse de recibo ARCO: {e}")

    return folio

def stalwart_deliver_local(raw_rfc822: bytes, recipient: str, sender: str = '', folder: str = None) -> bool:
    """
    Deposita una copia del correo entrante en el buzón local de Stalwart.
    Si el correo está dirigido a soporte@dory.mx, lo filtra directamente en la
    carpeta dedicada 'Soporte ARCO' de Thunderbird. De lo contrario, lo entrega en INBOX.
    folder: carpeta forzada (p. ej. cuarentena para veredicto PHISHING).
    """
    recipient = recipient.strip().lower() if recipient else 'soporte@dory.mx'
    if folder:
        target_folder = _quote_imap_folder(folder)
    else:
        target_folder = '"Soporte ARCO"' if 'soporte@dory.mx' in recipient else 'INBOX'
    
    # 1. Intento directo vía IMAP APPEND a la carpeta correspondiente
    try:
        import imaplib, time
        with _stalwart_imap_connect() as imap_cli:
            # Garantizar que la carpeta destino existe
            _ensure_imap_folder(imap_cli, target_folder)

            res = imap_cli.append(target_folder, '', imaplib.Time2Internaldate(time.time()), raw_rfc822)
            if res and res[0] == 'OK':
                logger.info(f"📬 [STALWART/IMAP] Correo dirigido a '{recipient}' depositado exitosamente en '{target_folder}' de '{STALWART_IMAP_USER}' (Thunderbird)")
                _BG_EXECUTOR.submit(_stalwart_replicate_to_peer, target_folder, raw_rfc822)
                return True
    except Exception as imap_err:
        logger.warning(f"IMAP APPEND local no disponible ({imap_err}), intentando Failover HA en {_get_peer_stalwart_host()}:993...")
        try:
            import imaplib, time
            peer_host = _get_peer_stalwart_host()
            with _stalwart_imap_connect(peer_host) as peer_cli:
                _ensure_imap_folder(peer_cli, target_folder)
                res = peer_cli.append(target_folder, '', imaplib.Time2Internaldate(time.time()), raw_rfc822)
                if res and res[0] == 'OK':
                    logger.info(f"📬 [STALWART/HA-FAILOVER] Correo depositado en nodo hermano {peer_host}:993 ('{target_folder}')")
                    return True
        except Exception as peer_err:
            logger.debug(f"IMAP APPEND HA tampoco disponible, fallback a SMTP: {peer_err}")

    # 2. Fallback vía SMTP local
    import smtplib
    try:
        if not sender:
            import email as email_mod
            from email.utils import parseaddr
            parsed = email_mod.message_from_bytes(raw_rfc822)
            sender = parseaddr(parsed.get('From', ''))[1] or 'unknown@external.sender'
        with smtplib.SMTP(STALWART_SMTP_HOST, STALWART_SMTP_PORT, timeout=10) as smtp:
            smtp.sendmail(sender, [recipient], raw_rfc822)
        logger.info(f"📬 [STALWART/SMTP] Correo depositado en buzón local '{recipient}' (de: {sender})")
        return True
    except Exception as e:
        logger.warning(f"⚠️ [STALWART] Error depositando correo en buzón local: {e}")
        return False


def stalwart_deliver_report(report: dict, email_info: dict) -> bool:
    """
    Deposita una copia idéntica del reporte de análisis generado por Dory en la carpeta
    'Respuestas Dory' de Thunderbird vía IMAP local para consulta y auditoría inmediata.
    """
    try:
        import imaplib, time, os
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.image import MIMEImage
        from mail_service import get_dory_icon_base64, DORY_ICON_PATH
        
        msg = MIMEMultipart('related')
        msg['Subject'] = report.get('subject', 'Reporte de Ciberseguridad Dory')
        msg['From'] = 'Dory Ciberseguridad <spam@dory.mx>'
        msg['To'] = email_info.get('sender_email', '')
        
        alt = MIMEMultipart('alternative')
        msg.attach(alt)
        alt.attach(MIMEText(report.get('plain', ''), 'plain', 'utf-8'))
        
        html_content = report.get('html', '')
        dory_https_url = 'https://engine.dory.mx/static/dory_logo.png'
        if dory_https_url in html_content:
            html_content = html_content.replace(dory_https_url, 'cid:dory_logo')
        alt.attach(MIMEText(html_content, 'html', 'utf-8'))
        
        if os.path.exists(DORY_ICON_PATH):
            with open(DORY_ICON_PATH, 'rb') as f:
                img = MIMEImage(f.read(), _subtype='png')
                img.add_header('Content-ID', '<dory_logo>')
                img.add_header('Content-Disposition', 'inline', filename='dory_logo.png')
                msg.attach(img)
                
        with _stalwart_imap_connect() as client:
            _ensure_imap_folder(client, '"Respuestas Dory"')
            client.append('"Respuestas Dory"', '', imaplib.Time2Internaldate(time.time()), msg.as_bytes())
            logger.info(f"📬 [STALWART/REPORTE] Copia de respuesta depositada en 'Respuestas Dory' para {email_info.get('sender_email')}")
            return True
    except Exception as e:
        logger.warning(f"⚠️ [STALWART/REPORTE] Error depositando reporte en buzón local: {e}")
        return False


@app.route('/api/mail/inbound', methods=['POST'])
def mail_inbound():
    """
    Ingesta directa de correos RFC822 desde Cloudflare Email Worker vía Tunnel.
    Recibe el flujo MIME raw, lo analiza con Dory AI Engine + Deep Inspection L2
    y lo almacena en feedback.db.

    Flujo v4:
      1. Autenticación OBLIGATORIA con X-Dory-Key (antes: si la cabecera faltaba se aceptaba
         cualquier petición, permitiendo inyectar correos y disparar respuestas desde Dory).
      2. Análisis ANTES de la entrega (antes el phishing llegaba a INBOX antes de analizarse).
      3. Entrega con cabeceras X-Dory-Verdict / X-Dory-Score; PHISHING va a la carpeta de cuarentena.
      4. Persistencia sincrónica (record_id) y efectos lentos en segundo plano (copia del reporte,
         respuesta SMTP/Resend, ARCO), actualizando reply_sent al terminar.
    """
    # 1. Autenticación del webhook (tiempo constante, rechazo si no hay secreto configurado)
    provided_key = request.headers.get('X-Dory-Key', '')
    if not DORY_WEBHOOK_SECRET:
        logger.error("DORY_WEBHOOK_SECRET no configurado: /api/mail/inbound deshabilitado.")
        return jsonify({'error': 'Inbound webhook not configured'}), 503
    if not provided_key or not hmac.compare_digest(provided_key.encode(), DORY_WEBHOOK_SECRET.encode()):
        logger.warning(f"Intento de acceso no autorizado a /api/mail/inbound desde {request.remote_addr}")
        return jsonify({'error': 'Unauthorized: invalid X-Dory-Key'}), 403

    raw_data = request.get_data()
    if not raw_data:
        return jsonify({'error': 'Empty email payload received'}), 400

    dory_recipient = (request.headers.get('X-Dory-Recipient') or 'carlos@dory.mx').strip().lower()
    dory_sender = request.headers.get('X-Dory-Sender', '')

    # 2. Análisis (fail-open: si el motor falla, el correo se entrega igualmente marcado UNSCANNED)
    try:
        worker = _get_mail_worker()
        result = worker.process_single_message(raw_data, recipient_email=dory_recipient)
    except Exception as e:
        logger.error(f"Error analizando correo entrante en /api/mail/inbound: {e}", exc_info=True)
        stalwart_ok = stalwart_deliver_local(_stamp_dory_headers(raw_data, 'UNSCANNED', 0),
                                             dory_recipient, dory_sender)
        return jsonify({'status': 'delivered_unscanned', 'stalwart_delivered': stalwart_ok,
                        'error': str(e)}), (200 if stalwart_ok else 500)

    prediction = result['prediction']
    email_info = result['email_info']
    category = prediction.get('category', 'SAFE')

    # 3. Entrega local con veredicto; PHISHING -> cuarentena
    stamped = _stamp_dory_headers(raw_data, category, prediction.get('risk_score', 0))
    target_folder = DORY_QUARANTINE_FOLDER if category == 'PHISHING' and DORY_QUARANTINE_FOLDER else None
    stalwart_ok = stalwart_deliver_local(stamped, dory_recipient, dory_sender, folder=target_folder)
    if not stalwart_ok and os.environ.get('DORY_REQUIRE_LOCAL_DELIVERY', '1').lower() in ('1', 'true', 'yes'):
        # 502 -> el Worker reintenta y, si persiste, usa su reenvío/rechazo de respaldo (no se pierde el correo)
        return jsonify({'status': 'delivery_failed', 'category': category}), 502

    # 4. Persistencia (cuerpo saneado con el Escudo de Privacidad)
    try:
        from mail_service import save_incoming_report
        from privacy_shield import PrivacyShield
        if result['db_payload'].get('email_body'):
            result['db_payload']['email_body'] = PrivacyShield.anonymize_text(
                result['db_payload']['email_body'])['sanitized_text']
        record_id = save_incoming_report(result['db_payload'])
    except Exception as e:
        logger.error(f"Error persistiendo reporte entrante: {e}", exc_info=True)
        record_id = -1

    # ── Atención Automática de Derechos ARCO ──
    # Si el correo va a soporte@dory.mx o el asunto menciona ARCO (palabra completa; antes "Marcos"
    # o "marco" disparaban un folio), radicar formalmente y generar acuse. Nunca para phishing.
    subject = email_info.get('subject') or ''
    is_arco = ('soporte@dory.mx' == dory_recipient or re.search(r'\barco\b', subject, re.IGNORECASE)) \
        and category != 'PHISHING'

    _BG_EXECUTOR.submit(_inbound_background_tasks, worker, result, record_id, dory_recipient, bool(is_arco))

    logger.info(
        f"✅ [INBOUND DORY] Correo procesado #{record_id} de '{email_info.get('sender_email')}' | "
        f"Dictamen: {category} (Score: {prediction.get('risk_score')}) | "
        f"Carpeta: {target_folder or 'INBOX'} | Tiempo: {result['processing_time_ms']}ms"
    )

    return jsonify({
        'status': 'success',
        'record_id': record_id,
        'sender': email_info.get('sender_email'),
        'subject': subject,
        'category': category,
        'is_phishing': prediction.get('is_phishing'),
        'risk_score': prediction.get('risk_score'),
        'confidence': prediction.get('confidence'),
        'threats': prediction.get('threats', []),
        'urls_found': email_info.get('urls', []),
        'processing_time_ms': result['processing_time_ms'],
        'stalwart_delivered': stalwart_ok,
        'delivered_folder': target_folder or 'INBOX',
        'reply_status': 'queued',
    }), 200


def _inbound_background_tasks(worker, result, record_id, dory_recipient, is_arco):
    """Efectos secundarios lentos del webhook, fuera del ciclo petición/respuesta."""
    email_info = result['email_info']
    try:
        stalwart_deliver_report(result['report'], email_info)
    except Exception as e:
        logger.warning(f"No se pudo copiar el reporte a 'Respuestas Dory': {e}")

    reply_ok = False
    try:
        reply_ok = worker.send_smtp_reply(email_info, result['report'], envelope_recipient=dory_recipient)
    except Exception as smtp_err:
        logger.warning(f"No se pudo despachar respuesta SMTP externa: {smtp_err}")

    if record_id and record_id > 0 and reply_ok:
        try:
            with closing(get_db_connection()) as conn, conn:
                conn.execute('UPDATE incoming_phishing_reports SET reply_sent = 1 WHERE id = ?', (record_id,))
        except Exception as e:
            logger.warning(f"No se pudo actualizar reply_sent para #{record_id}: {e}")

    if is_arco:
        try:
            handle_arco_request(email_info.get('sender_email', ''), email_info.get('subject', ''),
                                result['db_payload'].get('email_body', ''))
            # También registrar el consentimiento de interacción
            with closing(get_db_connection()) as conn, conn:
                conn.execute('''
                    INSERT INTO user_consents (session_id, user_email, consent_type, version, granted, scope, source_url)
                    VALUES (?, ?, 'email_arco_request', 'v2.4', 1, 'arco', 'email:soporte@dory.mx')
                ''', (f"eml_{record_id}", email_info.get('sender_email', '')))
        except Exception as e:
            logger.warning(f"Error en atención ARCO automática: {e}")

@app.route('/api/privacy/anonymize', methods=['POST'])
def privacy_anonymize():
    """
    Endpoint de sanitización en tiempo real para previsualización PII.
    """
    try:
        data = request.get_json() or {}
        text = data.get('text', '')
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        from privacy_shield import PrivacyShield
        result = PrivacyShield.anonymize_text(text)
        return jsonify({
            'success': True,
            'sanitized_text': result['sanitized_text'],
            'has_sensitive_data': result['has_sensitive_data'],
            'redacted_entities': result['redacted_entities'],
            'stats': result['stats'],
            'total_redacted_count': result['total_redacted_count']
        }), 200
    except Exception as e:
        logger.error(f"Error in privacy_anonymize: {e}")
        return jsonify({'error': str(e)}), 500


def _render_dory_error(status_code: int, code_label: str, title: str, message: str, auto_retry: bool = False, node_state_text: str = 'ERROR'):
    accept_hdr = request.headers.get('Accept', '')
    if request.path.startswith('/api/') or '/api/' in request.path or (
        'application/json' in accept_hdr and 'text/html' not in accept_hdr
    ):
        return jsonify({
            'error': title,
            'message': message,
            'code': code_label,
            'status': status_code
        }), status_code

    host_hdr = (request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or '').lower()
    req_path = request.path or ''
    is_tareas = req_path.startswith(('/tareas', '/edu/tareas'))
    is_becas = req_path.startswith(('/becas', '/edu/becas'))
    is_edu = 'edu.dory.mx' in host_hdr or req_path.startswith(('/edu', '/tareas', '/becas', '/juegos', '/splunk'))
    is_dev = 'dev.dory.mx' in host_hdr or req_path.startswith(('/dev', '/portfolio'))

    if is_tareas:
        brand_name = 'TaskHub'
        service_name = 'TaskHub (Nemo)'
        service_tag = '⚡ NEMO'
        accent_color = '#6366f1'
        brand_logo = '/static/nemo_logo.svg'
        home_url = '/edu/tareas/'
    elif is_becas:
        brand_name = 'BecaFinder'
        service_name = 'BecaFinder (Crush)'
        service_tag = '🐢 CRUSH'
        accent_color = '#06b6d4'
        brand_logo = '/static/crush_logo.svg'
        home_url = '/edu/becas/'
    else:
        brand_name = 'Dory EDU' if is_edu else ('Dory DEV' if is_dev else 'Dory.mx')
        service_name = brand_name
        service_tag = '🎓 EDU' if is_edu else ('💻 DEV' if is_dev else '🛡️ SHIELD')
        accent_color = '#0284C7' if is_edu else ('#8B5CF6' if is_dev else '#38BDF8')
        brand_logo = '/static/Favicon Gabo 512x512.png'
        home_url = '/edu' if is_edu else ('/dev' if is_dev else '/')

    # Si es 502 o 504 en HTML, enviar 503 al borde para evitar que Cloudflare reemplace nuestra vista
    http_status = 503 if status_code in (502, 504) else status_code

    html_body = render_template(
        'error_page.html',
        page_title=f"{title} — {service_name}",
        brand_name=brand_name,
        brand_logo=brand_logo,
        service_tag=service_tag,
        service_name=service_name,
        accent_color=accent_color,
        status_code=status_code,
        error_code_label=code_label,
        error_title=title,
        error_message=message,
        auto_retry=auto_retry,
        node_state_text=node_state_text,
        home_url=home_url,
        timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    )
    return html_body, http_status, {'Cache-Control': 'no-store, no-cache, must-revalidate'}


@app.errorhandler(400)
def handle_400_error(e):
    return _render_dory_error(
        400,
        'BAD_REQUEST_PAYLOAD',
        'Solicitud inválida o incompleta',
        'Los parámetros enviados no pudieron ser procesados por el Gateway de Dory.mx.',
        auto_retry=False,
        node_state_text='SOLICITUD INVÁLIDA'
    )


@app.errorhandler(401)
def handle_401_error(e):
    return _render_dory_error(
        401,
        'AUTH_REQUIRED',
        'Autenticación requerida en Dory.mx',
        'Inicia sesión en el portal para acceder a este módulo o sincronizar tu cuenta.',
        auto_retry=False,
        node_state_text='NO AUTENTICADO'
    )


@app.errorhandler(403)
def handle_403_error(e):
    return _render_dory_error(
        403,
        'ACCESS_RESTRICTED',
        'Acceso restringido por Dory Security Shield',
        'No cuentas con permisos suficientes para acceder a este recurso o la sesión de seguridad ha expirado.',
        auto_retry=False,
        node_state_text='RESTRINGIDO'
    )


@app.errorhandler(404)
def handle_404_error(e):
    return _render_dory_error(
        404,
        'ROUTE_NOT_FOUND',
        'Ruta no encontrada en Dory.mx',
        f"La dirección '{request.path}' no existe o fue movida dentro del ecosistema Dory.",
        auto_retry=False,
        node_state_text='NO ENCONTRADO'
    )


@app.errorhandler(429)
def handle_429_error(e):
    return _render_dory_error(
        429,
        'RATE_LIMIT_SHIELD',
        'Demasiadas solicitudes consecutivas',
        'Por protección anti-abuso de Dory Security Shield, espera unos segundos antes de volver a intentar.',
        auto_retry=True,
        node_state_text='RATE LIMIT'
    )


@app.errorhandler(500)
def handle_500_error(e):
    return _render_dory_error(
        500,
        'INTERNAL_ENGINE_ERROR',
        'Incidencia interna en el motor de Dory',
        'Se produjo una excepción inesperada al procesar tu solicitud. Nuestro sistema de monitoreo ya la registró.',
        auto_retry=False,
        node_state_text='EXCEPCIÓN'
    )


@app.errorhandler(502)
@app.errorhandler(503)
@app.errorhandler(504)
def handle_50x_error(e):
    code = getattr(e, 'code', 503) or 503
    return _render_dory_error(
        code,
        'SERVICE_RECONNECTING',
        'Sincronizando servicio interno...',
        'El túnel de Cloudflare y Dory Gateway están activos. El módulo solicitado se está reiniciando automáticamente.',
        auto_retry=True,
        node_state_text='REINICIANDO'
    )


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    use_waitress = os.environ.get('DORY_USE_WAITRESS', '1').lower() in ('1', 'true', 'yes')
    if use_waitress:
        try:
            import socket
            import waitress
            from waitress.server import TcpWSGIServer

            if os.name == 'nt' and hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                def _exclusive_reuse_addr(self):
                    try:
                        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    except OSError:
                        pass
                TcpWSGIServer.set_reuse_addr = _exclusive_reuse_addr

            logger.info(f"🚀 Starting Dory Production WSGI Server (Waitress) on 0.0.0.0:{port} [SO_EXCLUSIVEADDRUSE active]")
            waitress.serve(
                app,
                host='0.0.0.0',
                port=port,
                threads=int(os.environ.get('DORY_THREADS', 12)),
                connection_limit=256,
                channel_timeout=60,
                ident='Dory-Security-Gateway'
            )
            raise SystemExit(0)
        except ImportError:
            logger.warning("Waitress no disponible; usando Werkzeug con SO_EXCLUSIVEADDRUSE.")

    if os.name == 'nt':
        import socket
        from werkzeug.serving import BaseWSGIServer
        BaseWSGIServer.allow_reuse_address = False
        _orig_server_bind = BaseWSGIServer.server_bind

        def _exclusive_server_bind(self):
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            return _orig_server_bind(self)

        BaseWSGIServer.server_bind = _exclusive_server_bind
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)



