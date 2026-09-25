"""
Flask app using HuggingFace Inference API instead of local models.
Ultra-lightweight - no heavy ML libraries loaded locally.
"""
import os
import re
import logging
import sqlite3
import json
from datetime import datetime
from flask import Flask, request, render_template, jsonify
from functools import wraps, lru_cache
import requests
from urllib.parse import urlparse

# --- Basic Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# --- Flask App ---
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# --- HuggingFace Configuration ---
# You'll need to set this as an environment variable in Render
HF_API_TOKEN = os.environ.get('HF_API_TOKEN', '')  # Get from Render env vars
HF_API_URL = "https://api-inference.huggingface.co/models/"

# Model endpoints (you can upload your model or use similar ones)
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"  # For text embeddings
# For your Keras model, you'd need to convert it or use a similar classifier

# --- Google Safe Browsing Configuration ---
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# --- Database Configuration ---
DATABASE_PATH = os.path.join(APP_ROOT, 'feedback.db')

def init_database():
    """Initialize SQLite database for user feedback and reports with WAL mode for concurrency."""
    conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
    cursor = conn.cursor()
    cursor.execute('PRAGMA journal_mode=WAL;')
    cursor.execute('PRAGMA synchronous=NORMAL;')
    
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
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DATABASE_PATH} (WAL mode enabled)")

# Initialize database on startup
init_database()

# =====================================================================
# Pre-compiled Regular Expressions & Fast Set Lookups (Sub-millisecond Engine)
# =====================================================================
RE_URLS = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)
RE_IPV4_HOST = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
RE_IPV4_IN_URL = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE)
RE_EMOJIS = re.compile(
    r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF\U00002702-\U000027B0\U000024C2-\U0001F251]+'
)
RE_EXCLAMATIONS = re.compile(r'!{2,}')
RE_QUESTIONS = re.compile(r'\?{2,}')
RE_EMAIL_ADDRS = re.compile(r'\S+@\S+')
RE_EXTENSIONS = re.compile(r'\.[a-z0-9]{2,5}')

SUSPICIOUS_TLDS = frozenset([
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', 
    '.click', '.link', '.download', '.bid', '.online', '.site', 
    '.space', '.buzz', '.club', '.live', '.icu', '.vip', '.tech', 
    '.support', '.services', '.monster', '.review', '.country', '.kim',
    '.vu', '.cc', '.ws', '.cfd', '.rest', '.sbs'
])

URL_SHORTENERS = frozenset([
    'bit.ly', 'tinyurl.com', 'tiny.cc', 't.co', 'goo.gl', 'ow.ly', 
    'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'short.io', 'rb.gy'
])

KNOWN_TARGETS = (
    'bbva', 'santander', 'banorte', 'citibanamex', 'banamex', 'scotiabank', 
    'hsbc', 'azteca', 'coppel', 'bancoppel', 'mercadopago', 'mercadolibre', 
    'paypal', 'sat', 'imss', 'infonavit', 'microsoft', 'office365', 
    'outlook', 'google', 'apple', 'icloud', 'netflix', 'amazon', 
    'facebook', 'instagram', 'whatsapp', 'dhl', 'fedex', 'estafeta', 'ups',
    'cpanel', 'directadmin', 'webmail', 'zimbra', 'roundcube'
)

LEGIT_DOMAINS = frozenset([
    'bbva.mx', 'bbva.com', 'santander.com.mx', 'santander.com', 
    'banorte.com', 'citibanamex.com', 'banamex.com', 'scotiabank.com.mx',
    'hsbc.com.mx', 'hsbc.com', 'bancoazteca.com.mx', 'coppel.com',
    'mercadolibre.com.mx', 'mercadolibre.com', 'mercadopago.com.mx', 'mercadopago.com',
    'paypal.com', 'sat.gob.mx', 'gob.mx', 'imss.gob.mx', 'microsoft.com', 
    'office.com', 'live.com', 'google.com', 'apple.com', 'netflix.com', 
    'amazon.com', 'amazon.com.mx', 'dhl.com', 'dhl.com.mx', 'fedex.com', 
    'estafeta.com', 'python.org', 'cpanel.net', 'directadmin.com'
])

ACTION_PATH_KEYWORDS = (
    'login', 'signin', 'auth', 'verify', 'verificar', 'buzon', 'buzón', 
    'cancelar', 'reclamo', 'desbloquear', 'password', 'clave', 
    'actualizar', 'secure', 'account', 'cuenta', 'entrega', 'rastreo'
)

SUSPICIOUS_DOMAIN_HYPHEN_KEYWORDS = (
    'login', 'portal', 'seguridad', 'acceso', 'verificar', 'ayuda', 'soporte'
)

FISCAL_KEYWORDS = (
    'sat', 'buzon tributario', 'buzón tributario', 'rfc', 'fiscal', 'multa', 
    'auditoria', 'auditoría', 'requerimiento fiscal', 'declaracion anual', 
    'credito fiscal', 'embargo precautorio', 'notificacion judicial'
)

RE_FISCAL_KEYWORDS = re.compile(
    r'\b(sat|rfc|multa|multas|fiscal|fiscales|buz[oó]n tributario|cr[eé]dito fiscal|adeudo fiscal|requerimiento fiscal|declaraci[oó]n anual|auditor[ií]a|embargo precautorio|notificaci[oó]n judicial)\b',
    re.IGNORECASE
)

RE_BANKING_KEYWORDS = re.compile(
    r'\b(transferencia|transferencias|spei|saldo|tarjeta|tarjetas|debito|d[eé]bito|cr[eé]dito|credito|banco|bancari[oa]s?|dep[oó]sito|dep[oó]sitos|cargo no reconocido|transacci[oó]n|desbloquear|retenid[oa]|token|nip|cvv|clave interbancaria|compra aprobada|mercadopago|mercado pago)\b',
    re.IGNORECASE
)

RE_CREDENTIAL_WORDS = re.compile(
    r'\b(password|contrase[ñn]a|contrasena|social security|ssn|credit card|tarjeta|bank account|cuenta bancaria|pin|cvv|credenciales|token m[oó]vil|token movil|clave de acceso|datos de acceso|autenticaci[oó]n|autenticacion|acceso a tu buz[oó]n)\b',
    re.IGNORECASE
)

URGENCY_PHRASES = (
    '24 hours', '24 horas', 'immediately', 'inmediatamente', 'de inmediato', 
    'right now', 'ahora mismo', 'expire today', 'expira hoy', 'final notice', 
    'aviso final', 'ultimo aviso', 'último aviso', 'last chance', 'última oportunidad', 
    'act now', 'actúa ahora', 'actua ahora', 'expira en', 'en 2 horas', 
    'evite el bloqueo', 'evite multas', 'evite la suspensión', 'evite la suspension', 
    'inmediata requerida', 'correos entrantes pendientes', 'perder el acceso',
    'perderás el acceso', 'perderas el acceso', 'solicitud de autenticación', 'solicitud de autenticacion'
)

ACTION_REQUESTS = (
    'haga clic', 'haga click', 'click aqui', 'clic aqui', 'ingrese a', 
    'ingrese su', 'actualice sus', 'verifique su', 'cancele la', 
    'desconoce la', 'solvente', 'reclamar', 'descargue el archivo', 
    'para desbloquear', 'para verificar', 'continúe la verificación',
    'continue la verificacion', 'verifique que este'
)

ALL_PHISHING_KEYWORDS = (
    'urgente', 'verificar', 'suspender', 'bloquead', 'confirm', 'actualiz', 
    'caduc', 'expir', 'inmediatamente', 'premio', 'ganador', 'ganaste',
    'reclam', 'haga clic', 'click aqui', 'alert', 'seguridad', 'cuenta',
    'tarjeta', 'contraseña', 'clave', 'pin', 'urgent', 'verify', 'suspend', 
    'blocked', 'confirm', 'update', 'expire', 'prize', 'winner', 'won'
)

OFFER_WORDS = (
    'free iphone', 'iphone gratis', 'won', 'ganaste', 'winner', 'ganador',
    'prize', 'premio', 'lottery', 'lotería', 'loteria', '$1,000', '1000 usd', 'sorteo'
)

GENERIC_GREETINGS = (
    'dear customer', 'estimado cliente', 'dear user', 'estimado usuario',
    'dear sir', 'estimado señor', 'valued customer', 'cliente valorado'
)

BRAND_TYPOS = (
    'paypa1', 'g00gle', 'micros0ft', 'amaz0n', 'facebok', 'faceb00k', 'appl3', 'netfIix', 'netfl1x'
)

DANGEROUS_EXTS = frozenset([
    '.exe', '.scr', '.vbs', '.bat', '.cmd', '.ps1', '.iso', '.img', 
    '.html', '.htm', '.hta', '.docm', '.xlsm', '.pptm', '.wsf', '.cpl', '.pif',
    '.xla', '.xlam', '.001', '.r00', '.r01', '.r11', '.vhd', '.jar', '.ace', '.dll', '.com'
])

CLOUD_ABUSE_HOSTS = (
    'cloudapp.azure.com', 'firebaseapp.com', 'appspot.com',
    'pages.dev', 'workers.dev', 's3.amazonaws.com', 'storage.googleapis.com',
    'app.goo.gl', 'azurewebsites.net'
)

DOC_MEDIA_EXTS = frozenset(['.pdf', '.xlsx', '.xls', '.docx', '.doc', '.png', '.jpg', '.jpeg', '.xml', '.csv', '.ppt', '.pptx'])
MASKING_FINAL_EXTS = frozenset(['.txt', '.html', '.htm', '.zip', '.rar', '.7z', '.exe', '.scr', '.vbs', '.bat', '.cmd', '.js', '.wsf', '.xla', '.iso'])

RE_AV_SUBJECT_ALERT = re.compile(
    r'\[(detecci[oó]n|alerta|malware|virus|troyano|trojan|exploit|cve-\d+|spam)\]|troyano|cve-2017-|win32/exploit',
    re.IGNORECASE
)

RE_FISCAL_CFDI = re.compile(
    r'\b(cfdi|factura|facturaci[oó]n|comprobante fiscal|reciba su cfdi|no pagada|pago pendiente|segundo aviso|cfe en mora|devoluci[oó]n de pago|spei liquidado|cep liquidado|comprobantede de pago|envio de factura|env[ií]o del factura|env[ií]o del comprobante|factura de cfe|cancelaci[oó]n de cfdi|cfdi cancelado)\b',
    re.IGNORECASE
)

RE_CAMPAIGN_ID = re.compile(
    r'\b(cfdi|factura|facturaci[oó]n|comprobante fiscal|solicitud|aviso de factura|notificaci[oó]n|env[ií]o|presupuesto|lineas telef[oó]nicas|cfe|informaci[oó]n del proceso)\b.*?\(\d{5,8}\)',
    re.IGNORECASE
)

RE_EXTORTION = re.compile(
    r'\b(su cuenta ha sido hackeada|he robado sus datos|recuperar el acceso|datos personales debido a ciertas actividades|sitios sospechosos|grabar un video|c[aá]mara web|bitcoin|cartera btc|transferir bitcoins?)\b',
    re.IGNORECASE
)

RE_LOGISTICS = re.compile(
    r'\b(dhl on demand|estafeta entrega|fedex entrega|paquete retenido|gu[ií]a de entrega pendiente)\b',
    re.IGNORECASE
)

RE_PORT_PADDING_EVASION = re.compile(r':0{3,}\d+')
RE_WORK_FROM_HOME_SCAM = re.compile(r'\b(ganar \d+.*?al d[ií]a|sin salir de casa es posible|trabajo desde casa)\b', re.IGNORECASE)

@lru_cache(maxsize=4096)
def analyze_single_url(url: str) -> dict:
    """Cached domain and threat analysis for a single URL string."""
    url_lower = url.lower()
    if any(url_lower.startswith(p) for p in ('http://', 'https://', 'www.')):
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        host = parsed.netloc.split(':')[0]
        path = parsed.path.lower()
        fragment = (parsed.fragment or '').lower()
    else:
        host = url_lower
        path = ""
        fragment = ""

    has_ip = bool(RE_IPV4_HOST.match(host) or RE_IPV4_IN_URL.search(url_lower))
    has_tld = any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)
    has_shortener = any(shortener in host for shortener in URL_SHORTENERS)
    has_hash_email = bool(re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', fragment))
    has_port_padding = bool(RE_PORT_PADDING_EVASION.search(url))
    has_cloud_abuse = any(host.endswith(cloud) for cloud in CLOUD_ABUSE_HOSTS)

    # Impersonation
    is_legit = (host in LEGIT_DOMAINS) or any(host.endswith('.' + legit) for legit in LEGIT_DOMAINS)
    has_impersonation = False
    has_suspicious_hyphen = False
    if not is_legit:
        for target in KNOWN_TARGETS:
            if target in host:
                has_impersonation = True
                break
        if host.count('-') >= 2 or ('-' in host and any(t in host for t in SUSPICIOUS_DOMAIN_HYPHEN_KEYWORDS)):
            has_suspicious_hyphen = True

    has_login = any(kw in path for kw in ACTION_PATH_KEYWORDS) or has_hash_email

    return {
        'host': host,
        'has_ip': has_ip,
        'has_tld': has_tld,
        'has_shortener': has_shortener,
        'has_impersonation': has_impersonation,
        'has_suspicious_hyphen': has_suspicious_hyphen,
        'has_login': has_login,
        'has_hash_email': has_hash_email,
        'has_port_padding': has_port_padding,
        'has_cloud_abuse': has_cloud_abuse,
        'is_legit': is_legit
    }

def extract_basic_features(text, attachments=None):
    """Extract comprehensive features for phishing detection including domain analysis, localized threats, and attachment risks."""
    if not text or not isinstance(text, str):
        text = ""
    
    text_lower = text.lower()
    
    # Extract URLs and clean trailing punctuation
    raw_urls = RE_URLS.findall(text)
    urls = [u.rstrip('.,;:)!?"\'') for u in raw_urls]
    
    has_suspicious_tld = False
    has_url_shortener = False
    has_ip_in_url = False
    has_brand_impersonation = False
    has_login_path = False
    has_suspicious_domain_hyphen = False
    has_unverified_url = False
    all_urls_legit = (len(urls) > 0)
    
    for url in urls:
        u_info = analyze_single_url(url)
        if u_info['has_ip']:
            has_ip_in_url = True
        if u_info['has_tld']:
            has_suspicious_tld = True
        if u_info['has_shortener']:
            has_url_shortener = True
        if u_info['has_impersonation']:
            has_brand_impersonation = True
        if u_info['has_suspicious_hyphen']:
            has_suspicious_domain_hyphen = True
        if u_info['has_login']:
            has_login_path = True
        if not u_info['is_legit']:
            all_urls_legit = False
            has_unverified_url = True
    
    # Fiscal & Government Coercion
    # Fiscal & Government Coercion (Regex estricto de límites de palabra para evitar falsos positivos como "versatilidad")
    has_fiscal_context = bool(RE_FISCAL_KEYWORDS.search(text))
    
    # Banking, FinTech & Payment Alerts (Límites de palabra para evitar colisiones con palabras como "manipular")
    has_banking_context = bool(RE_BANKING_KEYWORDS.search(text))
    
    # Financial/credential requests (Límites de palabra para evitar falsos positivos como "opinión" con pin)
    requests_credentials = bool(RE_CREDENTIAL_WORDS.search(text))
    
    # Social engineering / urgency tactics
    has_urgency = any(phrase in text_lower for phrase in URGENCY_PHRASES)
    
    # Action requests & Click coercion
    has_action_request = any(ar in text_lower for ar in ACTION_REQUESTS)
    
    # Phishing keywords count
    keyword_matches = sum(1 for kw in ALL_PHISHING_KEYWORDS if kw in text_lower)
    
    # Too-good-to-be-true offers
    has_unrealistic_offer = any(word in text_lower for word in OFFER_WORDS)
    
    # Macro execution lures in text
    macro_lures = ('habilitar macros', 'activar macros', 'enable macros', 'habilitar contenido', 'activar edicion')
    has_macro_lure = any(lure in text_lower for lure in macro_lures)
    
    # Emoji spam
    emoji_count = len(RE_EMOJIS.findall(text))
    
    # Excessive punctuation
    multiple_exclamation = len(RE_EXCLAMATIONS.findall(text))
    multiple_question = len(RE_QUESTIONS.findall(text))
    
    # Greeting mismatch
    has_generic_greeting = any(greeting in text_lower for greeting in GENERIC_GREETINGS)
    
    # Typosquatting in raw text
    has_brand_typo = any(typo in text_lower for typo in BRAND_TYPOS)
    
    # Suspicious attachment scanning
    has_dangerous_attachment = False
    has_double_extension = False
    has_quarantined_attachment = False
    has_financial_archive_lure = False
    has_fake_invoice_attachment = False
    suspicious_attachments = []
    
    if attachments:
        for att in attachments:
            att_clean = str(att).strip().lower()
            clean_name = re.sub(r'\s+', ' ', att_clean).strip('. ')
            
            # Quarantined by mail server
            if 'deleted_attachments.txt' in clean_name:
                has_quarantined_attachment = True
                has_dangerous_attachment = True
                suspicious_attachments.append(att)
                continue
                
            # Compound / double extensions (e.g. .xlsx.txt, .pdf.html.zip)
            dots = clean_name.split('.')
            if len(dots) >= 3:
                ext1 = '.' + dots[-2].lower()
                ext2 = '.' + dots[-1].lower()
                if ext1 in DOC_MEDIA_EXTS and ext2 in MASKING_FINAL_EXTS:
                    has_double_extension = True
                    has_dangerous_attachment = True
                    suspicious_attachments.append(att)
            
            # Dangerous extensions
            if any(clean_name.endswith(ext) for ext in DANGEROUS_EXTS):
                has_dangerous_attachment = True
                suspicious_attachments.append(att)
                
            # Financial archive lure
            if any(clean_name.endswith(ext) for ext in ('.zip', '.rar', '.7z', '.iso', '.img', '.001')):
                if any(k in clean_name for k in ['spei', 'cep', 'comprobante', 'factura', 'cfdi', 'swift', 'pago', 'banca', 'transferencia', 'estado_de_pago']):
                    has_financial_archive_lure = True
                    has_dangerous_attachment = True
                    suspicious_attachments.append(att)
                    
            # HTML disguised as CFDI/Factura
            if (clean_name.endswith('.html') or clean_name.endswith('.htm')) and any(k in clean_name for k in ['factura', 'cfdi', 'comprobante', 'recibo']):
                has_fake_invoice_attachment = True
                has_dangerous_attachment = True
                suspicious_attachments.append(att)
    
    features = {
        'length': len(text),
        'word_count': len(text.split()),
        'uppercase_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
        'digit_count': sum(1 for c in text if c.isdigit()),
        'exclamation_count': text.count('!'),
        'question_count': text.count('?'),
        'url_count': len(urls),
        'urls': urls,
        'all_urls_legit': all_urls_legit,
        'has_unverified_url': has_unverified_url,
        'email_count': len(RE_EMAIL_ADDRS.findall(text)),
        
        # Advanced features
        'has_suspicious_tld': has_suspicious_tld,
        'has_url_shortener': has_url_shortener,
        'has_ip_in_url': has_ip_in_url,
        'has_brand_impersonation': has_brand_impersonation,
        'has_login_path': has_login_path,
        'has_suspicious_domain_hyphen': has_suspicious_domain_hyphen,
        'has_fiscal_context': has_fiscal_context,
        'has_banking_context': has_banking_context,
        'keyword_matches': keyword_matches,
        'has_urgency': has_urgency,
        'has_action_request': has_action_request,
        'requests_credentials': requests_credentials,
        'has_unrealistic_offer': has_unrealistic_offer,
        'has_macro_lure': has_macro_lure,
        'emoji_count': emoji_count,
        'multiple_exclamation': multiple_exclamation,
        'multiple_question': multiple_question,
        'has_generic_greeting': has_generic_greeting,
        'has_brand_typo': has_brand_typo,
        'has_dangerous_attachment': has_dangerous_attachment,
        'has_double_extension': has_double_extension,
        'has_quarantined_attachment': has_quarantined_attachment,
        'has_financial_archive_lure': has_financial_archive_lure,
        'has_fake_invoice_attachment': has_fake_invoice_attachment,
        'suspicious_attachments': suspicious_attachments,
        'attachment_count': len(attachments) if attachments else 0,
    }
    
    return features

def get_hf_embeddings(text):
    """Get text embeddings from HuggingFace API."""
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    
    response = requests.post(
        f"{HF_API_URL}{EMBEDDING_MODEL}",
        headers=headers,
        json={"inputs": text}
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        logger.error(f"HF API error: {response.status_code} - {response.text}")
        return None

def check_urls_with_safe_browsing(urls):
    """
    Check URLs against Google Safe Browsing API.
    
    Args:
        urls: List of URLs to check
        
    Returns:
        dict: {
            'malicious_urls': list of malicious URLs found,
            'threats_found': list of threat types,
            'is_safe': bool
        }
    """
    if not urls or not GOOGLE_SAFE_BROWSING_API_KEY:
        return {
            'malicious_urls': [],
            'threats_found': [],
            'is_safe': True,
            'api_available': bool(GOOGLE_SAFE_BROWSING_API_KEY)
        }
    
    # Prepare the request payload
    threat_entries = [{"url": url} for url in urls]
    
    payload = {
        "client": {
            "clientId": "dory-phishing-detector",
            "clientVersion": "2.1"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries
        }
    }
    
    try:
        response = requests.post(
            f"{GOOGLE_SAFE_BROWSING_URL}?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            
            # Parse the response
            matches = result.get('matches', [])
            malicious_urls = []
            threats_found = []
            
            for match in matches:
                url = match.get('threat', {}).get('url', '')
                threat_type = match.get('threatType', '')
                
                if url and url not in malicious_urls:
                    malicious_urls.append(url)
                
                if threat_type and threat_type not in threats_found:
                    # Convert threat type to user-friendly name
                    threat_mapping = {
                        'MALWARE': 'Malware',
                        'SOCIAL_ENGINEERING': 'Phishing/Social Engineering',
                        'UNWANTED_SOFTWARE': 'Unwanted Software',
                        'POTENTIALLY_HARMFUL_APPLICATION': 'Harmful Application'
                    }
                    threats_found.append(threat_mapping.get(threat_type, threat_type))
            
            return {
                'malicious_urls': malicious_urls,
                'threats_found': threats_found,
                'is_safe': len(malicious_urls) == 0,
                'api_available': True
            }
        else:
            logger.error(f"Google Safe Browsing API error: {response.status_code}")
            return {
                'malicious_urls': [],
                'threats_found': [],
                'is_safe': True,
                'api_available': True,
                'error': f"API returned {response.status_code}"
            }
            
    except requests.exceptions.Timeout:
        logger.warning("Google Safe Browsing API timeout")
        return {
            'malicious_urls': [],
            'threats_found': [],
            'is_safe': True,
            'api_available': True,
            'error': 'API timeout'
        }
    except Exception as e:
        logger.error(f"Google Safe Browsing API error: {str(e)}")
        return {
            'malicious_urls': [],
            'threats_found': [],
            'is_safe': True,
            'api_available': True,
            'error': str(e)
        }

def predict_phishing_hf(text, attachments=None, raw_html="", email_info=None):
    """
    Enhanced prediction using calibrated multi-tier heuristics + Google Safe Browsing
    + Automated Second-Pass Deep Inspection Filter (L2) for the intermediate zone (26-40 pts).
    Returns probability score from 0 (legitimate) to 1 (phishing).
    """
    # Extract comprehensive features
    features = extract_basic_features(text, attachments=attachments)
    
    # Clean extracted URLs & merge with raw_html hrefs and email_info
    urls = list(features.get('urls', []))
    if raw_html:
        href_urls = re.findall(r'href=["\'](https?://[^"\']+|www\.[^"\']+)["\']', raw_html, flags=re.IGNORECASE)
        for hu in href_urls:
            clean_hu = hu.rstrip('.,;:)!?"\'')
            if clean_hu and clean_hu not in urls:
                urls.append(clean_hu)
    if email_info and email_info.get('urls'):
        for eu in email_info['urls']:
            clean_eu = eu.rstrip('.,;:)!?"\'')
            if clean_eu and clean_eu not in urls:
                urls.append(clean_eu)
    
    # Re-evaluate features based on merged URLs
    for url in urls:
        u_info = analyze_single_url(url)
        if u_info['has_ip']: features['has_ip_in_url'] = True
        if u_info['has_tld']: features['has_suspicious_tld'] = True
        if u_info['has_shortener']: features['has_url_shortener'] = True
        if u_info['has_impersonation']: features['has_brand_impersonation'] = True
        if u_info['has_suspicious_hyphen']: features['has_suspicious_domain_hyphen'] = True
        if u_info['has_login']: features['has_login_path'] = True
        if u_info.get('has_hash_email'): features['has_hash_email'] = True
        if u_info.get('has_port_padding'): features['has_port_padding'] = True
        if u_info.get('has_cloud_abuse'): features['has_cloud_abuse'] = True
        if not u_info['is_legit']:
            features['all_urls_legit'] = False
            features['has_unverified_url'] = True
    features['urls'] = urls
    features['url_count'] = len(urls)

    # Check URLs with Google Safe Browsing API (if configured)
    safe_browsing_result = check_urls_with_safe_browsing(urls)
    
    score = 0
    threats = []
    
    subject_str = (email_info.get('subject') if email_info else '') or ''
    sender_str = (email_info.get('sender_email') if email_info else '') or ''
    x_spam_status = (email_info.get('x_spam_status') if email_info else '') or ''
    x_spam_flag = (email_info.get('x_spam_flag') if email_info else '') or ''
    x_virus_status = (email_info.get('x_virus_status') if email_info else '') or ''

    # === TIER 1: Critical Indicators (30-65 points) ===
    # 1. Perimeter Antivirus & Mail Server Threat Flags
    if RE_AV_SUBJECT_ALERT.search(subject_str) or RE_AV_SUBJECT_ALERT.search(text[:300]):
        score += 65
        threats.append('Mail server perimeter antivirus alert in subject (Malware/Trojan/Exploit signature)')
    elif 'yes' in x_spam_status.lower() or 'yes' in x_spam_flag.lower() or 'infected' in x_virus_status.lower():
        score += 50
        threats.append('Perimeter spam/threat flag confirmed in mail headers (X-Spam-Status / X-Virus)')

    if safe_browsing_result.get('api_available') and not safe_browsing_result.get('is_safe', True):
        score += 50
        for threat in safe_browsing_result.get('threats_found', []):
            threats.append(f'Google Safe Browsing: {threat}')

    # Threat Intelligence Feeds (URLhaus, Regional Mexico CERT-MX, Corpus)
    try:
        from threat_feed_sync import ThreatIntelligenceFeedManager
        is_threat_feed, feed_threats = ThreatIntelligenceFeedManager.check_indicators(urls)
        if is_threat_feed:
            score += 50
            threats.extend(feed_threats)
    except Exception as e:
        logger.debug(f"Threat intelligence lookup error: {e}")
            
    # Attachment Threats
    if features.get('has_quarantined_attachment'):
        score += 55
        threats.append('Mail server policy quarantined/deleted executable attachment (deleted_attachments.txt)')

    if features.get('has_double_extension'):
        score += 50
        threats.append(f'Deceptive compound/double-extension file attachment ({", ".join(features["suspicious_attachments"])})')
    elif features.get('has_financial_archive_lure'):
        score += 45
        threats.append(f'High-risk archive masquerading as Mexican financial document/CFDI ({", ".join(features["suspicious_attachments"])})')
    elif features.get('has_fake_invoice_attachment'):
        score += 45
        threats.append(f'HTML file masquerading as electronic invoice ({", ".join(features["suspicious_attachments"])})')
    elif features.get('has_dangerous_attachment'):
        score += 45
        threats.append(f'High-risk file attachment ({", ".join(features["suspicious_attachments"])})')
        if features.get('has_macro_lure'):
            score += 15
            threats.append('Macro activation lure for dangerous attachment')

    # Advanced URL Evasion: Port Padding Attack
    if features.get('has_port_padding'):
        score += 55
        threats.append('Port padding zero-evasion attack detected in URL')

    # Cloud Storage Abuse for Phishing / CFDI
    has_cfdi_lure = bool(RE_FISCAL_CFDI.search(subject_str) or RE_FISCAL_CFDI.search(text[:800]))
    if features.get('has_cloud_abuse'):
        if has_cfdi_lure:
            score += 40
            threats.append('Cloud storage host abused for fake fiscal/CFDI invoice download')
        else:
            score += 25
            threats.append('Public cloud hosting subdomain used for external redirect/phishing kit')

    if features.get('has_url_shortener') and has_cfdi_lure:
        score += 35
        threats.append('URL shortener concealing fake fiscal/CFDI invoice link')

    # Automated Bot Campaign ID in Subject
    if RE_CAMPAIGN_ID.search(subject_str):
        score += 40
        threats.append('Automated phishing campaign batch identifier detected in subject')

    # Extortion & Financial Scams
    if RE_EXTORTION.search(text) or RE_EXTORTION.search(subject_str):
        score += 45
        threats.append('Extortion / blackmail scam pattern detected')

    if RE_WORK_FROM_HOME_SCAM.search(subject_str) or RE_WORK_FROM_HOME_SCAM.search(text):
        score += 45
        threats.append('Work-from-home financial scam lure detected')

    if RE_LOGISTICS.search(subject_str) and any(att for att in (attachments or []) if any(str(att).lower().endswith(x) for x in ['.docx', '.doc', '.xlsx', '.zip', '.html', '.scr'])):
        score += 35
        threats.append('Fake logistics delivery lure with dangerous/office attachment')

    if ('no pagada' in subject_str.lower() or 'segundo aviso' in subject_str.lower()):
        if score < 40 and not sender_str.endswith('@quimicaboss.com.mx'):
            score += 30
            threats.append('Fiscal urgency coercion tactic (No pagada / Segundo aviso)')

    if features.get('has_hash_email'):
        score += 40
        threats.append('Target email embedded in URL fragment (Credential harvesting kit signature)')

    if features['has_ip_in_url']:
        score += 35
        threats.append('IP address in URL')
        
    if features['has_brand_impersonation']:
        score += 35
        threats.append('Brand impersonation in domain')
        
    if features['requests_credentials'] and features['has_unverified_url']:
        score += 30
        threats.append('Credential harvesting link')
    elif features['requests_credentials'] and not features['all_urls_legit']:
        score += 15
        threats.append('Requests credentials')
        
    if features['has_brand_typo']:
        score += 25
        threats.append('Brand name misspelling')

    # === TIER 2: Strong Indicators (20-25 points) ===
    if features['has_suspicious_tld']:
        score += 25
        threats.append('Suspicious domain extension')
        
    if features['has_url_shortener']:
        score += 20
        threats.append('URL shortener detected')
        
    if features['has_urgency']:
        score += 20
        threats.append('Urgent language tactics')
        
    if features['has_unrealistic_offer']:
        score += 20
        threats.append('Too-good-to-be-true offer')

    # === TIER 3: Contextual Indicators (10-15 points) ===
    if features['has_fiscal_context'] and features['has_unverified_url']:
        score += 15
        threats.append('Tax authority / fiscal coercion with unverified link')
    elif features['has_fiscal_context'] and not features['all_urls_legit']:
        score += 5
        
    if features['has_banking_context'] and features['has_unverified_url']:
        score += 15
        threats.append('Banking / transaction alert with unverified link')
    elif features['has_banking_context'] and not features['all_urls_legit']:
        score += 5
        
    if features['has_login_path'] and features['has_unverified_url']:
        score += 12
        threats.append('Suspicious action or login link')
        
    if features['has_suspicious_domain_hyphen']:
        score += 12
        threats.append('Hyphenated lookalike domain')
        
    if features['has_action_request'] and features['has_unverified_url']:
        score += 10
        threats.append('Action request with link')
        
    if features['keyword_matches'] > 4:
        score += 15
        threats.append(f'{features["keyword_matches"]} phishing keywords')
    elif features['keyword_matches'] > 2:
        score += 10
        threats.append(f'{features["keyword_matches"]} phishing keywords')
    elif features['keyword_matches'] > 0:
        score += 5

    # === TIER 4: Minor Indicators (3-8 points) ===
    if features['has_generic_greeting']:
        score += 8
        threats.append('Generic greeting')
        
    if features['uppercase_ratio'] > 0.25:
        score += 6
        threats.append('Excessive capitalization')
        
    if features['exclamation_count'] > 3 or features['multiple_exclamation'] > 0:
        score += 6
        
    if features['multiple_question'] > 0:
        score += 4
        
    if features['emoji_count'] > 3:
        score += 5

    # === Synergistic boost: Composite Phishing Triad ===
    # (Suspicious Link + Urgency/Coercion + Action/Credentials)
    has_phishing_link = (
        features['has_brand_impersonation'] or 
        features['has_suspicious_tld'] or 
        features['has_url_shortener'] or 
        features['has_ip_in_url'] or 
        features['has_login_path']
    )
    has_coercion = (
        features['has_urgency'] or 
        features['has_fiscal_context'] or 
        features['has_banking_context']
    )
    if features['url_count'] > 0 and has_phishing_link and has_coercion:
        score += 15
        threats.append('High-confidence composite phishing pattern')

    # === Whitelist Trust Bonus: All links point to verified official domains ===
    if features['all_urls_legit']:
        score = max(0, score - 20)

    # Normalize score to 0 - 100
    normalized_score = min(score, 100)
    
    # === SEGUNDO FILTRO ESPECIALIZADO: Deep Inspection L2 (Zona Intermedia 26-40 pts) ===
    l2_analysis = None
    if 26 <= normalized_score <= 40:
        try:
            from deep_inspection_l2 import DeepInspectionFilterL2
            l2_res = DeepInspectionFilterL2.analyze(
                text=text,
                urls=urls,
                attachments=attachments,
                raw_html=raw_html,
                email_info=email_info,
                initial_score=normalized_score
            )
            l2_analysis = l2_res
            normalized_score = l2_res['resolved_score']
            if l2_res['l2_threats']:
                threats.extend(l2_res['l2_threats'])
        except Exception as e:
            logger.error(f"Error en ejecución de Filtro L2: {e}")

    # Calibrated 3-Tier Classification:
    # Tier 1 (0 - 25):   Seguro / Confiable (Verde)
    # Tier 2 (26 - 40):  Sospechoso / Advertencia (Ámbar / Naranja)
    # Tier 3 (41 - 100): Phishing Confirmado / Crítico (Rojo)
    if normalized_score <= 25:
        category = 'SAFE'
        category_label_es = 'Seguro'
        category_label_en = 'Safe'
        category_color = '#10b981'
        is_phishing = False
    elif normalized_score <= 40:
        category = 'SUSPICIOUS'
        category_label_es = 'Sospechoso / Advertencia'
        category_label_en = 'Suspicious / Warning'
        category_color = '#ea580c'
        is_phishing = False
    else:
        category = 'PHISHING'
        category_label_es = 'Phishing Confirmado'
        category_label_en = 'Confirmed Phishing'
        category_color = '#dc2626'
        is_phishing = True
    
    # Calibrated confidence value
    if normalized_score > 40:
        confidence = min(max(normalized_score / 100.0, 0.65), 0.99)
    elif normalized_score <= 25:
        confidence = min(max((100.0 - normalized_score) / 100.0, 0.65), 0.99)
    else:
        confidence = 0.75
        
    return {
        'is_phishing': is_phishing,
        'category': category,
        'category_label_es': category_label_es,
        'category_label_en': category_label_en,
        'category_color': category_color,
        'confidence': round(confidence, 2),
        'risk_score': normalized_score,
        'max_possible_score': 100,
        'features': features,
        'threats': threats,
        'safe_browsing': safe_browsing_result,
        'l2_analysis': l2_analysis
    }

# --- Routes ---
@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for Render and Merlin Orchestrator."""
    reports_count = 0
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=5.0)
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM incoming_phishing_reports')
        reports_count = cur.fetchone()[0]
        conn.close()
    except Exception:
        pass

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
        # Debug logging
        print(f"DEBUG: Request content type: {request.content_type}")
        if request.is_json:
            print(f"DEBUG: JSON data: {request.get_json()}")
        else:
            print(f"DEBUG: Form data: {request.form}")

        # Check if JSON or form data
        if request.is_json:
            data = request.get_json()
            
            # Robustness: Handle case where get_json() returns None
            if data is None:
                try:
                    import json
                    data = json.loads(request.get_data(as_text=True))
                    print(f"DEBUG: Manually parsed JSON: {data}")
                except Exception as e:
                    print(f"DEBUG: Failed to manually parse JSON: {e}")
                    data = {}

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

        # Get prediction from calibrated engine using sanitized text
        result = predict_phishing_hf(text_to_analyze, attachments=attachments)
        
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
        data = request.get_json()
        
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
        conn = sqlite3.connect(DATABASE_PATH)
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
    """Check if username/password is valid."""
    # Simple authentication - in production, use environment variables
    admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_pass = os.environ.get('ADMIN_PASSWORD', 'dory2024')
    return username == admin_user and password == admin_pass

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
        conn = sqlite3.connect(DATABASE_PATH)
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
        conn = sqlite3.connect(DATABASE_PATH)
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
def mail_status():
    """Get status of the automated email inbox service and database counts."""
    try:
        from mail_service import MailConfig
        cfg = MailConfig()
        
        conn = sqlite3.connect(DATABASE_PATH)
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
def mail_simulate():
    """Simulate an incoming email and return the generated security report."""
    try:
        data = request.get_json() or {}
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
def mail_reports():
    """List recent incoming email reports from the corporate phishing corpus."""
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        conn = sqlite3.connect(DATABASE_PATH)
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

# Webhook secret for Cloudflare Worker & external tunnels
DORY_WEBHOOK_SECRET = os.environ.get('DORY_WEBHOOK_SECRET', 'dory-sec-defense-key-2026')

@app.route('/api/mail/inbound', methods=['POST'])
def mail_inbound():
    """
    Ingesta directa de correos RFC822 desde Cloudflare Email Worker vía Tunnel.
    Recibe el flujo MIME raw, lo analiza con Dory AI Engine + Deep Inspection L2
    y lo almacena en feedback.db.
    """
    try:
        # Validación opcional de cabecera secreta
        provided_key = request.headers.get('X-Dory-Key', '')
        if provided_key and provided_key != DORY_WEBHOOK_SECRET:
            logger.warning(f"Intento de acceso no autorizado a /api/mail/inbound desde {request.remote_addr}")
            return jsonify({'error': 'Unauthorized: invalid X-Dory-Key'}), 403

        raw_data = request.get_data()
        if not raw_data:
            return jsonify({'error': 'Empty email payload received'}), 400

        from mail_service import MailMonitorWorker, save_incoming_report
        worker = MailMonitorWorker()
        
        # Procesar con motor de IA y L2
        result = worker.process_single_message(raw_data)
        
        # Sanitizar cuerpo de correo con Escudo de Privacidad antes de persistir en feedback.db
        from privacy_shield import PrivacyShield
        if 'email_body' in result['db_payload'] and result['db_payload']['email_body']:
            shield_res = PrivacyShield.anonymize_text(result['db_payload']['email_body'])
            result['db_payload']['email_body'] = shield_res['sanitized_text']

        # Almacenar en feedback.db
        record_id = save_incoming_report(result['db_payload'])
        
        logger.info(
            f"✅ [INBOUND DORY] Correo procesado #{record_id} de '{result['email_info']['sender_email']}' | "
            f"Asunto: '{result['email_info']['subject']}' | "
            f"Dictamen: {result['prediction']['is_phishing']} (Score: {result['prediction']['risk_score']}) | "
            f"Tiempo: {result['processing_time_ms']}ms"
        )
        
        return jsonify({
            'status': 'success',
            'record_id': record_id,
            'sender': result['email_info']['sender_email'],
            'subject': result['email_info']['subject'],
            'is_phishing': result['prediction']['is_phishing'],
            'risk_score': result['prediction']['risk_score'],
            'confidence': result['prediction']['confidence'],
            'threats': result['prediction'].get('threats', []),
            'urls_found': result['email_info'].get('urls', []),
            'processing_time_ms': result['processing_time_ms']
        }), 200

    except Exception as e:
        logger.error(f"Error procesando correo entrante en /api/mail/inbound: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

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

if __name__ == '__main__':
    # Development server
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)


