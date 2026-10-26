#!/usr/bin/env python3
"""
deep_inspection_l2.py - Segundo Filtro Especializado de Inspección Profunda (Dory.lat)

Módulo de segunda etapa activado de forma 100% automatizada cuando un correo
obtiene una puntuación preliminar en la zona intermedia (Tier 2: 26 - 40 puntos / Sospechoso).

Inspecciona:
1. Homoglifos Unicode y caracteres invisibles (Zero-Width Evasion).
2. Redirecciones abiertas (Open Redirects) y ofuscación de subdominios.
3. Técnicas de ocultamiento HTML (font-size:0, display:none).
4. Suplantación de identidad ejecutiva (BEC - Business Email Compromise).

Efectúa resolución automatizada:
- Escalamiento a Tier 3 (> 40 pts, Phishing Confirmado) si detecta artilugios de evasión.
- Desescalamiento a Tier 1 (<= 25 pts, Seguro / Certificado L2) si la estructura es legítima.
"""

import re
import urllib.parse
import unicodedata
import math
import io
import os
import zipfile
import hashlib
import base64
import time
import collections
import logging
from typing import Dict, List, Any, Optional

try:
    import requests
except ImportError:
    requests = None

# Cargar .env si está disponible
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
except ImportError:
    pass

logger = logging.getLogger("deep_inspection_l2")

# Cache global en memoria para consultas de VirusTotal (evita duplicar llamadas)
_VT_CACHE: Dict[str, Dict[str, Any]] = {}
_VT_REQUEST_TIMESTAMPS = collections.deque()
_VT_MAX_PER_MINUTE = 4

def _can_query_virustotal() -> bool:
    """Verifica si no se supera el límite de tasa de la API pública de VirusTotal (4 req/min)."""
    api_key = os.environ.get('VIRUSTOTAL_API_KEY', '').strip()
    if not api_key or requests is None:
        return False
    now = time.time()
    while _VT_REQUEST_TIMESTAMPS and now - _VT_REQUEST_TIMESTAMPS[0] > 60.0:
        _VT_REQUEST_TIMESTAMPS.popleft()
    return len(_VT_REQUEST_TIMESTAMPS) < _VT_MAX_PER_MINUTE

def _record_virustotal_query():
    _VT_REQUEST_TIMESTAMPS.append(time.time())

def query_virustotal_file_hash(sha256: str) -> Optional[Dict[str, Any]]:
    """Consulta pasiva por hash SHA256 en VirusTotal (v3 Files endpoint)."""
    sha256 = sha256.lower().strip()
    if sha256 in _VT_CACHE:
        return _VT_CACHE[sha256]
    api_key = os.environ.get('VIRUSTOTAL_API_KEY', '').strip()
    if not api_key or not _can_query_virustotal():
        return None
    try:
        _record_virustotal_query()
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={'x-apikey': api_key},
            timeout=3.5
        )
        if resp.status_code == 200:
            stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            res = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
            }
            _VT_CACHE[sha256] = res
            return res
        elif resp.status_code == 404:
            res = {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'not_found': True}
            _VT_CACHE[sha256] = res
            return res
    except Exception as e:
        logger.debug(f"Error consultando VirusTotal para hash {sha256}: {e}")
    return None

def query_virustotal_url(url: str) -> Optional[Dict[str, Any]]:
    """Consulta pasiva de URL en VirusTotal (v3 URLs endpoint vía URL-id base64url)."""
    url = url.strip()
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    if url_id in _VT_CACHE:
        return _VT_CACHE[url_id]
    api_key = os.environ.get('VIRUSTOTAL_API_KEY', '').strip()
    if not api_key or not _can_query_virustotal():
        return None
    try:
        _record_virustotal_query()
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={'x-apikey': api_key},
            timeout=3.5
        )
        if resp.status_code == 200:
            stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            res = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
            }
            _VT_CACHE[url_id] = res
            return res
        elif resp.status_code == 404:
            res = {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'not_found': True}
            _VT_CACHE[url_id] = res
            return res
    except Exception as e:
        logger.debug(f"Error consultando VirusTotal para URL: {e}")
    return None

def calculate_entropy(s: str) -> float:
    """Calcula la entropía Shannon de una cadena de caracteres."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

# Caracteres homógrafos comunes (cirílicos/griegos que simulan latinos)
HOMOGLYPH_CYRILLIC_TO_LATIN = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0458': 'j', '\u0455': 's', '\u0410': 'A', '\u0412': 'B',
    '\u0415': 'E', '\u041a': 'K', '\u041c': 'M', '\u041d': 'H',
    '\u041e': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
    '\u0425': 'X'
}

# Caracteres invisibles y de ancho cero usados para romper firmas regex
ZERO_WIDTH_CHARS = {
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\ufeff',  # Byte order mark / zero-width no-break space
    '\u00ad',  # Soft hyphen
    '\u2060',  # Word joiner
    '\u200e',  # Left-to-right mark
    '\u200f',  # Right-to-left mark
}

# Parámetros comunes de redirección abierta
REDIRECT_PARAMS = ('url', 'redirect', 'redirect_to', 'next', 'target', 'dest', 'destination', 'goto', 'return', 'r', 'link', 'uri')

# Redireccionadores y destinos corporativos autorizados para evitar falsos positivos
TRUSTED_REDIRECTORS = frozenset([
    'redirect-url.email', 'google.com', 'linkedin.com', 'l.messenger.com'
])
TRUSTED_DESTINATIONS = frozenset([
    'quimicaboss.com.mx', 'quimicaboss.odoo.com', 'odoo.com', 'apperp.site'
])

# Cargos y directivos institucionales de Química Boss protegidos contra BEC
PROTECTED_VIP_ROLES = (
    'director general', 'direccion general', 'gerencia de finanzas', 'finanzas quimica boss',
    'contraloria', 'auditoria interna', 'carlos aceves', 'ing. carlos aceves', 'recursos humanos quimica boss'
)


class DeepInspectionFilterL2:
    """Motor de inspección especializada de segunda pasada para correos en zona intermedia (26-40 pts)."""

    @classmethod
    def check_homoglyphs_and_invisible_chars(cls, text: str, urls: List[str]) -> Dict[str, Any]:
        """Detecta caracteres invisibles y sustituciones de homoglifos entre alfabetos."""
        findings = []
        invisible_count = 0
        homoglyph_detected = False

        # 1. Chequeo de caracteres de ancho cero
        for char in text:
            if char in ZERO_WIDTH_CHARS:
                invisible_count += 1

        if invisible_count > 0:
            findings.append(f"Detectados {invisible_count} caracteres invisibles de ancho cero (intento de evasión de firmas)")

        # 2. Chequeo de caracteres cirílicos/griegos mezclados en palabras latinas
        for word in text.split():
            # Limpiar puntuación
            clean_word = re.sub(r'[^\w]', '', word)
            if len(clean_word) >= 4:
                scripts = set()
                for ch in clean_word:
                    try:
                        name = unicodedata.name(ch)
                        if 'LATIN' in name:
                            scripts.add('LATIN')
                        elif 'CYRILLIC' in name:
                            scripts.add('CYRILLIC')
                        elif 'GREEK' in name:
                            scripts.add('GREEK')
                    except ValueError:
                        pass
                
                if len(scripts) > 1:
                    homoglyph_detected = True
                    findings.append(f"Sustitución de homoglifo detectada en palabra: '{clean_word}'")
                    break

        # 3. Chequeo en dominios de URLs
        for u in urls:
            try:
                parsed = urllib.parse.urlparse(u)
                hostname = parsed.hostname or ''
                if any(ord(c) > 127 for c in hostname):
                    try:
                        ascii_host = hostname.encode('idna').decode('ascii')
                        if ascii_host.startswith('xn--'):
                            findings.append(f"Dominio internacionalizado sospechoso (Punycode): {hostname} -> {ascii_host}")
                            homoglyph_detected = True
                    except Exception:
                        pass
            except Exception:
                pass

        return {
            'has_invisible_chars': invisible_count > 0,
            'invisible_count': invisible_count,
            'has_homoglyphs': homoglyph_detected,
            'findings': findings
        }

    @classmethod
    def check_evasive_redirects_and_url_depth(cls, urls: List[str]) -> Dict[str, Any]:
        """Detecta parámetros de redirección abierta y subdominios anómalos de alta profundidad."""
        findings = []
        has_open_redirect = False
        has_excessive_subdomains = False

        for u in urls:
            try:
                parsed = urllib.parse.urlparse(u)
                hostname = (parsed.hostname or '').lower()
                query = parsed.query or ''

                # Detección de sintaxis user:pass@host engañosa
                if '@' in parsed.netloc.split(':')[0]:
                    findings.append(f"Ofuscación de URL con credenciales embebidas (@): {u}")
                    has_open_redirect = True

                # Detección de redirección abierta en query params
                if query:
                    params = urllib.parse.parse_qs(query)
                    for rp in REDIRECT_PARAMS:
                        if rp in params:
                            for val in params[rp]:
                                if val.startswith('http://') or val.startswith('https://') or val.startswith('//'):
                                    target_parsed = urllib.parse.urlparse(val)
                                    target_host = (target_parsed.hostname or '').lower()
                                    if target_host and target_host != hostname:
                                        is_trusted_redir = (hostname in TRUSTED_REDIRECTORS or any(hostname.endswith('.' + t) for t in TRUSTED_REDIRECTORS))
                                        is_trusted_dest = (target_host in TRUSTED_DESTINATIONS or any(target_host.endswith('.' + t) for t in TRUSTED_DESTINATIONS))
                                        if is_trusted_redir and is_trusted_dest:
                                            continue
                                        findings.append(f"Redirección abierta detectada: {hostname} redirige externamente a {target_host}")
                                        has_open_redirect = True

                # Detección de profundidad excesiva de subdominios
                parts = hostname.split('.')
                if len(parts) >= 4 and not parts[-1].isdigit():
                    # Ignorar casos estándar como .com.mx (3 partes: sub.dominio.com.mx = 4 partes)
                    non_tld_parts = [p for p in parts if p not in ('com', 'org', 'net', 'edu', 'gob', 'mx')]
                    if len(non_tld_parts) >= 3:
                        has_excessive_subdomains = True
                        findings.append(f"Subdominio de alta profundidad o estructura en capas: {hostname}")

            except Exception:
                pass

        return {
            'has_open_redirect': has_open_redirect,
            'has_excessive_subdomains': has_excessive_subdomains,
            'findings': findings
        }

    @classmethod
    def check_html_obfuscation(cls, raw_html: str, email_info: Optional[Dict[str, Any]] = None, urls: Optional[List[str]] = None) -> Dict[str, Any]:
        """Inspecciona el código HTML en busca de texto señuelo oculto mediante CSS o etiquetas manipuladas."""
        if not raw_html:
            return {'has_html_obfuscation': False, 'findings': []}

        findings = []
        has_obfuscation = False

        # Remover bloques <style>...</style> ya que las media queries responsive usan display:none legítimamente
        html_body_only = re.sub(r'<style.*?>.*?</style>', '', raw_html, flags=re.DOTALL | re.IGNORECASE)
        # Remover preheaders estándar de newsletters y correos transaccionales (display:none con max-height:0 o overflow:hidden)
        html_cleaned = re.sub(r'<(?:div|span)[^>]*style=["\'][^"\']*(?:max-height:\s*0|overflow:\s*hidden)[^"\']*["\'][^>]*>.*?</(?:div|span)>', '', html_body_only, flags=re.DOTALL | re.IGNORECASE)
        html_cleaned = re.sub(r'<(?:div|span)[^>]*class=["\'][^"\']*preheader[^"\']*["\'][^>]*>.*?</(?:div|span)>', '', html_cleaned, flags=re.DOTALL | re.IGNORECASE)

        # Comentarios HTML intercalados para romper palabras clave (técnica maliciosa de fragmentación)
        comment_splices = re.findall(r'[a-zA-Z]{1,4}<!--.*?-->[a-zA-Z]{1,4}', raw_html, flags=re.DOTALL)
        if comment_splices:
            has_obfuscation = True
            findings.append(f"Comentarios HTML intercalados para fragmentar palabras clave ({len(comment_splices)} instancias)")

        # Verificar si el remitente o los enlaces pertenecen a un ecosistema legítimo verificado
        sender_email = ((email_info or {}).get('sender_email') or '').lower()
        sender_host = sender_email.split('@')[-1] if '@' in sender_email else ''
        is_trusted_sender = False
        try:
            from dory_engine import LEGIT_DOMAINS
            legit_set = LEGIT_DOMAINS
        except Exception:
            legit_set = TRUSTED_DESTINATIONS

        if sender_host:
            is_trusted_sender = (sender_host in TRUSTED_DESTINATIONS) or (sender_host in legit_set) or any(sender_host.endswith('.' + d) for d in legit_set)

        # Patrones de texto oculto CSS en el contenido del cuerpo
        hidden_css_patterns = [
            r'font-size\s*:\s*0px?',
            r'display\s*:\s*none',
            r'visibility\s*:\s*hidden',
            r'color\s*:\s*transparent',
            r'color\s*:\s*rgba\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)',
            r'opacity\s*:\s*0(?:;|\b)'
        ]

        for pat in hidden_css_patterns:
            matches = re.findall(pat, html_cleaned, flags=re.IGNORECASE)
            if matches:
                # Si el remitente es de un dominio legítimo verificado y el patrón es solo display:none, es estilización responsive
                if is_trusted_sender and pat == r'display\s*:\s*none':
                    continue
                has_obfuscation = True
                findings.append(f"Elemento HTML con estilo de texto invisible/oculto ({matches[0]})")
                break

        return {
            'has_html_obfuscation': has_obfuscation,
            'findings': findings
        }

    @classmethod
    def check_bec_executive_impersonation(cls, email_info: Dict[str, Any], text: str) -> Dict[str, Any]:
        """Detecta ataques de Fraude del CEO (BEC) donde el remitente simula ser un directivo pero usa un buzón externo."""
        findings = []
        is_bec_attempt = False

        sender_name = (email_info.get('sender_name') or '').lower()
        sender_email = (email_info.get('sender_email') or '').lower()
        received_spf = (email_info.get('received_spf') or '').lower()

        # Identificar si el nombre visible invoca un rol ejecutivo de Química Boss
        claims_executive = any(role in sender_name for role in PROTECTED_VIP_ROLES)
        if not claims_executive:
            # Chequeo en la firma o primeras líneas del texto
            header_lines = "\n".join(text.split("\n")[:6]).lower()
            claims_executive = any(role in header_lines for role in PROTECTED_VIP_ROLES)

        if claims_executive:
            # Si dice ser directivo de Química Boss pero la dirección NO termina en @quimicaboss.com.mx
            if not sender_email.endswith('@quimicaboss.com.mx'):
                is_bec_attempt = True
                findings.append(
                    f"Intento crítico de BEC: Remitente visible simula directivo institucional ({email_info.get('sender_name')}) "
                    f"desde buzón externo no corporativo ({sender_email})"
                )
            elif 'fail' in received_spf or 'softfail' in received_spf:
                is_bec_attempt = True
                findings.append(
                    f"Falsificación de identidad directiva: El remitente declara ser {email_info.get('sender_name')} "
                    f"pero falló la validación criptográfica de autenticación SPF ({received_spf})"
                )

        return {
            'is_bec_attempt': is_bec_attempt,
            'findings': findings
        }

    @classmethod
    def check_advanced_url_threats(cls, urls: List[str], raw_html: str = "") -> Dict[str, Any]:
        """
        Motor 5: Análisis Forense Avanzado de URLs.
        - Discrepancia entre texto visible de ancla y destino real href (Anchor Mismatch).
        - Puertos no estándar (8080, 8443, 2082, etc.) típicos de phishing kits.
        - Ofuscación maliciosa en URL (doble codificación %25, data URI base64).
        - DGA / Dominios generados algorítmicamente con alta entropía Shannon.
        - Parámetros sospechosos de recolección de credenciales (?email=, ?user=).
        """
        findings = []
        has_url_threat = False

        # 1. Discrepancia en HTML (Texto visible vs Destino real href)
        if raw_html:
            anchor_pattern = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
            for match in anchor_pattern.finditer(raw_html):
                href = match.group(1).strip()
                visible_text = re.sub(r'<[^>]+>', '', match.group(2)).strip()
                
                # Si el texto visible parece un dominio o URL (ej. www.quimicaboss.com.mx o sat.gob.mx)
                if re.search(r'\b(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?\b', visible_text):
                    try:
                        vis_clean = visible_text if visible_text.startswith(('http://', 'https://')) else 'http://' + visible_text
                        vis_host = (urllib.parse.urlparse(vis_clean).hostname or '').lower()
                        
                        href_clean = href if href.startswith(('http://', 'https://')) else 'http://' + href
                        href_host = (urllib.parse.urlparse(href_clean).hostname or '').lower()
                        
                        if vis_host and href_host and vis_host != href_host:
                            vis_base = ".".join(vis_host.split('.')[-2:])
                            href_base = ".".join(href_host.split('.')[-2:])
                            if vis_base != href_base:
                                has_url_threat = True
                                findings.append(
                                    f"Discrepancia crítica de Enlace (Engaño Visual): El texto muestra '{vis_host}' pero el destino real dirige a '{href_host}'"
                                )
                    except Exception:
                        pass

        # 2. Análisis forense de cada URL
        SUSPICIOUS_PORTS = {8080, 8443, 8888, 2082, 2083, 2086, 2087, 3000, 5000, 8000, 9000, 4444}
        CREDENTIAL_QUERY_PARAMS = {'email', 'user', 'username', 'login', 'account', 'recipient', 'target', 'mail'}

        for u in urls:
            try:
                parsed = urllib.parse.urlparse(u)
                hostname = (parsed.hostname or '').lower()
                port = parsed.port
                query = parsed.query or ''

                # A. Puertos no estándar
                if port and port in SUSPICIOUS_PORTS:
                    has_url_threat = True
                    findings.append(f"Puerto no estándar en URL ({hostname}:{port}): Asociado a servidores web o paneles comprometidos")

                # B. Doble codificación o data URI en URL
                if '%25' in u or 'data:text/html' in u.lower() or 'javascript:' in u.lower():
                    has_url_threat = True
                    findings.append(f"Ofuscación maliciosa en URL (doble codificación o data URI): {u[:60]}...")

                # C. Entropía Shannon en el nombre de dominio (DGA / Dominios efímeros)
                parts = hostname.split('.')
                if len(parts) >= 2:
                    sub_or_domain = parts[0]
                    if len(sub_or_domain) >= 10:
                        ent = calculate_entropy(sub_or_domain)
                        if ent >= 3.65:
                            has_url_threat = True
                            findings.append(f"Alta entropía en dominio ({hostname}, {ent:.2f} bits): Patrón de DGA o dominio de ataque efímero")

                # D. Parámetros de recolección de credenciales
                if query:
                    params = urllib.parse.parse_qs(query)
                    for param_name, param_vals in params.items():
                        if param_name.lower() in CREDENTIAL_QUERY_PARAMS:
                            for pval in param_vals:
                                if '@' in pval or len(pval) > 25:
                                    has_url_threat = True
                                    findings.append(
                                        f"Parámetro de recolección de credenciales en URL: '?{param_name}={pval[:30]}...'"
                                    )
                                    break
            except Exception:
                pass

        return {
            'has_url_threat': has_url_threat,
            'findings': findings
        }

    DANGEROUS_ARCHIVE_EXTENSIONS = (
        '.url', '.lnk', '.exe', '.scr', '.pif', '.cpl', '.msi', '.msp',
        '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta',
        '.iso', '.img', '.dmg', '.vhd', '.vhdx'
    )
    SUSPICIOUS_MACRO_EXTENSIONS = (
        '.xlsm', '.docm', '.pptm', '.xltm', '.dotm', '.iqy'
    )

    @classmethod
    def check_in_memory_archives_and_virustotal(
        cls,
        attachments_data: Optional[List[Dict[str, Any]]] = None,
        attachment_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Motor 6: Análisis Forense de Adjuntos Comprimidos (.zip) en Memoria RAM (Zero-Disk)
        y Verificación de Amenazas en VirusTotal.
        """
        findings = []
        has_archive_threat = False
        vt_detections = []
        attachments_data = attachments_data or []
        attachment_names = attachment_names or []

        for att in attachments_data:
            fname = att.get('filename', '')
            payload = att.get('payload') or att.get('data')
            if not payload or not isinstance(payload, bytes):
                continue

            fname_lower = fname.lower()
            is_zip = fname_lower.endswith(('.zip', '.zipx')) or payload[:4] in (b'PK\x03\x04', b'PK\x05\x06')

            if not is_zip:
                # Si es un ejecutable, script o acceso directo directo no comprimido
                if any(fname_lower.endswith(ext) for ext in cls.DANGEROUS_ARCHIVE_EXTENSIONS):
                    has_archive_threat = True
                    sha256 = hashlib.sha256(payload).hexdigest()
                    findings.append(f"Adjunto ejecutable o script de alto riesgo directo: '{fname}'")
                    vt_res = query_virustotal_file_hash(sha256)
                    if vt_res and (vt_res.get('malicious', 0) >= 2 or (vt_res.get('malicious', 0) + vt_res.get('suspicious', 0) >= 2)):
                        mal_count = vt_res['malicious']
                        findings.append(f"VirusTotal confirmó amenaza: '{fname}' detectado como malicioso por {mal_count} motores antivirus (SHA256: {sha256[:16]}...)")
                        vt_detections.append({'file': fname, 'malicious': mal_count, 'sha256': sha256})
                continue

            # Inspección en memoria del archivo ZIP (Zero-Disk)
            zip_sha256 = hashlib.sha256(payload).hexdigest()
            vt_zip = query_virustotal_file_hash(zip_sha256)
            if vt_zip and (vt_zip.get('malicious', 0) >= 2 or (vt_zip.get('malicious', 0) + vt_zip.get('suspicious', 0) >= 2)):
                has_archive_threat = True
                mal_count = vt_zip['malicious']
                findings.append(f"VirusTotal confirmó archivo comprimido malicioso '{fname}' ({mal_count} motores AV detectados, SHA256: {zip_sha256[:16]}...)")
                vt_detections.append({'file': fname, 'malicious': mal_count, 'sha256': zip_sha256})

            try:
                bio = io.BytesIO(payload)
                with zipfile.ZipFile(bio, 'r') as zf:
                    infolist = zf.infolist()
                    # 1. Protección contra Zip Bomb
                    if len(infolist) > 500:
                        has_archive_threat = True
                        findings.append(f"Evasión por anomalía de compresión: El archivo '{fname}' contiene {len(infolist)} elementos (posible Zip Bomb o ofuscación)")
                    
                    total_uncompressed = sum(info.file_size for info in infolist)
                    if total_uncompressed > 50 * 1024 * 1024 and total_uncompressed > len(payload) * 100:
                        has_archive_threat = True
                        findings.append(f"Evasión por ratio de descompresión anómalo en '{fname}' (Posible Zip Bomb > 100:1)")

                    # 2. Inspección elemento por elemento
                    for info in infolist:
                        inner_name = info.filename
                        inner_lower = inner_name.lower().strip()
                        
                        # Archivos cifrados / protegidos con contraseña
                        if info.flag_bits & 0x1:
                            has_archive_threat = True
                            findings.append(f"Archivo ZIP cifrado/protegido con contraseña ('{fname}' -> '{inner_name}'): Técnica habitual para evadir antivirus de pasarela")

                        # Extensión peligrosa interna
                        is_dangerous_inner = any(inner_lower.endswith(ext) for ext in cls.DANGEROUS_ARCHIVE_EXTENSIONS)
                        is_macro_inner = any(inner_lower.endswith(ext) for ext in cls.SUSPICIOUS_MACRO_EXTENSIONS)
                        
                        # Doble extensión interna engañosa
                        parts = inner_lower.rsplit('.', 2)
                        is_double_ext = len(parts) >= 3 and parts[-2] in ('pdf', 'xlsx', 'docx', 'jpg', 'png', 'txt') and parts[-1] in ('exe', 'url', 'lnk', 'vbs', 'jse', 'bat', 'scr')

                        if is_dangerous_inner or is_macro_inner or is_double_ext:
                            has_archive_threat = True
                            findings.append(f"Artefacto malicioso u oculto detectado en ZIP '{fname}' -> '{inner_name}' (Evasión perimetral)")
                            
                            # Si es un acceso directo .url, leerlo en memoria para extraer URL de ataque
                            if inner_lower.endswith('.url'):
                                try:
                                    url_content = zf.read(info).decode('utf-8', errors='ignore')
                                    m_url = re.search(r'URL\s*=\s*([^\r\n]+)', url_content, re.IGNORECASE)
                                    if m_url:
                                        target_url = m_url.group(1).strip()
                                        findings.append(f"Acceso directo malicioso .url dentro del ZIP dirige a: '{target_url}'")
                                        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target_url) or target_url.startswith(('file:', r'\\')):
                                            findings.append(f"Técnica de dropper WebDAV/SMB/IP detectada en .url: '{target_url}'")
                                        if target_url.startswith(('http://', 'https://')):
                                            vt_url_res = query_virustotal_url(target_url)
                                            if vt_url_res and (vt_url_res.get('malicious', 0) >= 1 or vt_url_res.get('suspicious', 0) >= 1):
                                                vt_mal = vt_url_res.get('malicious', 0)
                                                findings.append(f"VirusTotal confirmó URL maliciosa referenciada en el ZIP: {vt_mal} motores detectados ({target_url})")
                                                vt_detections.append({'url': target_url, 'malicious': vt_mal})
                                except Exception as e_url:
                                    logger.debug(f"Error analizando archivo .url interno: {e_url}")

                            # Si el archivo interno es un script o ejecutable, calcular su SHA256 en memoria
                            elif is_dangerous_inner:
                                try:
                                    inner_bytes = zf.read(info)
                                    inner_sha = hashlib.sha256(inner_bytes).hexdigest()
                                    vt_inner = query_virustotal_file_hash(inner_sha)
                                    if vt_inner and (vt_inner.get('malicious', 0) >= 2 or (vt_inner.get('malicious', 0) + vt_inner.get('suspicious', 0) >= 2)):
                                        findings.append(f"VirusTotal confirmó ejecutable interno malicioso '{inner_name}': {vt_inner['malicious']} motores detectados")
                                        vt_detections.append({'file': inner_name, 'malicious': vt_inner['malicious'], 'sha256': inner_sha})
                                except Exception as e_in:
                                    logger.debug(f"Error analizando binario interno en ZIP: {e_in}")

            except zipfile.BadZipFile:
                has_archive_threat = True
                findings.append(f"Archivo ZIP corrupto o manipulado estructuralmente en '{fname}' (Técnica de evasión por desincronización de parser)")
            except Exception as e_zip:
                logger.debug(f"Error inspeccionando ZIP {fname}: {e_zip}")

        return {
            'has_archive_threat': has_archive_threat,
            'findings': findings,
            'vt_detections': vt_detections
        }

    @classmethod
    def analyze(
        cls,
        text: str,
        urls: List[str],
        attachments: Optional[List[str]] = None,
        raw_html: str = "",
        email_info: Optional[Dict[str, Any]] = None,
        initial_score: int = 30,
        attachments_data: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Ejecuta la batería completa de inspección profunda de 2ª etapa (L2).
        Retorna el veredicto resuelto de forma 100% automatizada a través de 6 motores.
        """
        email_info = email_info or {}
        attachments = attachments or []
        if attachments_data is None:
            attachments_data = email_info.get('attachments_data', [])

        res_homo = cls.check_homoglyphs_and_invisible_chars(text, urls)
        res_redir = cls.check_evasive_redirects_and_url_depth(urls)
        res_html = cls.check_html_obfuscation(raw_html, email_info, urls)
        res_bec = cls.check_bec_executive_impersonation(email_info, text)
        res_url = cls.check_advanced_url_threats(urls, raw_html)
        res_archive = cls.check_in_memory_archives_and_virustotal(attachments_data, attachments)

        all_findings = (
            res_homo['findings'] +
            res_redir['findings'] +
            res_html['findings'] +
            res_bec['findings'] +
            res_url['findings'] +
            res_archive['findings']
        )

        has_evasion = (
            res_homo['has_invisible_chars'] or
            res_homo['has_homoglyphs'] or
            res_redir['has_open_redirect'] or
            res_redir['has_excessive_subdomains'] or
            res_html['has_html_obfuscation'] or
            res_bec['is_bec_attempt'] or
            res_url['has_url_threat'] or
            res_archive['has_archive_threat']
        )

        # -------------------------------------------------------------
        # RESOLUCIÓN AUTOMÁTICA DE 2ª ETAPA:
        # -------------------------------------------------------------
        if has_evasion:
            # Caso 1: Se encontraron técnicas de evasión, amenazas de adjunto o suplantación directiva
            # Escalación automática a Tier 3: Phishing Confirmado
            if res_archive['has_archive_threat']:
                resolved_score = 100
            elif res_bec['is_bec_attempt']:
                resolved_score = min(initial_score + 35, 100)
            else:
                resolved_score = min(initial_score + 25, 100)

            status = "ESCALATED_PHISHING"
            resolved_category = "PHISHING"
            verdict_label = "Phishing Confirmado (Evasión Detectada por Filtro L2)"
            threat_labels = [f"[Filtro L2] {f}" for f in all_findings]
            confidence = 0.99 if res_archive['has_archive_threat'] else 0.95
        else:
            # Caso 2: Auditoría profunda exhaustiva limpia
            score_delta = -15
            resolved_score = max(0, initial_score + score_delta)
            
            if resolved_score <= 25:
                status = "DEESCALATED_SAFE"
                resolved_category = "SAFE"
                verdict_label = "Seguro (Certificado y Verificado por Filtro L2)"
            else:
                status = "MAINTAINED_SUSPICIOUS"
                resolved_category = "SUSPICIOUS"
                verdict_label = "Sospechoso (Sin Evasión, Advertencia Habitual)"

            threat_labels = []
            confidence = 0.88

        return {
            'status': status,
            'initial_score': initial_score,
            'resolved_score': resolved_score,
            'resolved_category': resolved_category,
            'verdict_label': verdict_label,
            'has_evasion': has_evasion,
            'l2_findings': all_findings,
            'l2_threats': threat_labels,
            'confidence': confidence,
            'checks_performed': {
                'homoglyphs_and_invisible_chars': not res_homo['has_homoglyphs'] and not res_homo['has_invisible_chars'],
                'evasive_redirects_and_url_depth': not res_redir['has_open_redirect'] and not res_redir['has_excessive_subdomains'],
                'html_obfuscation': not res_html['has_html_obfuscation'],
                'bec_executive_impersonation': not res_bec['is_bec_attempt'],
                'advanced_url_analysis': not res_url['has_url_threat'],
                'in_memory_archive_and_virustotal': not res_archive['has_archive_threat']
            }
        }


