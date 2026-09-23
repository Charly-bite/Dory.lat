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
from typing import Dict, List, Any, Optional

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
    def check_html_obfuscation(cls, raw_html: str) -> Dict[str, Any]:
        """Inspecciona el código HTML en busca de texto señuelo oculto mediante CSS o etiquetas manipuladas."""
        if not raw_html:
            return {'has_html_obfuscation': False, 'findings': []}

        findings = []
        has_obfuscation = False

        # Patrones de texto oculto CSS
        hidden_css_patterns = [
            r'font-size\s*:\s*0px?',
            r'display\s*:\s*none',
            r'visibility\s*:\s*hidden',
            r'color\s*:\s*transparent',
            r'color\s*:\s*rgba\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)',
            r'opacity\s*:\s*0(?:;|\b)'
        ]

        for pat in hidden_css_patterns:
            matches = re.findall(pat, raw_html, flags=re.IGNORECASE)
            if matches:
                has_obfuscation = True
                findings.append(f"Elemento HTML con estilo de texto invisible/oculto ({matches[0]})")
                break

        # Comentarios HTML intercalados para romper palabras clave
        comment_splices = re.findall(r'[a-zA-Z]{1,4}<!--.*?-->[a-zA-Z]{1,4}', raw_html, flags=re.DOTALL)
        if comment_splices:
            has_obfuscation = True
            findings.append(f"Comentarios HTML intercalados para fragmentar palabras clave ({len(comment_splices)} instancias)")

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

    @classmethod
    def analyze(
        cls,
        text: str,
        urls: List[str],
        attachments: Optional[List[str]] = None,
        raw_html: str = "",
        email_info: Optional[Dict[str, Any]] = None,
        initial_score: int = 30
    ) -> Dict[str, Any]:
        """
        Ejecuta la batería completa de inspección profunda de 2ª etapa (L2).
        Retorna el veredicto resuelto de forma 100% automatizada a través de 5 motores.
        """
        email_info = email_info or {}
        attachments = attachments or []

        res_homo = cls.check_homoglyphs_and_invisible_chars(text, urls)
        res_redir = cls.check_evasive_redirects_and_url_depth(urls)
        res_html = cls.check_html_obfuscation(raw_html)
        res_bec = cls.check_bec_executive_impersonation(email_info, text)
        res_url = cls.check_advanced_url_threats(urls, raw_html)

        all_findings = (
            res_homo['findings'] +
            res_redir['findings'] +
            res_html['findings'] +
            res_bec['findings'] +
            res_url['findings']
        )

        has_evasion = (
            res_homo['has_invisible_chars'] or
            res_homo['has_homoglyphs'] or
            res_redir['has_open_redirect'] or
            res_redir['has_excessive_subdomains'] or
            res_html['has_html_obfuscation'] or
            res_bec['is_bec_attempt'] or
            res_url['has_url_threat']
        )

        # -------------------------------------------------------------
        # RESOLUCIÓN AUTOMÁTICA DE 2ª ETAPA:
        # -------------------------------------------------------------
        if has_evasion:
            # Caso 1: Se encontraron técnicas de evasión o suplantación directiva
            # Escalación automática a Tier 3: Phishing Confirmado
            score_delta = 35 if res_bec['is_bec_attempt'] else 25
            resolved_score = min(initial_score + score_delta, 100)
            status = "ESCALATED_PHISHING"
            resolved_category = "PHISHING"
            verdict_label = "Phishing Confirmado (Evasión Detectada por Filtro L2)"
            threat_labels = [f"[Filtro L2] {f}" for f in all_findings]
            confidence = 0.95
        else:
            # Caso 2: Auditoría profunda exhaustiva limpia
            # No hay homoglifos, no hay redirecciones, no hay texto oculto, no hay BEC, no hay amenazas de URL
            # Desescalamiento automático a Tier 1: Seguro
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
                'advanced_url_analysis': not res_url['has_url_threat']
            }
        }

