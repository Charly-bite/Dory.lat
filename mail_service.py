#!/usr/bin/env python3
"""
mail_service.py - Servicio de Monitoreo y Respuesta Automática de Correo (Dory.lat)

Permite a los usuarios de la empresa reenviar o enviar correos sospechosos a un buzón
de ciberseguridad dedicado (ej. desarrollo_qb@quimicaboss.com.mx) y recibir en segundos un correo
automático con el reporte y análisis de phishing, registrándolo en la base de datos corporativa.

Versión 3.5:
- Soporte de Push en Tiempo Real mediante IMAP IDLE (RFC 2177).
- Concurrencia Multi-Hilo con ThreadPoolExecutor.
- Escaneo de Archivos Adjuntos Peligrosos y Dobles Extensiones.
- Análisis de Cabeceras de Autenticación (SPF / DKIM).
- Salvaguardas de Dominio Corporativo y Filtro de Bots.
"""

import os
import sys
import re
import json
import time
import ssl
import select
import logging
import sqlite3
import threading
import imaplib
import smtplib
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from email.header import decode_header
import base64
from email.utils import parseaddr, formatdate, make_msgid, parsedate_to_datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from datetime import datetime

# Configure encoding for Windows terminals
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] [MailService] %(message)s'
)
logger = logging.getLogger("MailService")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, 'mail_config.json')
CONFIG_EXAMPLE = os.path.join(APP_DIR, 'mail_config.example.json')
DATABASE_PATH = os.path.join(APP_DIR, 'feedback.db')
DORY_ICON_PATH = os.path.join(APP_DIR, 'static', 'Favicon Gabo 128x128.png')

_CACHED_DORY_B64 = None

def get_dory_icon_base64() -> str:
    """Retorna la imagen oficial del icono de Dory en base64 con caché en memoria."""
    global _CACHED_DORY_B64
    if _CACHED_DORY_B64 is not None:
        return _CACHED_DORY_B64
    if os.path.exists(DORY_ICON_PATH):
        try:
            with open(DORY_ICON_PATH, 'rb') as f:
                _CACHED_DORY_B64 = base64.b64encode(f.read()).decode('utf-8')
                return _CACHED_DORY_B64
        except Exception as e:
            logger.error(f"Error cargando icono de Dory desde {DORY_ICON_PATH}: {e}")
    return ""

# Import detection engine from app_hf
try:
    from app_hf import predict_phishing_hf
except ImportError:
    sys.path.insert(0, APP_DIR)
    from app_hf import predict_phishing_hf


# =====================================================================
# 1. Configuración del Servicio
# =====================================================================
class MailConfig:
    """Administra la configuración del buzón IMAP y servidor SMTP."""

    def __init__(self, config_dict=None):
        data = config_dict or self._load_from_disk_or_env()
        
        # IMAP Configuration
        imap = data.get('imap', {})
        self.imap_server = imap.get('server', os.environ.get('DORY_IMAP_SERVER', ''))
        self.imap_port = int(imap.get('port', os.environ.get('DORY_IMAP_PORT', 993)))
        self.imap_user = imap.get('user', os.environ.get('DORY_IMAP_USER', ''))
        self.imap_password = imap.get('password', os.environ.get('DORY_IMAP_PASSWORD', ''))
        self.imap_use_ssl = imap.get('use_ssl', True)
        self.imap_mailbox = imap.get('mailbox', 'INBOX')

        # SMTP Configuration
        smtp = data.get('smtp', {})
        self.smtp_server = smtp.get('server', os.environ.get('DORY_SMTP_SERVER', ''))
        self.smtp_port = int(smtp.get('port', os.environ.get('DORY_SMTP_PORT', 465)))
        self.smtp_user = smtp.get('user', os.environ.get('DORY_SMTP_USER', self.imap_user))
        self.smtp_password = smtp.get('password', os.environ.get('DORY_SMTP_PASSWORD', self.imap_password))
        self.smtp_use_tls = smtp.get('use_tls', False)
        self.smtp_use_ssl = smtp.get('use_ssl', True)

        # Service Options
        service = data.get('service', {})
        self.poll_interval = int(service.get('poll_interval_seconds', 15))
        self.poll_mode = service.get('poll_mode', os.environ.get('DORY_POLL_MODE', 'stateless'))
        self.mark_as_read = service.get('mark_as_read', True)
        self.move_to_folder = service.get('move_to_folder', None)
        self.allowed_domain = service.get('allowed_domain', 'quimicaboss.com.mx')
        self.sender_display_name = service.get('sender_display_name', 'Dory Ciberseguridad Química Boss')
        self.support_contact = service.get('support_contact', 'desarrollo_qb@quimicaboss.com.mx')
        self.max_workers = int(service.get('max_workers', 8))
        self.idle_timeout = int(service.get('idle_timeout_seconds', 180))
        self.additional_accounts = data.get('additional_accounts', [])


    @classmethod
    def _load_from_disk_or_env(cls):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"No se pudo leer {CONFIG_FILE}: {e}")
        return {}

    def is_configured(self) -> bool:
        """Verifica si las credenciales mínimas han sido configuradas."""
        placeholders = ['tu_contraseña', 'ingresa', 'aqui', 'aquí', 'password', 'placeholder']
        has_imap_pw = bool(self.imap_password and not any(p in self.imap_password.lower() for p in placeholders))
        has_smtp_pw = bool(self.smtp_password and not any(p in self.smtp_password.lower() for p in placeholders))
        has_imap = bool(self.imap_server and self.imap_user and has_imap_pw)
        has_smtp = bool(self.smtp_server and self.smtp_user and has_smtp_pw)
        return has_imap and has_smtp


# =====================================================================
# 2. Extractor y Analizador MIME de Correos
# =====================================================================
class EmailMIMEParser:
    """Extrae texto, remitentes, enlaces, adjuntos y contenido reenviado."""

    @staticmethod
    def decode_mime_header(header_value: str) -> str:
        """Decodifica encabezados MIME codificados en UTF-8 o ISO-8859-1."""
        if not header_value:
            return ""
        decoded_fragments = []
        try:
            for text, charset in decode_header(header_value):
                if isinstance(text, bytes):
                    encoding = charset or 'utf-8'
                    try:
                        decoded_fragments.append(text.decode(encoding, errors='replace'))
                    except Exception:
                        decoded_fragments.append(text.decode('latin-1', errors='replace'))
                else:
                    decoded_fragments.append(str(text))
            return "".join(decoded_fragments)
        except Exception:
            return str(header_value)

    @classmethod
    def parse_raw_bytes(cls, raw_bytes: bytes) -> dict:
        """Parsea un flujo de bytes RFC822 y devuelve un diccionario normalizado."""
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        return cls.parse_message_object(msg)

    @classmethod
    def parse_message_object(cls, msg) -> dict:
        """Parsea un objeto de mensaje de email con adjuntos y cabeceras de autenticación."""
        subject = cls.decode_mime_header(msg.get('Subject', ''))
        raw_from = cls.decode_mime_header(msg.get('From', ''))
        sender_name, sender_email = parseaddr(raw_from)
        
        reply_to_raw = cls.decode_mime_header(msg.get('Reply-To', ''))
        _, reply_to_email = parseaddr(reply_to_raw)
        effective_reply_to = reply_to_email or sender_email

        raw_to = cls.decode_mime_header(msg.get('To', ''))
        _, recipient_to_email = parseaddr(raw_to)
        
        message_id = msg.get('Message-ID', '')
        date_str = msg.get('Date', '')
        received_spf = cls.decode_mime_header(msg.get('Received-SPF', ''))
        auth_results = cls.decode_mime_header(msg.get('Authentication-Results', ''))
        x_loop = cls.decode_mime_header(msg.get('X-Loop', ''))
        auto_submitted = cls.decode_mime_header(msg.get('Auto-Submitted', ''))
        x_spam_status = cls.decode_mime_header(msg.get('X-Spam-Status', ''))
        x_spam_score = cls.decode_mime_header(msg.get('X-Spam-Score', ''))
        x_spam_flag = cls.decode_mime_header(msg.get('X-Spam-Flag', ''))

        body_plain = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get_content_disposition() or '').lower()
                
                # Extraer nombre del adjunto
                filename = part.get_filename()
                if filename:
                    attachments.append(cls.decode_mime_header(filename))
                elif 'attachment' in content_disposition:
                    name = part.get_param('name')
                    if name:
                        attachments.append(cls.decode_mime_header(name))

                # Ignorar adjuntos al extraer el texto principal
                if 'attachment' in content_disposition:
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or 'utf-8'
                    text = payload.decode(charset, errors='replace')
                    if content_type == 'text/plain' and not body_plain:
                        body_plain = text
                    elif content_type == 'text/html' and not body_html:
                        body_html = text
                except Exception as e:
                    logger.debug(f"Error extrayendo parte {content_type}: {e}")
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or 'utf-8'
                if payload:
                    text = payload.decode(charset, errors='replace')
                    if msg.get_content_type() == 'text/html':
                        body_html = text
                    else:
                        body_plain = text
            except Exception as e:
                logger.debug(f"Error extrayendo cuerpo plano: {e}")

        # Sintetizar texto de análisis a partir de plain o limpiando HTML
        combined_text = body_plain.strip()
        if not combined_text and body_html:
            cleaned = re.sub(r'<style.*?>.*?</style>', '', body_html, flags=re.DOTALL | re.IGNORECASE)
            cleaned = re.sub(r'<script.*?>.*?</script>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
            cleaned = re.sub(r'<[^>]+>', ' ', cleaned)
            combined_text = re.sub(r'\s+', ' ', cleaned).strip()

        # Extraer enlaces tanto de texto como de etiquetas href
        urls = set(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', combined_text))
        if body_html:
            href_urls = re.findall(r'href=["\'](https?://[^"\']+|www\.[^"\']+)["\']', body_html, flags=re.IGNORECASE)
            urls.update(href_urls)
            
        clean_urls = [u.rstrip('.,;:)!?"\'') for u in urls if u]

        # Detectar si es un correo reenviado por un usuario corporativo
        forwarded_info = cls._detect_forwarded_content(combined_text, subject)

        return {
            'subject': subject,
            'sender_name': sender_name,
            'sender_email': sender_email,
            'reply_to': effective_reply_to,
            'recipient_to': raw_to,
            'recipient_to_email': recipient_to_email,
            'message_id': message_id,
            'date': date_str,
            'body_text': combined_text,
            'body_html': body_html,
            'urls': clean_urls,
            'attachments': attachments,
            'received_spf': received_spf,
            'auth_results': auth_results,
            'x_loop': x_loop,
            'auto_submitted': auto_submitted,
            'x_spam_status': x_spam_status,
            'x_spam_score': x_spam_score,
            'x_spam_flag': x_spam_flag,
            'is_forwarded': forwarded_info['is_forwarded'],
            'forwarded_sender': forwarded_info['original_sender'],
            'forwarded_subject': forwarded_info['original_subject'],
            'analysis_text': f"{subject}\n\n{combined_text}"
        }

    @staticmethod
    def _detect_forwarded_content(text: str, subject: str) -> dict:
        """Detecta si el mensaje fue reenviado para aislar el remitente y cuerpo original."""
        is_fwd = any(subject.strip().lower().startswith(p) for p in ['fwd:', 'rv:', 'reenv:', 'forward:'])
        
        fwd_regexes = [
            r'(?:---------- Forwarded message ---------|-----Mensaje original-----)\s*De:\s*(.+?)\n.*?Asunto:\s*(.+?)(?:\n|$)',
            r'De:\s*(.+?)\r?\n(?:Enviado el|Fecha):\s*.+?\r?\n(?:Para:\s*.+?\r?\n)?Asunto:\s*(.+?)(?:\r?\n|$)',
            r'From:\s*(.+?)\r?\n(?:Sent|Date):\s*.+?\r?\n(?:To:\s*.+?\r?\n)?Subject:\s*(.+?)(?:\r?\n|$)',
            r'From:\s*(.+?)\n.*?Subject:\s*(.+?)(?:\n|$)'
        ]
        
        orig_sender = ""
        orig_subject = ""
        
        for pat in fwd_regexes:
            match = re.search(pat, text, flags=re.IGNORECASE | re.DOTALL)
            if match:
                is_fwd = True
                orig_sender = match.group(1).strip()
                orig_subject = match.group(2).strip()
                break

        return {
            'is_forwarded': is_fwd,
            'original_sender': orig_sender,
            'original_subject': orig_subject
        }


# =====================================================================
# 3. Generador de Reportes de Ciberseguridad (HTML y Texto)
# =====================================================================
def explain_threat_indicator(threat: str) -> dict:
    """
    Traduce y desglosa un indicador técnico de amenaza en una explicación
    clara para los empleados, detallando por qué detonó la alerta y su impacto.
    """
    t_lower = threat.lower()
    
    # Indicadores del Filtro Especializado L2
    if threat.startswith('[Filtro L2]'):
        content = threat.replace('[Filtro L2]', '').strip()
        if 'caracteres invisibles' in t_lower:
            return {
                'title': 'Evasión Forense: Caracteres Invisibles de Ancho Cero',
                'impact': '+25 pts (Escalado L2)',
                'reason': 'El remitente insertó caracteres no imprimibles (\\u200b, \\u200c) entre las palabras para eludir firmas de detección y ocultar términos protegidos.',
                'icon': '🔬'
            }
        elif 'homoglifo' in t_lower:
            return {
                'title': 'Evasión Forense: Sustitución de Homoglifos (Alfabetos Mixtos)',
                'impact': '+25 pts (Escalado L2)',
                'reason': 'Se combinaron caracteres cirílicos o griegos con letras latinas para engañar la lectura visual mientras se burla el filtro de texto.',
                'icon': '🔤'
            }
        elif 'redirección abierta' in t_lower or 'redireccion abierta' in t_lower:
            return {
                'title': 'Redirección Abierta (Open Redirect)',
                'impact': '+25 pts (Escalado L2)',
                'reason': 'El hipervínculo utiliza parámetros de salto (?url=...) para desviar al usuario desde un dominio en apariencia inocuo hacia un servidor atacante externo.',
                'icon': '↪️'
            }
        elif 'bec' in t_lower or 'directivo' in t_lower:
            return {
                'title': 'Suplantación Ejecutiva Crítica (Fraude del CEO / BEC)',
                'impact': '+35 pts (Escalado L2)',
                'reason': 'El mensaje aparenta provenir de la Dirección General o Finanzas de Química Boss, pero fue transmitido desde un buzón externo no corporativo o falló la verificación criptográfica SPF.',
                'icon': '👔'
            }
        elif 'discrepancia' in t_lower:
            return {
                'title': 'Discrepancia Visual de Enlace (Anchor Mismatch)',
                'impact': '+25 pts (Escalado L2)',
                'reason': 'El texto visible del enlace simula ser un dominio seguro o institucional, pero el destino real al hacer clic dirige hacia una dirección web ajena.',
                'icon': '🎭'
            }
        elif 'puerto no estándar' in t_lower or 'puerto no estandar' in t_lower:
            return {
                'title': 'Puerto Inusual / No Estándar en Enlace',
                'impact': '+25 pts (Escalado L2)',
                'reason': 'El enlace apunta a puertos no estándar (8080, 8443, etc.), comunes en servidores comprometidos o paneles de phishing temporal.',
                'icon': '🔌'
            }
        elif 'entropía' in t_lower or 'entropia' in t_lower or 'dga' in t_lower:
            return {
                'title': 'Dominio Aleatorio / Alta Entropía (DGA)',
                'impact': '+25 pts (Escalado L2)',
                'reason': 'El nombre de dominio posee una secuencia caótica generada algorítmicamente, característica de infraestructura maliciosa efímera.',
                'icon': '🎲'
            }
        elif 'recolección de credenciales' in t_lower or 'recoleccion de credenciales' in t_lower:
            return {
                'title': 'Recolección Prellenada de Credenciales',
                'impact': '+25 pts (Escalado L2)',
                'reason': 'La dirección web contiene el correo o usuario precargado en sus parámetros para inducir al robo inmediato de contraseñas.',
                'icon': '🎣'
            }
        elif 'texto invisible' in t_lower or 'oculto' in t_lower or 'html' in t_lower:
            return {
                'title': 'Ofuscación HTML / CSS Oculto',
                'impact': '+25 pts (Escalado L2)',
                'reason': 'Se detectó texto con tamaño cero o visibilidad oculta en el código HTML, técnica empleada para engañar a los motores de escaneo.',
                'icon': '👁️‍🗨️'
            }
        else:
            return {
                'title': 'Artificio Detectado por Inspección Profunda L2',
                'impact': '+25 pts',
                'reason': content,
                'icon': '🔬'
            }

    # Indicadores Heurísticos Generales
    if 'double-extension' in t_lower or 'doble extensión' in t_lower:
        return {
            'title': 'Archivo con Doble Extensión Engañosa',
            'impact': '+45 pts',
            'reason': 'El archivo oculta un ejecutable o script malicioso bajo el aspecto inocente de un documento (ej. archivo.pdf.exe).',
            'icon': '📎'
        }
    elif 'high-risk file' in t_lower or 'alto riesgo' in t_lower:
        return {
            'title': 'Archivo Adjunto Potencialmente Destructivo',
            'impact': '+45 pts',
            'reason': 'El adjunto incluye tipos de archivo de riesgo elevado (ejecutables, scripts o macros activas) capaces de alterar el equipo.',
            'icon': '⚠️'
        }
    elif 'macro' in t_lower:
        return {
            'title': 'Coerción para Habilitar Macros',
            'impact': '+15 pts',
            'reason': 'El texto incita al usuario a "habilitar macros" o "activar contenido", vía común para descargar troyanos y ransomware.',
            'icon': '⚠️'
        }
    elif 'brand impersonation' in t_lower:
        return {
            'title': 'Suplantación de Marca en Enlace (Lookalike)',
            'impact': '+35 pts',
            'reason': 'El enlace simula nombres comerciales de bancos, paqueterías o entes oficiales mediante un dominio no perteneciente a la marca.',
            'icon': '🏢'
        }
    elif 'ip address' in t_lower or 'dirección ip' in t_lower:
        return {
            'title': 'Dirección IP Numérica Directa',
            'impact': '+35 pts',
            'reason': 'El enlace apunta a una dirección IP directa en vez de un dominio registrado para burlar filtros de reputación DNS.',
            'icon': '🌐'
        }
    elif 'url fragment' in t_lower or 'fragment' in t_lower:
        return {
            'title': 'Kit de Phishing con Prellenado de Correo',
            'impact': '+40 pts',
            'reason': 'El enlace contiene tu dirección de correo incrustada para simular un portal auténtico y robar tu contraseña de acceso.',
            'icon': '🎣'
        }
    elif 'credential' in t_lower or 'credencial' in t_lower:
        return {
            'title': 'Solicitud Forzada de Credenciales / Contraseñas',
            'impact': '+30 pts',
            'reason': 'El mensaje exige validar, cambiar o ingresar credenciales de acceso a través de un sitio web no institucional.',
            'icon': '🔑'
        }
    elif 'suspicious domain extension' in t_lower or 'tld' in t_lower:
        return {
            'title': 'Extensión de Dominio de Alto Riesgo (TLD Sospechoso)',
            'impact': '+25 pts',
            'reason': 'El enlace utiliza terminaciones web (.xyz, .tk, .top, etc.) frecuentemente empleadas para campañas maliciosas efímeras.',
            'icon': '🚩'
        }
    elif 'url shortener' in t_lower or 'acortador' in t_lower:
        return {
            'title': 'Enmascaramiento mediante Acortador de URL',
            'impact': '+20 pts',
            'reason': 'Se empleó un servicio acortador (bit.ly, tinyurl, etc.) para esconder el destino real y dificultar su verificación preventiva.',
            'icon': '🔗'
        }
    elif 'urgent' in t_lower or 'urgencia' in t_lower:
        return {
            'title': 'Presión Psicológica y Coerción Temporal',
            'impact': '+20 pts',
            'reason': 'El mensaje impone plazos límite perentorios ("en 24 horas", "inmediatamente") para forzar una reacción apresurada sin consultar a TI.',
            'icon': '⏱️'
        }
    elif 'fiscal' in t_lower or 'sat' in t_lower:
        return {
            'title': 'Referencia a Notificación Fiscal o SAT Externa',
            'impact': '+15 pts',
            'reason': 'El correo incluye menciones fiscales o tributarias con enlaces a sitios no verificados.',
            'icon': '📋'
        }
    elif 'banking' in t_lower or 'banco' in t_lower or 'spei' in t_lower:
        return {
            'title': 'Alerta Financiera / Bancaria Falsa',
            'impact': '+15 pts',
            'reason': 'Avisos apócrifos de bloqueos de tarjeta, transferencias retenidas o cargos no reconocidos redirigiendo a portales no oficiales.',
            'icon': '💳'
        }
    elif 'login' in t_lower or 'action or login' in t_lower:
        return {
            'title': 'Ruta de Inicio de Sesión o Acción Sospechosa',
            'impact': '+12 pts',
            'reason': 'El enlace conduce directamente a rutas de autenticación (/login, /verificar, /auth) en servidores ajenos no autorizados.',
            'icon': '🚪'
        }
    elif 'action request' in t_lower:
        return {
            'title': 'Incitación Forzada a la Acción (Llamado a Clic)',
            'impact': '+10 pts',
            'reason': 'Instrucciones imperativas ordenando hacer clic o abrir vínculos bajo pretexto de validación obligatoria.',
            'icon': '👆'
        }
    elif 'hyphenated' in t_lower or 'guionado' in t_lower:
        return {
            'title': 'Dominio Guionado de Apariencia Falsa (Lookalike)',
            'impact': '+12 pts',
            'reason': 'Uso de guiones combinados con palabras clave ("portal-sat", "seguridad-login") para engañar a primera vista.',
            'icon': '🏷️'
        }
    elif 'generic greeting' in t_lower or 'saludo' in t_lower:
        return {
            'title': 'Saludo Despersonalizado / Genérico',
            'impact': '+8 pts',
            'reason': 'El remitente no te menciona por tu nombre o cargo ("Estimado usuario"), rasgo característico de envíos masivos de spam malicioso.',
            'icon': '👤'
        }
    elif 'composite' in t_lower:
        return {
            'title': 'Patrón Triádico Compuesto de Phishing',
            'impact': '+15 pts',
            'reason': 'Convergencia simultánea de enlaces dudosos, coerción temporal e incitación a entregar accesos.',
            'icon': '⚡'
        }
    elif 'keywords' in t_lower:
        return {
            'title': 'Vocabulario Típico de Campañas Phishing',
            'impact': '+10 pts',
            'reason': f'Presencia reiterada de términos señuelo habituales en correos fraudulentos ({threat}).',
            'icon': '📝'
        }
    else:
        return {
            'title': threat,
            'impact': '+10 pts',
            'reason': 'Indicador atípico detectado durante el análisis de ciberseguridad.',
            'icon': '⚠️'
        }


class ReportGenerator:
    """Construye correos de respuesta automáticos visualmente atractivos, claros y pedagógicos."""

    @classmethod
    def generate_report(cls, prediction_result: dict, email_info: dict, config: MailConfig) -> dict:
        """Genera el asunto, cuerpo HTML y cuerpo en texto plano para el correo de respuesta."""
        is_phishing = prediction_result.get('is_phishing', False)
        risk_score = prediction_result.get('risk_score', 0)
        confidence = int(prediction_result.get('confidence', 0.5) * 100)
        threats = prediction_result.get('threats', [])
        features = prediction_result.get('features', {})
        urls = email_info.get('urls', [])
        attachments = email_info.get('attachments', [])
        orig_subject = email_info.get('subject', 'Sin Asunto')
        report_id = f"DORY-{int(time.time())}-{risk_score}"
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        # Cargar icono oficial de Dory en base64 para vista previa HTML inmediata
        dory_b64 = get_dory_icon_base64()
        dory_icon_src = f"data:image/png;base64,{dory_b64}" if dory_b64 else ""

        # Categoría de riesgo calibrada (0-25 Seguro, 26-40 Sospechoso, >40 Phishing Confirmado)
        if risk_score > 40:
            risk_category = "PHISHING CONFIRMADO"
            accent_color = "#dc2626"
            badge_bg = "#fef2f2"
            badge_border = "#f87171"
            status_title = "🚨 ALERTA: PHISHING CONFIRMADO (ALTO RIESGO)"
            subject_prefix = "[DORY ALERTA - PHISHING]"
        elif risk_score >= 26:
            risk_category = "SOSPECHOSO / ADVERTENCIA"
            accent_color = "#ea580c"
            badge_bg = "#fff7ed"
            badge_border = "#fb923c"
            status_title = "⚠️ ADVERTENCIA: CORREO SOSPECHOSO (ELEMENTOS INUSUALES)"
            subject_prefix = "[DORY ADVERTENCIA - SOSPECHOSO]"
        else:
            risk_category = "SEGURO / CONFIABLE"
            accent_color = "#16a34a"
            badge_bg = "#f0fdf4"
            badge_border = "#86efac"
            status_title = "✅ REPORTE: CORREO SEGURO / CONFIABLE"
            subject_prefix = "[DORY REPORTE - SEGURO]"

        reply_subject = f"{subject_prefix} Re: {orig_subject}"

        # Desglose Explicativo de Puntos que Activaron la Alerta (Solo para correos Sospechosos o Phishing con riesgo > 25)
        threats_html = ""
        threats_plain_list = []
        if risk_score > 25 and threats:
            items_html = []
            seen_titles = set()
            selected_threats = []
            for t in threats:
                info = explain_threat_indicator(t)
                title = info['title']
                if title not in seen_titles:
                    seen_titles.add(title)
                    selected_threats.append(info)
                if len(selected_threats) >= 3:
                    break

            for info in selected_threats:
                threats_plain_list.append(f"  * {info['icon']} {info['title']}: {info['reason']}")
                items_html.append(f'''
                <li style="margin-bottom: 8px; line-height: 1.5;">
                    <strong style="color: #0f172a;">{info['icon']} {info['title']}:</strong> <span style="color: #475569;">{info['reason']}</span>
                </li>
                ''')

            threats_html = f'''
            <div style="margin-bottom: 22px;">
                <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; color: #64748b; margin-bottom: 8px;">
                    Puntos Específicos que Activaron la Alerta ({len(selected_threats)} factores clave):
                </div>
                <ul style="margin: 0; padding-left: 20px; font-size: 13px;">
                    {"".join(items_html)}
                </ul>
            </div>
            '''
        else:
            threats_html = ""

        # Adjuntos de Riesgo (Compacto)
        att_html = ""
        suspicious_atts = features.get('suspicious_attachments', [])
        if suspicious_atts:
            att_html = f'''
            <div style="margin-bottom: 18px; padding: 10px 14px; background: #fff1f2; border: 1px solid #fecaca; border-radius: 6px; font-size: 12px; color: #991b1b;">
                📎 <strong>Adjunto de riesgo detectado:</strong> {", ".join(suspicious_atts)} (evita abrirlo).
            </div>
            '''

        # Acción Inmediata (Clara y sin redundancia)
        if risk_score > 40:
            action_html = f'''
            <div style="margin-bottom: 20px; padding: 14px 16px; background: #fef2f2; border-left: 4px solid #dc2626; border-radius: 6px;">
                <strong style="color: #991b1b; font-size: 13px; display: block; margin-bottom: 3px;">Acción requerida:</strong>
                <span style="font-size: 13px; color: #7f1d1d; line-height: 1.5;">
                    <strong>NO abras enlaces ni descargues archivos</strong> de este mensaje. Elimínalo o repórtalo en tu buzón. Si ingresaste alguna contraseña, avisa a TI (<a href="mailto:{config.support_contact}" style="color: #991b1b; text-decoration: underline;">{config.support_contact}</a>) de inmediato.
                </span>
            </div>
            '''
            action_plain = "- NO abras enlaces ni descargues archivos adjuntos.\n- Elimina el correo o repórtalo en tu buzón.\n- Si ingresaste contraseñas, notifica a TI de inmediato."
        elif risk_score >= 26:
            action_html = f'''
            <div style="margin-bottom: 20px; padding: 14px 16px; background: #fff7ed; border-left: 4px solid #ea580c; border-radius: 6px;">
                <strong style="color: #9a3412; font-size: 13px; display: block; margin-bottom: 3px;">Precaución recomendada:</strong>
                <span style="font-size: 13px; color: #7c2d12; line-height: 1.5;">
                    El correo contiene elementos inusuales. Verifica con el remitente por Teams o llamada antes de interactuar.
                </span>
            </div>
            '''
            action_plain = "- Verifica con el remitente por Teams o llamada antes de interactuar.\n- No actives macros ni ejecutes adjuntos no solicitados."
        else:
            action_html = '''
            <div style="margin-bottom: 20px; padding: 14px 16px; background: #f0fdf4; border-left: 4px solid #16a34a; border-radius: 6px;">
                <strong style="color: #166534; font-size: 13px; display: block; margin-bottom: 3px;">Correo Seguro:</strong>
                <span style="font-size: 13px; color: #14532d; line-height: 1.5;">
                    Puedes interactuar con este correo normalmente manteniendo la precaución habitual.
                </span>
            </div>
            '''
            action_plain = "- El correo es seguro y confiable.\n- Procede normalmente."

        # Datos del correo y aislamiento de remitente original si fue reenviado
        is_fwd = email_info.get('is_forwarded', False)
        fwd_sender = email_info.get('forwarded_sender', '').strip()
        fwd_subject = email_info.get('forwarded_subject', '').strip()
        sender_email = email_info.get('sender_email', 'Desconocido')
        display_subject = fwd_subject if (is_fwd and fwd_subject) else orig_subject

        if is_fwd and fwd_sender:
            sender_line = f'<strong style="color: #334155;">Remitente Sospechoso:</strong> <span style="color: #0f172a;">{fwd_sender}</span> <span style="font-size: 11px; color: #64748b;">(Reenviado por {sender_email})</span>'
            sender_plain = f"Remitente Sospechoso: {fwd_sender} (Reenviado por {sender_email})"
        else:
            sender_line = f'<strong style="color: #334155;">Remitente:</strong> <span style="color: #0f172a;">{sender_email}</span>'
            sender_plain = f"Remitente: {sender_email}"

        html_body = f'''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; color: #1e293b;">
    <div style="max-width: 560px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.06); border: 1px solid #cbd5e1;">
        
        <!-- Header Banner -->
        <div style="background: {accent_color}; padding: 18px 24px; color: #ffffff;">
            <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.95; margin-bottom: 5px;">
                <img src="{dory_icon_src}" alt="Dory" width="14" height="14" style="width: 14px; height: 14px; border-radius: 50%; vertical-align: -2px; display: inline-block; margin-right: 5px;">Dory Defense Bot • Análisis de Seguridad
            </div>
            <h2 style="margin: 0; font-size: 18px; font-weight: 700; line-height: 1.3;">{status_title}</h2>
        </div>

        <!-- Body Container -->
        <div style="padding: 22px 24px;">
            
            <!-- Datos del Correo Analizado -->
            <div style="padding: 12px 16px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 18px; font-size: 13px; line-height: 1.5;">
                <div style="margin-bottom: 4px; color: #64748b;">
                    <strong style="color: #334155;">Asunto:</strong> <span style="color: #0f172a;">{display_subject}</span>
                </div>
                <div style="color: #64748b;">
                    {sender_line}
                </div>
            </div>

            <!-- Acción Inmediata -->
            {action_html}

            <!-- Adjuntos de Riesgo si existen -->
            {att_html}

            <!-- Motivos Clave si aplica -->
            {threats_html}

            <!-- FIRMA OFICIAL DORY (Limpia y Ejecutiva) -->
            <div style="margin-top: 24px; padding: 18px 20px; background: #0f172a; border-radius: 10px; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; box-shadow: 0 4px 14px rgba(15, 23, 42, 0.15);">
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="width: 106px; vertical-align: middle; padding-right: 18px;">
                            <table cellpadding="0" cellspacing="0" border="0" style="width: 88px; height: 88px; border-radius: 20px; background: linear-gradient(135deg, #0284c7 0%, #2563eb 50%, #4f46e5 100%); box-shadow: 0 4px 16px rgba(37, 99, 235, 0.45); border-collapse: separate;">
                                <tr>
                                    <td align="center" valign="middle" style="width: 88px; height: 88px; text-align: center; vertical-align: middle; padding: 0;">
                                        <img src="{dory_icon_src}" alt="Dory AI" width="76" height="76" style="width: 76px; height: 76px; border-radius: 50%; display: block; margin: 0 auto; border: 0;">
                                    </td>
                                </tr>
                            </table>
                        </td>
                        <td style="vertical-align: middle;">
                            <div style="font-size: 16px; font-weight: 800; letter-spacing: 0.5px; color: #38bdf8; line-height: 1.3;">
                                DORY CYBERDEFENSE AI ENGINE
                            </div>
                            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.8px; margin-top: 4px; line-height: 1.4;">
                                Motor Autónomo de Detección de Phishing • Química Boss
                            </div>
                            <div style="font-size: 11px; color: #cbd5e1; margin-top: 8px; line-height: 1.4;">
                                Soporte TI: <a href="mailto:{config.support_contact}" style="color: #38bdf8; text-decoration: none; font-weight: bold;">{config.support_contact}</a>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>

        </div>
    </div>
</body>
</html>
'''

        # Plain-Text Generation (Menos es Más)
        if risk_score > 25 and threats_plain_list:
            threats_txt = "\n".join(threats_plain_list)
            threats_section = f"""PUNTOS ESPECÍFICOS QUE ACTIVARON LA ALERTA:
{threats_txt}

"""
        else:
            threats_section = ""

        plain_body = f"""====================================================================
{status_title}
Dory Defense Bot - Análisis de Seguridad
====================================================================

Asunto: {display_subject}
{sender_plain}
Diagnóstico: {risk_category}

ACCIÓN REQUERIDA:
{action_plain}

{threats_section}====================================================================
🐟 DORY CYBERDEFENSE AI ENGINE
Motor Autónomo de Detección de Phishing • Química Boss
Soporte TI: {config.support_contact}
====================================================================
"""

        return {
            'subject': reply_subject,
            'html': html_body,
            'plain': plain_body,
            'report_id': report_id
        }


# =====================================================================
# 4. Almacenamiento en Base de Datos Local (feedback.db)
# =====================================================================
def save_incoming_report(report_data: dict) -> int:
    """Guarda el correo analizado en la tabla incoming_phishing_reports."""
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute('PRAGMA journal_mode=WAL;')
        cursor.execute('PRAGMA synchronous=NORMAL;')
        
        cursor.execute('''
            INSERT INTO incoming_phishing_reports (
                sender_email, recipient_email, subject, email_body,
                prediction, risk_score, confidence, threats_detected,
                urls_found, reply_sent, processing_time_ms, raw_headers
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report_data.get('sender_email', ''),
            report_data.get('recipient_email', ''),
            report_data.get('subject', ''),
            report_data.get('email_body', ''),
            report_data.get('prediction', ''),
            report_data.get('risk_score', 0),
            report_data.get('confidence', 0.0),
            json.dumps(report_data.get('threats_detected', [])),
            json.dumps(report_data.get('urls_found', [])),
            report_data.get('reply_sent', False),
            report_data.get('processing_time_ms', 0.0),
            report_data.get('raw_headers', '')
        ))
        
        conn.commit()
        record_id = cursor.lastrowid
        conn.close()
        logger.info(f"Registro de reporte entrante #{record_id} guardado exitosamente en feedback.db")
        return record_id
    except Exception as e:
        logger.error(f"Error guardando reporte entrante en SQLite: {e}", exc_info=True)
        return -1


class ThreadLocalSMTPClient:
    """Administra conexiones SMTP persistentes y reutilizables por cada hilo de trabajo con auto-reconexión."""
    def __init__(self, config: MailConfig):
        self.config = config
        self._local = threading.local()

    def get_connection(self):
        client = getattr(self._local, 'client', None)
        if client is not None:
            try:
                # Probar si el socket sigue activo con comando NOOP
                status, _ = client.noop()
                if status == 250:
                    return client
            except Exception:
                try:
                    client.quit()
                except Exception:
                    pass
                self._local.client = None

        # Establecer y autenticar nueva sesión SMTP
        if self.config.smtp_use_ssl:
            client = smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port, timeout=15)
        else:
            client = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port, timeout=15)
            client.ehlo()
            if self.config.smtp_use_tls:
                client.starttls(context=ssl.create_default_context())
                client.ehlo()

        client.login(self.config.smtp_user, self.config.smtp_password)
        self._local.client = client
        return client

    def close(self):
        client = getattr(self._local, 'client', None)
        if client:
            try:
                client.quit()
            except Exception:
                pass
            self._local.client = None


# =====================================================================
# 5. Monitor de Buzón y Despachador SMTP Concurrente
# =====================================================================
class MailMonitorWorker:
    """Gestiona la conexión IMAP en tiempo real (IDLE) y el envío concurrente vía SMTP."""

    def __init__(self, config: MailConfig = None):
        self.config = config or MailConfig()
        self.executor = ThreadPoolExecutor(max_workers=min(self.config.max_workers, 2), thread_name_prefix="DoryWorker")
        self.idle_timeout = self.config.idle_timeout
        self._smtp_lock = threading.Lock()
        self._last_smtp_send = 0.0

    def process_single_message(self, raw_bytes: bytes) -> dict:
        """Parsea, analiza y genera respuesta para un correo en bruto con soporte de adjuntos."""
        start_time = time.time()
        
        # 1. Parsear correo y adjuntos
        email_info = EmailMIMEParser.parse_raw_bytes(raw_bytes)
        
        # 2. Predecir con el motor heurístico calibrado v3.5 + Filtro L2 Automatizado
        prediction = predict_phishing_hf(
            email_info['analysis_text'],
            attachments=email_info.get('attachments', []),
            raw_html=email_info.get('body_html', ''),
            email_info=email_info
        )

        # 3. Verificar inconsistencia de autenticación SPF/DKIM
        spf = email_info.get('received_spf', '').lower()
        auth = email_info.get('auth_results', '').lower()
        if ('fail' in spf or 'softfail' in spf or 'spf=fail' in auth):
            if prediction['features'].get('has_brand_impersonation') or prediction['risk_score'] >= 30:
                prediction['risk_score'] = min(prediction['risk_score'] + 20, 100)
                if 'Failed SPF/DKIM origin authentication (Possible sender spoofing)' not in prediction['threats']:
                    prediction['threats'].append('Failed SPF/DKIM origin authentication (Possible sender spoofing)')
                prediction['is_phishing'] = (prediction['risk_score'] > 40)

        # 3b. Correlación con filtros de DirectAdmin / SpamAssassin
        spam_status = email_info.get('x_spam_status', '').lower()
        spam_flag = email_info.get('x_spam_flag', '').lower()
        if 'yes' in spam_flag or spam_status.startswith('yes'):
            if prediction['risk_score'] < 50:
                prediction['risk_score'] = min(prediction['risk_score'] + 25, 100)
            if 'DirectAdmin / SpamAssassin Flagged as SPAM' not in prediction['threats']:
                prediction['threats'].append('DirectAdmin / SpamAssassin Flagged as SPAM')
            prediction['is_phishing'] = (prediction['risk_score'] > 40)

        # 4. Generar reporte visual
        report = ReportGenerator.generate_report(prediction, email_info, self.config)
        
        processing_time = round((time.time() - start_time) * 1000, 2)

        # Determine 3-tier prediction category for DB
        pred_category = 'PHISHING' if prediction['risk_score'] > 40 else ('SUSPICIOUS' if prediction['risk_score'] >= 26 else 'LEGITIMATE')

        # 5. Preparar datos para base de datos
        db_payload = {
            'sender_email': email_info['sender_email'],
            'recipient_email': self.config.imap_user,
            'subject': email_info['subject'],
            'email_body': email_info['body_text'],
            'prediction': pred_category,
            'risk_score': prediction['risk_score'],
            'confidence': prediction['confidence'],
            'threats_detected': prediction['threats'],
            'urls_found': email_info['urls'],
            'reply_sent': False,
            'processing_time_ms': processing_time,
            'raw_headers': f"SPF: {email_info.get('received_spf', '')} | AUTH: {email_info.get('auth_results', '')}"
        }

        return {
            'email_info': email_info,
            'prediction': prediction,
            'report': report,
            'db_payload': db_payload,
            'processing_time_ms': processing_time
        }

    def send_smtp_reply(self, email_info: dict, report: dict) -> bool:
        """Envía el correo de respuesta de forma inmediata reutilizando conexión SMTP autenticada."""
        sender_email = email_info.get('sender_email', '').strip()
        recipient = email_info.get('reply_to', sender_email).strip()

        # Salvaguarda 1: No responder a remitentes vacíos
        if not recipient:
            logger.info("Omitiendo respuesta automática: remitente no válido o vacío")
            return False

        # Salvaguarda 1b: Prevenir bucles infinitos con encabezados de bot y marcas de Dory
        x_loop = email_info.get('x_loop', '').lower()
        auto_submitted = email_info.get('auto_submitted', '').lower()
        subject_lower = email_info.get('subject', '').lower()
        if 'doryphishingbot' in x_loop or 'auto-replied' in auto_submitted or '[dory' in subject_lower:
            logger.info(f"Omitiendo respuesta automática: correo generado por bot o reporte previo ({recipient})")
            return False

        # Salvaguarda 2: No responder a remitentes automatizados / bots conocidos
        recipient_lower = recipient.lower()
        bot_indicators = [
            'noreply', 'no-reply', 'mailer-daemon', 'postmaster', 'notifications@github.com',
            'alert', 'automated', 'donotreply', 'newsletters', 'bounce'
        ]
        if any(bot in recipient_lower for bot in bot_indicators):
            logger.info(f"Omitiendo respuesta automática a remitente automatizado/bot: {recipient}")
            return False

        # Salvaguarda 3: Exclusividad corporativa
        if self.config.allowed_domain:
            allowed = self.config.allowed_domain.lower()
            if not recipient_lower.endswith(f"@{allowed}"):
                logger.warning(
                    f"Omitiendo respuesta automática a remitente fuera del dominio corporativo permitido (@{allowed}): {recipient}"
                )
                return False

        # Salvaguarda 4: Confirmar intención de análisis explícita
        # Si el correo llega a una cuenta dedicada de ciberseguridad (spam@ o dory@) o el buzón monitoreado
        # es una de estas cuentas, cualquier correo de un empleado corporativo tiene intención implícita de análisis.
        to_email = email_info.get('recipient_to_email', '').lower()
        dedicated_inboxes = ['spam@', 'dory@', 'seguridad@', 'phishing@', 'abuse@']
        is_dedicated_inbox = any(d in to_email for d in dedicated_inboxes) or \
                             any(d in self.config.imap_user.lower() for d in dedicated_inboxes)

        is_forwarded = email_info.get('is_forwarded', False)
        intent_keywords = [
            'revisar', 'phishing', 'seguridad', 'analizar', 'dory',
            'fwd:', 'rv:', 'reenv:', 'forward:', 'spam', 'sospechoso', 'malicioso',
            'prueba', 'test', 'alerta', 'factura', 'banco'
        ]
        has_intent = (
            is_dedicated_inbox or
            is_forwarded or
            any(kw in subject_lower for kw in intent_keywords)
        )
        if not has_intent:
            logger.warning(
                f"Omitiendo respuesta automática a {recipient}: no se detectó intención explícita de análisis (asunto sin etiquetas de revisión ni reenvío)"
            )
            return False

        # Salvaguarda 5: No enviar respuesta a correos con más de 48 horas de antigüedad
        date_str = email_info.get('date', '')
        if date_str:
            try:
                msg_dt = parsedate_to_datetime(date_str)
                now = datetime.now(msg_dt.tzinfo) if msg_dt.tzinfo else datetime.now()
                if (now - msg_dt).total_seconds() > 172800:
                    logger.info(f"Omitiendo respuesta automática a {recipient}: correo con fecha anterior a 48h ({date_str})")
                    return False
            except Exception as e:
                logger.warning(f"Error analizando fecha '{date_str}': {e}")

        # Construcción del mensaje MIME (multipart/related con alternativa + CID inline)
        msg = MIMEMultipart('related')
        msg['Subject'] = report['subject']
        msg['From'] = f"{self.config.sender_display_name} <{self.config.smtp_user}>"
        msg['To'] = recipient
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = make_msgid(domain='dory.local')
        msg['X-Loop'] = 'DoryPhishingBot'
        msg['Auto-Submitted'] = 'auto-replied'

        # Enlazar en el mismo hilo de conversación si existe Message-ID original
        if email_info.get('message_id'):
            orig_id = email_info['message_id']
            msg['In-Reply-To'] = orig_id
            msg['References'] = orig_id

        msg_alt = MIMEMultipart('alternative')
        msg.attach(msg_alt)

        part_plain = MIMEText(report['plain'], 'plain', 'utf-8')
        msg_alt.attach(part_plain)

        # Para compatibilidad universal (evitando bloqueos de data URI en clientes estrictos como Outlook),
        # convertimos las URLs de datos en referencias cid:dory_logo y adjuntamos la imagen inline
        dory_b64 = get_dory_icon_base64()
        dory_data_uri = f"data:image/png;base64,{dory_b64}"
        html_for_smtp = report['html']
        if dory_data_uri and dory_data_uri in html_for_smtp:
            html_for_smtp = html_for_smtp.replace(dory_data_uri, "cid:dory_logo")

        part_html = MIMEText(html_for_smtp, 'html', 'utf-8')
        msg_alt.attach(part_html)

        if os.path.exists(DORY_ICON_PATH):
            try:
                with open(DORY_ICON_PATH, 'rb') as f_img:
                    img_part = MIMEImage(f_img.read(), _subtype="png")
                    img_part.add_header('Content-ID', '<dory_logo>')
                    img_part.add_header('Content-Disposition', 'inline', filename='dory_logo.png')
                    msg.attach(img_part)
            except Exception as e:
                logger.error(f"Error adjuntando icono inline dory_logo: {e}")

        server = None
        with self._smtp_lock:
            # Cadencia de seguridad para evitar PORTFLOOD en firewall (mínimo 1.5s entre conexiones SMTP)
            elapsed = time.time() - self._last_smtp_send
            if elapsed < 1.5:
                time.sleep(1.5 - elapsed)

            try:
                if self.config.smtp_use_ssl:
                    server = smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port, timeout=10)
                else:
                    server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port, timeout=10)
                    server.ehlo()
                    if self.config.smtp_use_tls:
                        server.starttls(context=ssl.create_default_context())
                        server.ehlo()

                server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(self.config.smtp_user, [recipient], msg.as_string())
                logger.info(f"✅ Respuesta automática enviada exitosamente a: {recipient}")
                return True
            except Exception as e:
                logger.error(f"❌ Error al enviar correo de respuesta SMTP: {e}", exc_info=True)
                return False
            finally:
                self._last_smtp_send = time.time()
                if server:
                    try:
                        server.quit()
                    except Exception:
                        try:
                            server.close()
                        except Exception:
                            pass

    def _concurrent_task(self, raw_email: bytes, mail_id: str):
        """Tarea ejecutada de forma concurrente en el pool de hilos para cada correo entrante."""
        try:
            result = self.process_single_message(raw_email)
            reply_ok = self.send_smtp_reply(result['email_info'], result['report'])
            result['db_payload']['reply_sent'] = reply_ok
            save_incoming_report(result['db_payload'])
        except Exception as e:
            logger.error(f"Error procesando correo #{mail_id} en hilo concurrente: {e}", exc_info=True)

    def _check_and_dispatch(self, imap_client) -> int:
        """Busca correos no leídos y los despacha al pool concurrente de hilos de forma no bloqueante."""
        status, data = imap_client.search(None, 'UNSEEN')
        if status != 'OK' or not data or not data[0]:
            return 0

        mail_ids = data[0].split()
        if not mail_ids:
            return 0

        # Priorizar siempre los correos más recientes primero (orden LIFO / nuevo a viejo)
        # para que correos nuevos entrantes se procesen inmediatamente sin esperar colas históricas.
        reversed_ids = list(reversed(mail_ids))
        batch_ids = reversed_ids[:25]
        if len(mail_ids) > 25:
            logger.info(f"Procesando lote prioritario de {len(batch_ids)} correos recientes de {len(mail_ids)} pendientes...")

        for m_id in batch_ids:
            status, msg_data = imap_client.fetch(m_id, '(RFC822)')
            if status != 'OK':
                continue

            raw_email = msg_data[0][1]

            # Marcar de inmediato como leído en el servidor
            if self.config.mark_as_read:
                imap_client.store(m_id, '+FLAGS', '\\Seen')

            # Despacho concurrente inmediato (asíncrono, no bloquea el canal IMAP)
            self.executor.submit(self._concurrent_task, raw_email, m_id.decode())

        return len(mail_ids)

    def check_and_process_inbox(self) -> int:
        """Realiza una consulta puntual a la bandeja IMAP (para modo --run o pruebas)."""
        if not self.config.is_configured():
            logger.warning("Servicio IMAP/SMTP no configurado o contraseña pendiente. Revisa mail_config.json")
            return 0

        imap_client = None
        try:
            if self.config.imap_use_ssl:
                imap_client = imaplib.IMAP4_SSL(self.config.imap_server, self.config.imap_port)
            else:
                imap_client = imaplib.IMAP4(self.config.imap_server, self.config.imap_port)

            imap_client.login(self.config.imap_user, self.config.imap_password)
            imap_client.select(self.config.imap_mailbox)
            count = self._check_and_dispatch(imap_client)
            imap_client.close()
            imap_client.logout()
            return count
        except Exception as e:
            logger.error(f"Error consultando buzón IMAP: {e}", exc_info=True)
            return 0

    def _listen_mailbox(self, server: str, port: int, user: str, password: str, use_ssl: bool, mailbox: str):
        """Mantiene una conexión persistente IMAP IDLE para un buzón específico."""
        logger.info(f"Conectando a IMAP {user} ({server}:{port})...")
        backoff = 5
        while True:
            imap_client = None
            try:
                if use_ssl:
                    imap_client = imaplib.IMAP4_SSL(server, port)
                else:
                    imap_client = imaplib.IMAP4(server, port)

                imap_client.login(user, password)
                imap_client.select(mailbox)

                # Procesar mensajes pendientes al conectar
                self._check_and_dispatch(imap_client)

                supports_idle = 'IDLE' in imap_client.capabilities
                backoff = 5  # Reset backoff tras conexión exitosa

                if supports_idle:
                    logger.info(f"⚡ [{user}] Protocolo IMAP IDLE soportado. Activando modo Push en Tiempo Real (< 2s)...")
                    while True:
                        tag = imap_client._new_tag()
                        imap_client.send(tag + b' IDLE\r\n')
                        resp = imap_client.readline()
                        if not resp.startswith(b'+'):
                            logger.warning(f"[{user}] Respuesta inesperada de IDLE: {resp}. Cambiando a sondeo.")
                            break

                        # Esperar notificaciones push en el socket sin consumir CPU
                        sock = imap_client.sock
                        if sock:
                            select.select([sock], [], [], self.idle_timeout)

                        # Salir de modo IDLE con DONE para consultar el estado
                        imap_client.send(b'DONE\r\n')
                        imap_client.readline()

                        # Despachar correos recién llegados
                        self._check_and_dispatch(imap_client)
                else:
                    logger.info(f"[{user}] Servidor sin IDLE. Modo sondeo activo cada {self.config.poll_interval}s...")
                    while True:
                        time.sleep(self.config.poll_interval)
                        self._check_and_dispatch(imap_client)

            except Exception as e:
                logger.error(f"[{user}] Conexión IMAP reiniciándose tras evento de red ({e}). Reintento en {backoff}s...")
                if imap_client:
                    try:
                        imap_client.logout()
                    except Exception:
                        pass
                    try:
                        if hasattr(imap_client, 'sock') and imap_client.sock:
                            imap_client.sock.close()
                    except Exception:
                        pass
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)


    def _poll_mailbox_stateless(self, server: str, port: int, user: str, password: str, use_ssl: bool, mailbox: str, interval: int = 30):
        """Consulta periódica sin estado: conecta, revisa INBOX e INBOX.spam, procesa, cierra conexión y duerme. CERO procesos persistentes en el servidor."""
        logger.info(f"⚡ [Modo Sin Estado] Iniciando sondeo ultra-seguro para {user} cada {interval}s (Cero impacto en servidor)...")
        consecutive_errors = 0
        while True:
            imap_client = None
            sleep_time = interval
            try:
                if use_ssl:
                    imap_client = imaplib.IMAP4_SSL(server, port, timeout=10)
                else:
                    imap_client = imaplib.IMAP4(server, port, timeout=10)

                imap_client.login(user, password)
                
                # 1. Revisar buzón principal (INBOX)
                imap_client.select(mailbox)
                self._check_and_dispatch(imap_client)

                # 2. Revisar carpeta de Spam de DirectAdmin (INBOX.spam) en la misma conexión
                try:
                    typ, _ = imap_client.select("INBOX.spam")
                    if typ == 'OK':
                        self._check_and_dispatch(imap_client)
                except Exception:
                    pass

                # 3. Desconexión limpia inmediata
                try:
                    imap_client.close()
                except Exception:
                    pass
                try:
                    imap_client.logout()
                except Exception:
                    pass
                consecutive_errors = 0
                sleep_time = interval
            except Exception as e:
                consecutive_errors += 1
                if consecutive_errors == 1:
                    sleep_time = 45
                elif consecutive_errors == 2:
                    sleep_time = 90
                elif consecutive_errors == 3:
                    sleep_time = 180
                elif consecutive_errors <= 5:
                    sleep_time = 300
                else:
                    sleep_time = 600
                    logger.critical(
                        f"🛡️ [Circuit Breaker] Fallos de conexión recurrentes ({consecutive_errors} consecutivos). "
                        f"Pausando {sleep_time}s para permitir enfriamiento total del firewall CSF."
                    )
                logger.warning(f"[{user}] Aviso en sondeo sin estado ({e}). Pausa de seguridad: {sleep_time}s (fallo #{consecutive_errors})")
            finally:
                if imap_client:
                    try:
                        if hasattr(imap_client, 'sock') and imap_client.sock:
                            imap_client.sock.close()
                    except Exception:
                        pass
                    imap_client = None

            time.sleep(sleep_time)


    def run_daemon(self):
        """
        Ejecuta el ciclo continuo de alta disponibilidad multi-buzón:
        - Modo 'stateless': Sondeo ligero sin sockets persistentes, garantizando 0 carga en el servidor/cPanel.
        - Modo 'idle': Push persistente en tiempo real.
        """
        if not self.config.is_configured():
            logger.warning("Configuración principal incompleta. Revisa mail_config.json")
            return

        logger.info(f"Iniciando demonio Dory (Pool de {self.config.max_workers} hilos, Modo: {self.config.poll_mode})...")
        threads = []

        if getattr(self.config, 'poll_mode', 'stateless') == 'stateless':
            # Modo Ultra-Seguro Sin Estado: Conexión puntual de 0.2s cada intervalo. Nunca satura Dovecot.
            t_main = threading.Thread(
                target=self._poll_mailbox_stateless,
                args=(
                    self.config.imap_server,
                    self.config.imap_port,
                    self.config.imap_user,
                    self.config.imap_password,
                    self.config.imap_use_ssl,
                    self.config.imap_mailbox,
                    self.config.poll_interval
                ),
                daemon=True,
                name=f"STAT_IMAP-{self.config.imap_user}"
            )
            threads.append(t_main)
            t_main.start()
        else:
            # Buzón principal (oficial: spam@quimicaboss.com.mx) - INBOX
            t_main = threading.Thread(
                target=self._listen_mailbox,
                args=(
                    self.config.imap_server,
                    self.config.imap_port,
                    self.config.imap_user,
                    self.config.imap_password,
                    self.config.imap_use_ssl,
                    self.config.imap_mailbox
                ),
                daemon=True,
                name=f"IMAP-{self.config.imap_user}"
            )
            threads.append(t_main)
            t_main.start()

            # Carpeta de Spam DirectAdmin (INBOX.spam) para correos desviados por SpamAssassin
            t_spam_folder = threading.Thread(
                target=self._listen_mailbox,
                args=(
                    self.config.imap_server,
                    self.config.imap_port,
                    self.config.imap_user,
                    self.config.imap_password,
                    self.config.imap_use_ssl,
                    "INBOX.spam"
                ),
                daemon=True,
                name=f"IMAP-{self.config.imap_user}-SpamFolder"
            )
            threads.append(t_spam_folder)
            t_spam_folder.start()



        # Buzones adicionales (ej. dory@quimicaboss.com.mx)
        for acc in getattr(self.config, 'additional_accounts', []):
            u = acc.get('user')
            p = acc.get('password')
            s = acc.get('server', self.config.imap_server)
            port = int(acc.get('port', self.config.imap_port))
            ssl_flag = acc.get('use_ssl', True)
            box = acc.get('mailbox', 'INBOX')
            if u and p:
                t_acc = threading.Thread(
                    target=self._listen_mailbox,
                    args=(s, port, u, p, ssl_flag, box),
                    daemon=True,
                    name=f"IMAP-{u}"
                )
                threads.append(t_acc)
                t_acc.start()

        for t in threads:
            t.join()


# =====================================================================
# 6. Muestras para Simulación y Pruebas Locales
# =====================================================================
SIMULATED_SAMPLES = {
    'sat': {
        'from': 'Notificaciones SAT <notificaciones@sat-buzon.online>',
        'subject': 'URGENTE: Notificación de Inconsistencias en Buzón Tributario',
        'attachments': ['Requerimiento_Fiscal.pdf'],
        'body': '''Estimado Contribuyente:

El Servicio de Administración Tributaria (SAT) ha detectado inconsistencias graves en sus declaraciones fiscales recientes.
Cuenta con 24 horas para ingresar a su buzón tributario y solventar el requerimiento para evitar el bloqueo inmediato de sus Sellos Digitales y multas acumulativas.

Ingrese aquí para revisar el requerimiento:
https://sat-consultas.online/buzon-tributario/login

Atentamente,
Servicio de Administración Tributaria'''
    },
    'malware_attach': {
        'from': 'Facturación Proveedor <cobranza@proveedor-servicios.net>',
        'subject': '[REVISAR] Fwd: Comprobante de transferencia SPEI urgente',
        'attachments': ['Factura_Cancelacion_2026.pdf.exe'],
        'body': '''Hola equipo de compras,

Les adjuntamos el comprobante fiscal y la factura correspondiente para su validación urgente.
Favor de ejecutar el comprobante adjunto para liberar el saldo.

Saludos cordiales.'''
    },
    'banco': {
        'from': 'Seguridad Santander <alertas@santander-seguridad.net>',
        'subject': 'ALERTA: Su cuenta ha sido bloqueada preventivamente',
        'attachments': [],
        'body': '''Estimado cliente Santander:

Hemos detectado un intento de cargo no reconocido por $8,450.00 MXN en su tarjeta de débito.
Por su seguridad, sus accesos han sido suspendidos temporalmente.

Para desbloquear sus fondos y cancelar la transacción, ingrese de inmediato a:
https://santander-seguridad.net/desbloqueo?token=928371

Evite multas y cargos adicionales completando la validación en menos de 2 horas.'''
    },
    'legitimo': {
        'from': 'Ing. Carlos Aceves <carlos.aceves@quimicaboss.com.mx>',
        'subject': 'Minuta y acuerdos de la junta de ciberseguridad',
        'attachments': ['Minuta_Seguridad_Septiembre.pdf'],
        'body': '''Hola equipo,

Les comparto los puntos clave revisados en la sesión de hoy:
1. Pruebas de detección de phishing en español completadas con éxito.
2. Planeación del buzón de correo automático para recepción de muestras.
3. Próxima revisión programada para el viernes.

Cualquier comentario adicional, favor de responder a este mismo hilo.

Saludos cordiales,
Carlos Aceves'''
    }
}


def run_simulation(sample_key='sat', save_html_preview=True, custom_text=None, custom_sender=None, custom_attachments=None):
    """Ejecuta una simulación completa sin requerir conexión a servidor de correo."""
    logger.info(f"--- Iniciando Simulación de Correo ('{sample_key}') ---")
    
    sample = SIMULATED_SAMPLES.get(sample_key, SIMULATED_SAMPLES['sat'])
    sender = custom_sender or sample['from']
    subject = sample['subject']
    body = custom_text or sample['body']
    attachments = custom_attachments or sample.get('attachments', [])

    # Construir correo simulado con adjuntos si aplica
    if attachments:
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = 'desarrollo_qb@quimicaboss.com.mx'
        msg['Subject'] = subject
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = f"<simulated-{int(time.time())}@quimicaboss.com.mx>"
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        for att in attachments:
            part = MIMEText("Contenido de prueba simulado", 'plain', 'utf-8')
            part.add_header('Content-Disposition', 'attachment', filename=att)
            msg.attach(part)
        raw_rfc822 = msg.as_bytes()
    else:
        raw_rfc822 = f"""From: {sender}
To: desarrollo_qb@quimicaboss.com.mx
Subject: {subject}
Date: {formatdate(localtime=True)}
Message-ID: <simulated-{int(time.time())}@quimicaboss.com.mx>
Content-Type: text/plain; charset="utf-8"

{body}
""".encode('utf-8')

    worker = MailMonitorWorker()
    result = worker.process_single_message(raw_rfc822)
    
    # Guardar en base de datos
    record_id = save_incoming_report(result['db_payload'])
    
    # Guardar vista previa HTML
    preview_file = os.path.join(APP_DIR, 'preview_email_report.html')
    if save_html_preview:
        with open(preview_file, 'w', encoding='utf-8') as f:
            f.write(result['report']['html'])
        logger.info(f"📄 Vista previa del reporte generada en: {preview_file}")

    print("\n" + "=" * 80)
    print("SIMULACIÓN DE REPORTE AUTOMÁTICO DE SEGURIDAD (v3.5)")
    print("=" * 80)
    print(f"ID Base de Datos: #{record_id}")
    print(f"Asunto Respuesta: {result['report']['subject']}")
    print(f"Veredicto:       {result['prediction']['is_phishing']} (Score: {result['prediction']['risk_score']}/100)")
    print(f"Confianza:       {result['prediction']['confidence'] * 100:.1f}%")
    print(f"Amenazas:        {result['prediction'].get('threats', [])}")
    print(f"Adjuntos:        {result['email_info'].get('attachments', [])}")
    print(f"Enlaces:         {result['email_info']['urls']}")
    print("-" * 80)
    print("CUERPO DE TEXTO PLANO QUE RECIBIRÍA EL USUARIO:")
    print("-" * 80)
    print(result['report']['plain'])
    print("=" * 80)

    return result


# =====================================================================
# 7. Punto de Entrada CLI
# =====================================================================
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Servicio de Buzón de Correo y Respuesta Automática (Dory.lat)")
    parser.add_argument('--simulate', action='store_true', help='Ejecuta una simulación local y genera preview_email_report.html')
    parser.add_argument('--sample', choices=['sat', 'banco', 'malware_attach', 'legitimo'], default='sat', help='Muestra a simular')
    parser.add_argument('--status', action='store_true', help='Muestra el estado de la configuración y estadísticas de la base de datos')
    parser.add_argument('--run', action='store_true', help='Ejecuta una sola revisión de la bandeja de entrada IMAP')
    parser.add_argument('--daemon', action='store_true', help='Ejecuta el demonio continuo con soporte IMAP IDLE en tiempo real')

    args = parser.parse_args()

    if args.status:
        cfg = MailConfig()
        print("\n--- Estado del Servicio de Correo Dory (v3.5 Alta Capacidad) ---")
        print(f"Configuración cargada: {'✅ Configurada' if cfg.is_configured() else '⚠️ Incompleta'}")
        print(f"Servidor IMAP:        {cfg.imap_server}:{cfg.imap_port} (SSL: {cfg.imap_use_ssl})")
        print(f"Usuario IMAP:         {cfg.imap_user or '(No configurado)'}")
        print(f"Servidor SMTP:        {cfg.smtp_server}:{cfg.smtp_port} (SSL: {cfg.smtp_use_ssl})")
        print(f"Dominio Autorizado:   @{cfg.allowed_domain}")
        print(f"Concurrencia:         {cfg.max_workers} hilos de procesamiento en paralelo")
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*), SUM(CASE WHEN prediction='PHISHING' THEN 1 ELSE 0 END) FROM incoming_phishing_reports")
            total, phish = cur.fetchone()
            conn.close()
            print(f"Reportes en Base de Datos: Total: {total or 0} | Phishing: {phish or 0}")
        except Exception as e:
            print(f"Error consultando base de datos: {e}")

    elif args.run:
        worker = MailMonitorWorker()
        count = worker.check_and_process_inbox()
        print(f"Ciclo completado. Mensajes procesados: {count}")

    elif args.daemon:
        worker = MailMonitorWorker()
        worker.run_daemon()

    else:
        run_simulation(sample_key=args.sample)
