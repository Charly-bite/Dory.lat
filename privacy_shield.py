#!/usr/bin/env python3
"""
privacy_shield.py - Módulo de Anonimización y Escudo de Privacidad PII (Dory.lat)

Detecta, sanitiza y enmascara información personal identificable (PII), datos
financieros, credenciales e identificadores corporativos/fiscales antes de
que los textos sean procesados por modelos de IA o almacenados en auditoría.

Reemplaza los valores reales por tokens semánticos (ej. [TARJETA_PROTEGIDA])
para preservar intacta la capacidad de detección de ingeniería social y phishing
sin exponer la privacidad de los colaboradores ni de la organización.
"""

import re
import logging
from typing import Dict, List, Tuple, Any

logger = logging.getLogger("PrivacyShield")

def luhn_checksum(card_number_str: str) -> bool:
    """Valida si una secuencia numérica cumple con el algoritmo de Luhn (tarjetas de crédito/débito)."""
    digits = [int(d) for d in card_number_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class PrivacyShield:
    """Motor de detección y anonimización de datos sensibles y PII."""

    # 1. Identificadores Fiscales Mexicanos (RFC y CURP)
    RE_CURP = re.compile(
        r'\b[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d\b',
        re.IGNORECASE
    )
    RE_RFC = re.compile(
        r'\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b',
        re.IGNORECASE
    )

    # 2. Datos Financieros
    RE_CLABE = re.compile(
        r'\b\d{18}\b'
    )
    RE_CARD_CANDIDATE = re.compile(
        r'\b(?:\d{4}[ -]){3}\d{4}\b|\b\d{15,16}\b'
    )
    RE_CVV = re.compile(
        r'(?i)\b(?:cvv|cvc|código de seguridad|codigo de seguridad)[:=\s]+(\d{3,4})\b'
    )

    # 3. Credenciales y Secretos (requiere asignación explícita : o =)
    RE_PASSWORD = re.compile(
        r'(?i)(?:password|contraseña|clave|token|secret|acceso)\s*[:=]\s*["\']?([^\s"\'<>]{4,})["\']?'
    )
    RE_BEARER = re.compile(
        r'(?i)\bBearer\s+[a-zA-Z0-9_\-\.]{16,}\b'
    )
    RE_API_KEY = re.compile(
        r'(?i)(?:api[_-]?key|secret[_-]?key)[:=\s]+["\']?([a-zA-Z0-9_\-]{16,})["\']?'
    )

    # 4. Teléfonos (formatos mexicanos de 10 dígitos o con código +52)
    RE_PHONE = re.compile(
        r'(?i)(?:(?:tel(?:éfono)?|cel(?:ular)?|whatsapp|móvil)[:=\s]*)?'
        r'(?:\+?52[\s.-]?)?(?:\(?\d{2,3}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}\b'
    )

    # 5. Saludos con Nombres Personales (Preserva títulos corporativos)
    RE_SALUTATION_NAME = re.compile(
        r'(?i)\b(estimad[oa]s?|atentamente|saludos|saludos cordiales|de parte de|lic\.|ing\.|dr\.|dra\.|sr\.|sra\.)\s+'
        r'([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+){1,3})'
    )

    @classmethod
    def anonymize_text(cls, text: str, allowed_domain: str = "quimicaboss.com.mx") -> Dict[str, Any]:
        """
        Sanitiza y anonimiza el texto reemplazando PII con tokens semánticos.
        Preserva los enlaces sospechosos para que la evaluación de phishing no se altere.
        """
        if not text:
            return {
                'sanitized_text': "",
                'redacted_entities': [],
                'has_sensitive_data': False,
                'stats': {}
            }

        sanitized = text
        redacted = []
        stats = {
            'cards': 0,
            'clabe': 0,
            'rfc': 0,
            'curp': 0,
            'passwords': 0,
            'tokens': 0,
            'phones': 0,
            'emails': 0,
            'names': 0
        }

        # --- A. Credenciales y Secretos ---
        def mask_password(match):
            stats['passwords'] += 1
            full_match = match.group(0)
            pwd = match.group(1)
            preview = pwd[:2] + "****" if len(pwd) > 2 else "****"
            redacted.append({
                'category': 'Credencial / Contraseña',
                'preview': preview,
                'token': '[PASSWORD_PROTEGIDO]'
            })
            return full_match.replace(pwd, '[PASSWORD_PROTEGIDO]')

        sanitized = cls.RE_PASSWORD.sub(mask_password, sanitized)

        def mask_bearer(match):
            stats['tokens'] += 1
            redacted.append({
                'category': 'Token de Autenticación',
                'preview': 'Bearer ****',
                'token': 'Bearer [TOKEN_PROTEGIDO]'
            })
            return 'Bearer [TOKEN_PROTEGIDO]'

        sanitized = cls.RE_BEARER.sub(mask_bearer, sanitized)

        def mask_api_key(match):
            stats['tokens'] += 1
            full_match = match.group(0)
            key = match.group(1)
            redacted.append({
                'category': 'API Key / Secreto',
                'preview': key[:4] + "****",
                'token': '[API_KEY_PROTEGIDA]'
            })
            return full_match.replace(key, '[API_KEY_PROTEGIDA]')

        sanitized = cls.RE_API_KEY.sub(mask_api_key, sanitized)

        # --- B. CVV / Código de Seguridad ---
        def mask_cvv(match):
            stats['cards'] += 1
            full_match = match.group(0)
            cvv = match.group(1)
            redacted.append({
                'category': 'Código CVV',
                'preview': '***',
                'token': '[CVV_PROTEGIDO]'
            })
            return full_match.replace(cvv, '[CVV_PROTEGIDO]')

        sanitized = cls.RE_CVV.sub(mask_cvv, sanitized)

        # --- C. Cuentas CLABE (18 dígitos) ---
        def mask_clabe(match):
            val = match.group(0)
            if len(val) == 18:
                stats['clabe'] += 1
                preview = val[:4] + "********" + val[-4:]
                redacted.append({
                    'category': 'Cuenta CLABE Interbancaria',
                    'preview': preview,
                    'token': '[CLABE_PROTEGIDA]'
                })
                return '[CLABE_PROTEGIDA]'
            return val

        sanitized = cls.RE_CLABE.sub(mask_clabe, sanitized)

        # --- D. Tarjetas de Crédito / Débito (con validación de Luhn) ---
        def mask_card(match):
            val = match.group(0)
            clean_digits = re.sub(r'\D', '', val)
            if 15 <= len(clean_digits) <= 16 and luhn_checksum(clean_digits):
                stats['cards'] += 1
                preview = clean_digits[:4] + "-****-****-" + clean_digits[-4:]
                redacted.append({
                    'category': 'Tarjeta Bancaria',
                    'preview': preview,
                    'token': '[TARJETA_PROTEGIDA]'
                })
                return '[TARJETA_PROTEGIDA]'
            return val

        sanitized = cls.RE_CARD_CANDIDATE.sub(mask_card, sanitized)

        # --- E. Identificadores Fiscales: CURP y RFC ---
        def mask_curp(match):
            val = match.group(0)
            stats['curp'] += 1
            preview = val[:4] + "******" + val[-2:]
            redacted.append({
                'category': 'CURP (Identidad Nacional)',
                'preview': preview,
                'token': '[CURP_PROTEGIDO]'
            })
            return '[CURP_PROTEGIDO]'

        sanitized = cls.RE_CURP.sub(mask_curp, sanitized)

        def mask_rfc(match):
            val = match.group(0)
            # Excluir palabras comunes en mayúsculas que parezcan RFC
            excluded = {'SAT', 'SPEI', 'BBVA', 'IMSS', 'INFO', 'HTML', 'HTTP', 'POST', 'USER'}
            if val.upper() in excluded or '[RFC_PROTEGIDO]' in val:
                return val
            stats['rfc'] += 1
            preview = val[:3] + "******" + val[-2:]
            redacted.append({
                'category': 'RFC (Registro Federal de Contribuyentes)',
                'preview': preview,
                'token': '[RFC_PROTEGIDO]'
            })
            return '[RFC_PROTEGIDO]'

        sanitized = cls.RE_RFC.sub(mask_rfc, sanitized)

        # --- F. Correos de Empleados Corporativos ---
        if allowed_domain:
            re_corp_email = re.compile(
                r'\b([a-zA-Z0-9_.+-]+)@' + re.escape(allowed_domain) + r'\b',
                re.IGNORECASE
            )
            def mask_corp_email(match):
                stats['emails'] += 1
                user = match.group(1)
                preview = user[:2] + "***@" + allowed_domain
                redacted.append({
                    'category': 'Correo Corporativo Interno',
                    'preview': preview,
                    'token': f'[CORREO_EMPLEADO_PROTEGIDO]'
                })
                return f'[CORREO_EMPLEADO_PROTEGIDO]'

            sanitized = re_corp_email.sub(mask_corp_email, sanitized)

        # --- G. Teléfonos Personales ---
        def mask_phone(match):
            val = match.group(0)
            digits = re.sub(r'\D', '', val)
            # Solo enmascarar si tiene entre 10 y 13 dígitos y no es fecha (ej. 20260923)
            if 10 <= len(digits) <= 13:
                # Filtrar fechas numéricas tipo YYYYMMDD
                if digits.startswith(('19', '20')) and len(digits) == 8:
                    return val
                stats['phones'] += 1
                preview = digits[:2] + "****" + digits[-2:]
                redacted.append({
                    'category': 'Número Telefónico',
                    'preview': preview,
                    'token': '[TELEFONO_PROTEGIDO]'
                })
                return '[TELEFONO_PROTEGIDO]'
            return val

        sanitized = cls.RE_PHONE.sub(mask_phone, sanitized)

        # --- H. Nombres en Saludos / Despedidas ---
        def mask_name(match):
            salutation = match.group(1)
            name = match.group(2)
            # Excluir nombres comerciales y entidades reconocidas
            whitelist_entities = {
                'quimica boss', 'química boss', 'dory defense', 'sat',
                'servicio de administracion tributaria', 'servicio de administración tributaria',
                'banco santander', 'bbva bancomer', 'mercado libre', 'soporte tecnico',
                'soporte técnico', 'atencion a clientes', 'atención a clientes'
            }
            if name.lower().strip() in whitelist_entities:
                return match.group(0)

            stats['names'] += 1
            parts = name.split()
            preview = parts[0][:2] + "***"
            redacted.append({
                'category': 'Nombre de Colaborador / Persona',
                'preview': preview,
                'token': f"{salutation} [NOMBRE_PROTEGIDO]"
            })
            return f"{salutation} [NOMBRE_PROTEGIDO]"

        sanitized = cls.RE_SALUTATION_NAME.sub(mask_name, sanitized)

        has_sensitive_data = len(redacted) > 0

        return {
            'sanitized_text': sanitized,
            'redacted_entities': redacted,
            'has_sensitive_data': has_sensitive_data,
            'stats': stats,
            'total_redacted_count': len(redacted)
        }
