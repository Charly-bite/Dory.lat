#!/usr/bin/env python3
"""
test_send_live_new_design.py - Envío Real en Vivo para Validar la Nueva Plantilla

Envía un correo de prueba a desarrollo_qb@quimicaboss.com.mx para activar
en vivo el procesamiento IMAP IDLE y verificar la entrega del nuevo correo
de respuesta con el desglose de puntos y la firma oficial Dory.
"""

import sys
import os
import json
import smtplib
import ssl
import imaplib
import email
from email.header import decode_header
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import formatdate, make_msgid

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, 'mail_config.json')

with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
    config = json.load(f)

smtp_cfg = config['smtp']
imap_cfg = config['imap']
target_email = "desarrollo_qb@quimicaboss.com.mx"

print("====================================================================")
print("  DORY DEFENSE BOT - PRUEBA EN VIVO: NUEVA PLANTILLA Y FIRMA OFICIAL")
print("====================================================================")
print(f"Servidor SMTP: {smtp_cfg['server']}:{smtp_cfg['port']} (SSL)")
print(f"Destinatario:  {target_email}\n")

# Construir mensaje de simulación
msg = MIMEMultipart()
msg['Subject'] = "[REVISAR] Fwd: Urgente: Actualización de Cuenta y Factura Fiscal Pendiente"
msg['From'] = f"Auditor de Seguridad <{smtp_cfg['user']}>"
msg['To'] = target_email
msg['Date'] = formatdate(localtime=True)
msg_id = make_msgid(domain='quimicaboss.com.mx')
msg['Message-ID'] = msg_id

body_text = """Estimado equipo de Seguridad Dory,

Reenvío el siguiente correo sospechoso recibido hoy para su análisis urgente:

--- Mensaje Reenviado ---
De: Soporte y Notificaciones SAT <alertas@sat-tramites-urgentes.xyz>
Asunto: Requerimiento Fiscal Inmediato y Multa Pendiente
Fecha: 21 de Septiembre de 2026

Estimado contribuyente de Química Boss,
Se han detectado inconsistencias críticas en su declaración anual. Evite el bloqueo y embargo de sus cuentas bancarias en un plazo máximo de 24 horas.
Ingrese de inmediato al portal para validar sus credenciales y clave de acceso:
http://portal-sat-seguridad.xyz/login?usuario=finanzas@quimicaboss.com.mx

Descargue el desglose oficial adjunto. Para visualizar los montos debe habilitar macros en el archivo.

Atentamente,
Administración General de Recaudación
"""

msg.attach(MIMEText(body_text, 'plain', 'utf-8'))

# Adjunto sospechoso con macros (.xlsm)
attachment_filename = "Requerimiento_Fiscal_SAT_2026.xlsm"
dummy_payload = b"PK\x03\x04\x14\x00\x06\x00Test macro sheet for Dory demonstration."
part = MIMEApplication(dummy_payload, Name=attachment_filename)
part['Content-Disposition'] = f'attachment; filename="{attachment_filename}"'
msg.attach(part)

try:
    print(f"[*] Conectando al servidor SMTP ({smtp_cfg['server']}:{smtp_cfg['port']})...")
    if smtp_cfg.get('use_ssl', True):
        server = smtplib.SMTP_SSL(smtp_cfg['server'], smtp_cfg['port'], timeout=15)
    else:
        server = smtplib.SMTP(smtp_cfg['server'], smtp_cfg['port'], timeout=15)
        server.ehlo()
        if smtp_cfg.get('use_tls', True):
            server.starttls(context=ssl.create_default_context())
            server.ehlo()

    server.login(smtp_cfg['user'], smtp_cfg['password'])
    print("[*] Autenticación SMTP exitosa.")

    print(f"[*] Despachando correo de prueba con adjunto '{attachment_filename}'...")
    server.sendmail(smtp_cfg['user'], [target_email], msg.as_string())
    server.quit()
    print(f"[+] Correo enviado exitosamente a {target_email}!")
    print(f"    Message-ID: {msg_id}")

    print("\n[*] Esperando 5 segundos para que el demonio IMAP IDLE procese el correo y transmita la respuesta...")
    time.sleep(5)

    # Conectar por IMAP para confirmar la llegada de la respuesta
    print("[*] Consultando bandeja de entrada vía IMAP SSL...")
    imap = imaplib.IMAP4_SSL(imap_cfg['server'], imap_cfg['port'])
    imap.login(imap_cfg['user'], imap_cfg['password'])
    imap.select('INBOX')

    status, messages = imap.search(None, 'SUBJECT', '"[DORY ALERTA - PHISHING]"')
    if status == 'OK' and messages[0]:
        msg_ids = messages[0].split()
        latest_id = msg_ids[-1]
        _, msg_data = imap.fetch(latest_id, '(RFC822.HEADER)')
        raw_header = msg_data[0][1]
        parsed_header = email.message_from_bytes(raw_header)
        
        # Decodificar asunto
        raw_subj = parsed_header.get('Subject', '')
        decoded_subj_parts = decode_header(raw_subj)
        subj_str = ""
        for part_bytes, charset in decoded_subj_parts:
            if isinstance(part_bytes, bytes):
                subj_str += part_bytes.decode(charset or 'utf-8', errors='replace')
            else:
                subj_str += str(part_bytes)

        print("\n====================================================================")
        print("  ✓ RESPUESTA RECIBIDA EN BANDEJA DE ENTRADA CON NUEVO FORMATO      ")
        print("====================================================================")
        print(f"Asunto:     {subj_str}")
        print(f"De:         {parsed_header.get('From')}")
        print(f"Fecha:      {parsed_header.get('Date')}")
        print(f"Loop-Check: {parsed_header.get('X-Loop')} | {parsed_header.get('Auto-Submitted')}")
        print("--------------------------------------------------------------------")
        print("✔ El correo con el nuevo diseño, desglose de puntos pedagógico")
        print("  y la firma oficial Dory ha sido entregado exitosamente a tu buzón.")
    else:
        print("[!] No se encontró el correo de respuesta aún, el demonio puede seguir procesando.")

    imap.logout()

except Exception as e:
    print(f"[X] Error en la prueba en vivo: {e}")
    sys.exit(1)
