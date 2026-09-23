#!/usr/bin/env python3
"""
test_send_live_attachment.py - Envío de Correo Real con Archivo Adjunto (Dory.lat)

Envía un correo real con archivo adjunto sospechoso a desarrollo_qb@quimicaboss.com.mx
utilizando el servidor SMTP autenticado (SSL puerto 465) para activar en vivo
el escáner de adjuntos y la respuesta automática de Dory.
"""

import sys
import os
import json
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import formatdate, make_msgid

# Windows encoding support
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
target_email = "desarrollo_qb@quimicaboss.com.mx"

print("====================================================================")
print("  DORY DEFENSE BOT - PRUEBA EN VIVO: ENVÍO REAL CON ADJUNTO        ")
print("====================================================================")
print(f"Servidor SMTP: {smtp_cfg['server']}:{smtp_cfg['port']} (SSL)")
print(f"Cuenta:        {smtp_cfg['user']}")
print(f"Destinatario:  {target_email}\n")

# Construir mensaje MIME con adjunto
msg = MIMEMultipart()
msg['Subject'] = "[REVISAR] Fwd: Comprobante de Pago SPEI y Factura para revisión de seguridad"
msg['From'] = f"Auditor TI <{smtp_cfg['user']}>"
msg['To'] = target_email
msg['Date'] = formatdate(localtime=True)
msg_id = make_msgid(domain='quimicaboss.com.mx')
msg['Message-ID'] = msg_id

body_text = """Estimado equipo de Ciberseguridad Dory (Química Boss),

Reenvío este correo sospechoso recibido el día de hoy de un supuesto proveedor externo.
El mensaje solicita abrir la plantilla adjunta y habilitar macros para visualizar los montos y comprobantes fiscales.
Favor de evaluar si el archivo adjunto es seguro antes de procesar el pago.

Datos del correo recibido:
De: Facturación y Cobranza <notificaciones@pagos-spei-proveedor.top>
Asunto: Factura Vencida y Comprobante SPEI
Cuerpo: "Para visualizar el desglose de retenciones, debe habilitar macros al abrir el archivo adjunto."

Saludos cordiales,
Ing. Carlos Aceves - Química Boss
"""

msg.attach(MIMEText(body_text, 'plain', 'utf-8'))

# Adjuntar archivo con macro sospechosa (.xlsm)
attachment_filename = "Factura_Costos_Proveedor.xlsm"
dummy_payload = b"PK\x03\x04\x14\x00\x06\x00Benign test macro-enabled spreadsheet for Dory Phishing Defense."
part = MIMEApplication(dummy_payload, Name=attachment_filename)
part['Content-Disposition'] = f'attachment; filename="{attachment_filename}"'
msg.attach(part)

# Conectar y enviar
try:
    print(f"[*] Conectando a {smtp_cfg['server']}:{smtp_cfg['port']}...")
    server = smtplib.SMTP_SSL(smtp_cfg['server'], smtp_cfg['port'], timeout=15)
    server.login(smtp_cfg['user'], smtp_cfg['password'])
    print("[*] Autenticación SMTP exitosa.")
    
    print(f"[*] Enviando correo con adjunto '{attachment_filename}'...")
    server.sendmail(smtp_cfg['user'], [target_email], msg.as_string())
    server.quit()
    print(f"\n{chr(27)}[92m[✓] Correo de prueba enviado con éxito a {target_email}.{chr(27)}[0m")
    print(f"    Message-ID: {msg_id}")
    print("\n[*] Esperando 4 segundos a que el demonio IMAP IDLE procese el correo y emita el reporte...")
    time.sleep(4)

except Exception as e:
    print(f"\n{chr(27)}[91m[X] Error enviando correo: {e}{chr(27)}[0m")
    sys.exit(1)
