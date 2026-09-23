#!/usr/bin/env python3
"""
test_send_phishing.py - Envía un correo de prueba simulando un reenvío sospechoso
para comprobar el ciclo completo de detección y respuesta automática.
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

SMTP_SERVER = "mail.quimicaboss.com.mx"
SMTP_PORT = 465
USER = "desarrollo_qb@quimicaboss.com.mx"
PASSWORD = "QuimicaB.2025$$"

subject = "[REVISAR] Fwd: URGENTE: Notificacion de cargo no reconocido Santander"

body = """Hola equipo, me llego este correo y parece falso. Me ayudan a revisarlo?

---------- Forwarded message ---------
De: Banco Santander <seguridad@santander-banco-seguro.net>
Fecha: 21 de septiembre de 2026
Asunto: ALERTA: Cargo no reconocido en su tarjeta de debito
Para: desarrollo_qb@quimicaboss.com.mx

Estimado cliente Santander:

Hemos registrado un cargo sospechoso por $15,890.00 MXN en su cuenta.
Sus fondos han sido retenidos preventivamente.

Para cancelar este cargo y evitar multas, ingrese inmediatamente en menos de 2 horas a:
https://santander-banco-seguro.net/login/cancelar-cargo?id=83719

Atentamente,
Departamento de Prevencion de Fraudes Santander
"""

msg = MIMEText(body, 'plain', 'utf-8')
msg['Subject'] = subject
msg['From'] = USER
msg['To'] = USER
msg['Date'] = formatdate(localtime=True)
msg['Message-ID'] = make_msgid(domain='quimicaboss.com.mx')

print(f"[*] Conectando a {SMTP_SERVER}:{SMTP_PORT}...")
with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=ssl.create_default_context()) as server:
    server.login(USER, PASSWORD)
    server.sendmail(USER, [USER], msg.as_string())
    print("[+] Correo de prueba enviado exitosamente a la bandeja de entrada.")
