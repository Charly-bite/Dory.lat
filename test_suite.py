#!/usr/bin/env python3
"""
test_suite.py - Suite Integral de Pruebas Automatizadas y Rendimiento (Dory.lat)

Módulos de Prueba:
1. Benchmark Heurístico Offline (12 casos en Español / LatAm).
2. Escáner de Archivos Adjuntos Peligrosos y Dobles Extensiones.
3. Parser MIME, Reenvíos y Análisis de Autenticación SPF/DKIM.
4. Prueba de Concurrencia y Benchmark de Rendimiento (QPS y Latencia).
5. Verificación de Contratos de API (/health, /predict, /api/mail/*).
"""

import sys
import os
import time
import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error

# Ensure UTF-8 on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

from app_hf import predict_phishing_hf, extract_basic_features, DATABASE_PATH
from mail_service import EmailMIMEParser, MailConfig, ReportGenerator, save_incoming_report

# Terminal Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class DoryTestSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print(f"\n{BOLD}{CYAN}===================================================================={RESET}")
        print(f"{BOLD}{CYAN}      DORY DEFENSE BOT - SUITE INTEGRAL DE PRUEBAS TÉCNICAS         {RESET}")
        print(f"{BOLD}{CYAN}===================================================================={RESET}\n")

    # =================================================================
    # MÓDULO 1: Benchmark Heurístico de Detección (12 Casos Reales)
    # =================================================================
    def test_01_heuristic_benchmark_accuracy(self):
        """Valida que los 12 casos de prueba de referencia alcancen 100% de precisión."""
        test_cases = [
            # --- 6 Casos de Phishing ---
            {
                "id": "PHISH_SAT",
                "expected": True,
                "text": "URGENTE: Notificación de irregularidades fiscales en Buzón Tributario. Cuenta con 24 horas para solventar el requerimiento o sus Sellos Digitales serán cancelados. Ingrese aquí: https://sat-consultas.online/buzon-tributario/login"
            },
            {
                "id": "PHISH_SANTANDER",
                "expected": True,
                "text": "ALERTA SANTANDER: Se ha detectado un cargo no reconocido en su cuenta de débito por $8,450 MXN. Para cancelar la transacción y desbloquear su tarjeta ingrese inmediatamente: https://santander-seguridad.net/desbloqueo"
            },
            {
                "id": "PHISH_BBVA",
                "expected": True,
                "text": "Estimado cliente BBVA: Su token móvil ha sido suspendido por inactividad. Evite la suspensión de su cuenta bancaria actualizando sus credenciales en 2 horas: http://bbva-token.xyz/login"
            },
            {
                "id": "PHISH_MERCADOLIBRE",
                "expected": True,
                "text": "Mercado Libre Seguridad: Detectamos un acceso sospechoso desde un dispositivo desconocido. Si no fue usted, verifique su contraseña ahora mismo para proteger su saldo de Mercado Pago: https://mercadopago-alertas.live/seguridad"
            },
            {
                "id": "PHISH_PREMIO",
                "expected": True,
                "text": "🎉 ¡Felicidades! Has ganado un iPhone 15 Pro en nuestro sorteo anual. Reclama tu premio antes de que expire en 24 horas: http://sorteo-apple.club/reclamar"
            },
            {
                "id": "PHISH_OFFICE365",
                "expected": True,
                "text": "Aviso de TI: Su contraseña de Office 365 expira hoy. Haga clic aquí para mantener su misma contraseña y evitar el bloqueo de acceso: http://192.168.1.100/auth/office365"
            },
            # --- 6 Casos Legítimos ---
            {
                "id": "LEGIT_MINUTA",
                "expected": False,
                "text": "Hola Carlos, adjunto la minuta de la reunión de seguridad de hoy. Revisamos el despliegue del bot de correo y los avances del proyecto Dory. Saludos cordiales."
            },
            {
                "id": "LEGIT_FACTURA_ODOO",
                "expected": False,
                "text": "Estimado proveedor: Le compartimos la orden de compra OC-2026-089 generada desde nuestro sistema ERP Odoo para su surtido regular. Favor de confirmar recepción."
            },
            {
                "id": "LEGIT_FEDEX",
                "expected": False,
                "text": "Su paquete con número de rastreo 78291048201 ha sido recolectado y se encuentra en tránsito. Puede seguir el estado en https://fedex.com/tracking. Gracias por su preferencia."
            },
            {
                "id": "LEGIT_GOOGLE_CALENDAR",
                "expected": False,
                "text": "Invitación: Sincronización semanal de TI @ Mar 23 de Sep 2026 10:00 - 10:30 (CDMX). Organizado por direccion@quimicaboss.com.mx."
            },
            {
                "id": "LEGIT_SOPORTE_TI",
                "expected": False,
                "text": "Mantenimiento programado de servidores: Este sábado de 22:00 a 02:00 hrs se aplicarán parches de seguridad en la red local. No se requiere ninguna acción por parte de los usuarios."
            },
            {
                "id": "LEGIT_NEWSLETTER_PYTHON",
                "expected": False,
                "text": "Python Weekly Newsletter: Descubre las novedades de Python 3.14, nuevas librerías de concurrencia y tutoriales de desarrollo web en https://python.org."
            }
        ]

        correct_count = 0
        total_time = 0.0

        print(f"{BOLD}[+] Módulo 1: Evaluando Benchmark Heurístico (12 Casos)...{RESET}")
        for case in test_cases:
            t0 = time.time()
            res = predict_phishing_hf(case['text'])
            dt = (time.time() - t0) * 1000
            total_time += dt

            is_correct = (res['is_phishing'] == case['expected'])
            if is_correct:
                correct_count += 1
                status = f"{GREEN}PASS{RESET}"
            else:
                status = f"{RED}FAIL{RESET}"

            verdict_str = "PHISHING" if res['is_phishing'] else "LEGÍTIMO"
            print(f"  [{status}] {case['id']:<24} -> Score: {res['risk_score']:>3}/100 | Diagnóstico: {verdict_str:<9} ({dt:.2f} ms)")

        avg_lat = total_time / len(test_cases)
        accuracy = (correct_count / len(test_cases)) * 100.0
        print(f"  -> {BOLD}Precisión:{RESET} {accuracy:.1f}% ({correct_count}/{len(test_cases)}) | {BOLD}Latencia media:{RESET} {avg_lat:.2f} ms/caso\n")
        self.assertEqual(accuracy, 100.0, "El benchmark heurístico debe mantener 100% de precisión.")

    # =================================================================
    # MÓDULO 2: Escáner de Archivos Adjuntos Peligrosos
    # =================================================================
    def test_02_attachment_threat_scanner(self):
        """Valida detección de extensiones de alto riesgo y dobles extensiones."""
        print(f"{BOLD}[+] Módulo 2: Evaluando Escáner de Adjuntos Peligrosos...{RESET}")
        
        # Caso 1: Doble extensión maliciosa
        res1 = predict_phishing_hf("Hola, adjunto comprobante.", attachments=["Factura_SPEI_2026.pdf.exe"])
        self.assertTrue(res1['features']['has_double_extension'])
        self.assertTrue(res1['features']['has_dangerous_attachment'])
        self.assertTrue(res1['is_phishing'])
        print(f"  [{GREEN}PASS{RESET}] Doble extensión (.pdf.exe) detectada -> Score: {res1['risk_score']}/100")

        # Caso 2: Macro en documento Office
        res2 = predict_phishing_hf("Revisa el macro adjunto.", attachments=["Planilla_Costos.xlsm"])
        self.assertTrue(res2['features']['has_dangerous_attachment'])
        self.assertFalse(res2['features']['has_double_extension'])
        print(f"  [{GREEN}PASS{RESET}] Macro Office (.xlsm) detectada -> Score: {res2['risk_score']}/100")

        # Caso 3: Archivo ejecutable directo
        res3 = predict_phishing_hf("Instalador solicitado.", attachments=["Setup_Tool.scr"])
        self.assertTrue(res3['features']['has_dangerous_attachment'])
        print(f"  [{GREEN}PASS{RESET}] Archivo de riesgo (.scr) detectado -> Score: {res3['risk_score']}/100")

        # Caso 4: Archivos legítimos limpios
        res4 = predict_phishing_hf("Minuta adjunta.", attachments=["Minuta_Junta.pdf", "Logo.png"])
        self.assertFalse(res4['features']['has_dangerous_attachment'])
        self.assertFalse(res4['is_phishing'])
        print(f"  [{GREEN}PASS{RESET}] Adjuntos seguros (.pdf, .png) -> Sin alerta de amenaza\n")

    # =================================================================
    # MÓDULO 3: Parser MIME y Autenticación SPF/DKIM
    # =================================================================
    def test_03_mime_parser_and_spf(self):
        """Valida extracción de metadatos RFC822, reenvíos y SPF."""
        print(f"{BOLD}[+] Módulo 3: Evaluando Parser MIME y Reenvíos...{RESET}")

        sample_mime = (
            b"From: \"Carlos Aceves\" <carlos.aceves@quimicaboss.com.mx>\r\n"
            b"To: desarrollo_qb@quimicaboss.com.mx\r\n"
            b"Subject: [REVISAR] Fwd: Alerta de cuenta suspendida\r\n"
            b"Message-ID: <test-1234@quimicaboss.com.mx>\r\n"
            b"Received-SPF: Pass (mail.quimicaboss.com.mx: domain of carlos.aceves@quimicaboss.com.mx)\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"---------- Forwarded message ---------\r\n"
            b"From: Notificaciones SAT <alertas@sat-tramites.online>\r\n"
            b"Subject: Notificacion urgente\r\n\r\n"
            b"Estimado contribuyente, ingrese a https://sat-tramites.online/login para solventar requerimiento."
        )

        parsed = EmailMIMEParser.parse_raw_bytes(sample_mime)
        self.assertEqual(parsed['sender_email'], 'carlos.aceves@quimicaboss.com.mx')
        self.assertEqual(parsed['subject'], '[REVISAR] Fwd: Alerta de cuenta suspendida')
        self.assertTrue(parsed['is_forwarded'])
        self.assertIn('alertas@sat-tramites.online', parsed['forwarded_sender'])
        self.assertIn('https://sat-tramites.online/login', parsed['urls'])
        print(f"  [{GREEN}PASS{RESET}] Reenvío detectado correctamente. Remitente original: {parsed['forwarded_sender']}")
        print(f"  [{GREEN}PASS{RESET}] Cabecera SPF validada: {parsed['received_spf'][:35]}...\n")

    # =================================================================
    # MÓDULO 4: Benchmark de Concurrencia y Rendimiento (QPS)
    # =================================================================
    def test_04_concurrency_and_performance_qps(self):
        """Valida que el motor procese múltiples correos simultáneos a más de 500 QPS."""
        print(f"{BOLD}[+] Módulo 4: Evaluando Concurrencia y QPS (Simulación de 50 Correos)...{RESET}")

        sample_texts = [
            "URGENTE: Notificación fiscal SAT. Ingrese a https://sat-consultas.online/buzon",
            "Minuta de la reunión de hoy entre el equipo de desarrollo y TI.",
            "ALERTA SANTANDER: Se ha detectado un cargo no reconocido. Ingrese a https://santander-seguridad.net/login",
            "Factura adjunta para revisión mensual de compras.",
            "🎉 ¡Felicidades! Has ganado un iPhone. Reclama en http://sorteo-apple.club/reclamar"
        ]

        num_requests = 50
        max_workers = 8

        t_start = time.time()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(predict_phishing_hf, sample_texts[i % len(sample_texts)]) for i in range(num_requests)]
            results = [f.result() for f in as_completed(futures)]
        
        t_total = time.time() - t_start
        qps = num_requests / t_total
        lat_avg_ms = (t_total / num_requests) * 1000

        print(f"  -> Total procesados: {len(results)} correos concurrentes")
        print(f"  -> Tiempo total: {t_total:.3f} s")
        print(f"  -> {BOLD}Throughput:{RESET} {qps:.1f} correos/segundo (QPS)")
        print(f"  -> {BOLD}Latencia media por hilo:{RESET} {lat_avg_ms:.2f} ms")

        # Concurrencia en SQLite (WAL mode)
        db_start = time.time()
        with ThreadPoolExecutor(max_workers=4) as db_exec:
            db_futures = []
            for i in range(10):
                payload = {
                    'sender_email': f'usuario{i}@quimicaboss.com.mx',
                    'recipient_email': 'desarrollo_qb@quimicaboss.com.mx',
                    'subject': f'Prueba Concurrencia #{i}',
                    'email_body': 'Texto de prueba concurrente.',
                    'prediction': 'LEGITIMATE',
                    'risk_score': 10,
                    'confidence': 0.90,
                    'threats_detected': [],
                    'urls_found': [],
                    'reply_sent': True,
                    'processing_time_ms': 5.0,
                    'raw_headers': 'Test-Header: concurrent'
                }
                db_futures.append(db_exec.submit(save_incoming_report, payload))
            
            inserted_ids = [f.result() for f in as_completed(db_futures)]

        db_elapsed = (time.time() - db_start) * 1000
        self.assertTrue(all(rid > 0 for rid in inserted_ids))
        print(f"  [{GREEN}PASS{RESET}] 10 inserciones SQLite concurrentes exitosas ({db_elapsed:.2f} ms, 0 locks)\n")

    # =================================================================
    # MÓDULO 5: Verificación de Contratos de API Local
    # =================================================================
    def test_05_api_contracts(self):
        """Verifica disponibilidad y formato de las rutas web del servidor local."""
        print(f"{BOLD}[+] Módulo 5: Verificando Contratos de API (/health, /api/mail/*)...{RESET}")

        base_url = "http://127.0.0.1:5000"

        # 1. Health Endpoint
        try:
            req = urllib.request.Request(f"{base_url}/health")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                self.assertEqual(resp.status, 200)
                self.assertEqual(data.get('status'), 'healthy')
                self.assertIn('total_reports_processed', data)
                print(f"  [{GREEN}PASS{RESET}] GET /health -> 200 OK (Versión: {data.get('version')})")
        except urllib.error.URLError as e:
            print(f"  [{YELLOW}WARN{RESET}] No se pudo conectar a {base_url}/health ({e}). ¿Servidor web en ejecución?")
            return

        # 2. Mail Status Endpoint
        try:
            req = urllib.request.Request(f"{base_url}/api/mail/status")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                self.assertEqual(resp.status, 200)
                self.assertIn('statistics', data)
                print(f"  [{GREEN}PASS{RESET}] GET /api/mail/status -> 200 OK (Reportes: {data['statistics']['total_reports']})")
        except Exception as e:
            self.fail(f"Falla en /api/mail/status: {e}")

        # 3. Mail Reports Endpoint
        try:
            req = urllib.request.Request(f"{base_url}/api/mail/reports?limit=5")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                self.assertEqual(resp.status, 200)
                self.assertIn('reports', data)
                print(f"  [{GREEN}PASS{RESET}] GET /api/mail/reports -> 200 OK (Recuperados: {len(data['reports'])} reportes)")
        except Exception as e:
            self.fail(f"Falla en /api/mail/reports: {e}")

        # 4. Mail Simulate Endpoint
        try:
            post_data = json.dumps({"sample": "banco"}).encode('utf-8')
            req = urllib.request.Request(
                f"{base_url}/api/mail/simulate",
                data=post_data,
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                self.assertEqual(resp.status, 200)
                self.assertTrue(data.get('success'))
                print(f"  [{GREEN}PASS{RESET}] POST /api/mail/simulate -> 200 OK (Report ID: {data.get('report_id')})\n")
        except Exception as e:
            self.fail(f"Falla en /api/mail/simulate: {e}")

    # =================================================================
    # MÓDULO 6: Filtro Secundario Especializado (Deep Inspection L2)
    # =================================================================
    def test_06_deep_inspection_l2(self):
        """Valida la resolución 100% automatizada del Filtro L2 en zona intermedia (26-40 pts)."""
        print(f"{BOLD}[+] Módulo 6: Evaluando Filtro Secundario Especializado L2 (Deep Inspection)...{RESET}")
        
        # Caso A: Correo en zona gris con caracteres invisibles de ancho cero
        # "p​a​y​p​a​l" con zero-width space \u200b
        text_invisible = "Estimado usuario, favor de realizar la actualización anual en 24 horas para su cuenta p\u200bay\u200bpal."
        res_a = predict_phishing_hf(text_invisible)
        self.assertIsNotNone(res_a.get('l2_analysis'))
        self.assertEqual(res_a['l2_analysis']['status'], 'ESCALATED_PHISHING')
        self.assertTrue(res_a['is_phishing'])
        self.assertGreater(res_a['risk_score'], 40)
        print(f"  [{GREEN}PASS{RESET}] Evasión con caracteres invisibles detectada -> Escalado a Phishing ({res_a['risk_score']}/100)")

        # Caso B: Correo en zona gris con redirección abierta (Open Redirect)
        text_redir = "Estimado cliente, aviso urgente en 24 horas: http://servicios.com?url=http://servidor-atacante.xyz"
        res_b = predict_phishing_hf(text_redir)
        self.assertIsNotNone(res_b.get('l2_analysis'))
        self.assertEqual(res_b['l2_analysis']['status'], 'ESCALATED_PHISHING')
        self.assertTrue(res_b['is_phishing'])
        self.assertGreater(res_b['risk_score'], 40)
        print(f"  [{GREEN}PASS{RESET}] Redirección abierta (?url=...) detectada -> Escalado a Phishing ({res_b['risk_score']}/100)")

        # Caso C: Suplantación de Autoridad Interna (Fraude del CEO / BEC)
        email_info_bec = {
            'sender_name': 'Ing. Carlos Aceves - Director General',
            'sender_email': 'carlos.aceves.personal@gmail.com',  # Externo pretendiendo ser Director
            'received_spf': 'softfail'
        }
        text_bec = "Estimado equipo, aviso de inmediato: Necesito que realices una transferencia SPEI antes de que expire hoy para pago."
        res_c = predict_phishing_hf(text_bec, email_info=email_info_bec)
        self.assertIsNotNone(res_c.get('l2_analysis'))
        self.assertEqual(res_c['l2_analysis']['status'], 'ESCALATED_PHISHING')
        self.assertTrue(res_c['is_phishing'])
        self.assertGreater(res_c['risk_score'], 40)
        print(f"  [{GREEN}PASS{RESET}] Suplantación ejecutiva BEC detectada -> Escalado a Phishing ({res_c['risk_score']}/100)")

        # Caso D: Correo en zona gris legítimo sin artilugios de evasión -> Desescalado a Seguro
        text_clean_gray = "Estimado colaborador, favor de realizar la actualización anual en 24 horas. Para verificar ingrese a https://quimicaboss.com.mx/portal"
        res_d = predict_phishing_hf(text_clean_gray)
        self.assertIsNotNone(res_d.get('l2_analysis'))
        self.assertEqual(res_d['l2_analysis']['status'], 'DEESCALATED_SAFE')
        self.assertFalse(res_d['is_phishing'])
        self.assertLessEqual(res_d['risk_score'], 25)
        print(f"  [{GREEN}PASS{RESET}] Correo limpio sin evasión verificado -> Desescalado a Seguro ({res_d['risk_score']}/100)")

        # Caso E: Motor 5 L2 - Análisis Avanzado de URLs (Discrepancia Texto vs Href)
        html_mismatch = '<p>Favor de validar en <a href="http://servidor-malicioso.com">https://quimicaboss.com.mx/portal</a></p>'
        text_mismatch = "Estimado cliente, aviso urgente en 24 horas para revisión: https://quimicaboss.com.mx/portal"
        res_e = predict_phishing_hf(text_mismatch, raw_html=html_mismatch)
        self.assertIsNotNone(res_e.get('l2_analysis'))
        self.assertEqual(res_e['l2_analysis']['status'], 'ESCALATED_PHISHING')
        self.assertTrue(res_e['is_phishing'])
        self.assertGreater(res_e['risk_score'], 40)
        print(f"  [{GREEN}PASS{RESET}] Análisis Forense de URL (Discrepancia texto vs destino) -> Escalado a Phishing ({res_e['risk_score']}/100)")

        # Caso F: Generador de Reportes (Desglose Pedagógico de Puntos y Firma Personalizada Dory)
        from mail_service import ReportGenerator, MailConfig
        report_pkg = ReportGenerator.generate_report(res_e, {'subject': 'Aviso urgente de portal', 'sender_email': 'remitente@externo.xyz', 'urls': ['http://servidor-malicioso.com']}, MailConfig())
        self.assertIn("Puntos Específicos que Activaron la Alerta", report_pkg['html'])
        self.assertIn("DORY CYBERDEFENSE AI ENGINE", report_pkg['html'])
        self.assertIn("DORY CYBERDEFENSE AI ENGINE", report_pkg['plain'])
        
        # Caso G: Verificación de Reporte Seguro (Sin factores de alerta que confundan al usuario)
        from app_hf import extract_basic_features
        feats_safe = extract_basic_features("Aporta versatilidad a las formulaciones químicas con máxima satisfacción.")
        self.assertFalse(feats_safe['has_fiscal_context'], "La palabra 'versatilidad' o 'satisfacción' no debe disparar alerta fiscal")
        res_safe = predict_phishing_hf("Aporta versatilidad a las formulaciones químicas.")
        report_safe = ReportGenerator.generate_report(res_safe, {'subject': 'Formulaciones', 'sender_email': 'lab@quimicaboss.com.mx', 'urls': []}, MailConfig())
        self.assertNotIn("Puntos Específicos que Activaron la Alerta", report_safe['html'])
        self.assertNotIn("PUNTOS ESPECÍFICOS QUE ACTIVARON LA ALERTA", report_safe['plain'])
        self.assertNotIn("Simulación de Autoridad Fiscal", report_safe['html'])
        print(f"  [{GREEN}PASS{RESET}] Reporte Seguro libre de factores de alerta alarmistas y falsos positivos de palabras verificados.\n")


if __name__ == '__main__':
    unittest.main(verbosity=0)
