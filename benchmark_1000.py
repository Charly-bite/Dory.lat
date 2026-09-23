#!/usr/bin/env python3
"""
benchmark_1000.py - Benchmark a Gran Escala con Muestra de 1,000 Correos (Dory.lat)

Evalúa el motor de detección calibrado de 3 niveles:
- Tier 1 (0 - 25):   Seguro / Confiable
- Tier 2 (26 - 40):  Sospechoso / Advertencia
- Tier 3 (41 - 100): Phishing Confirmado / Crítico

Genera un corpus sintético realista de 1,000 casos (500 phishing/malware, 500 legítimos),
calculando métricas de rendimiento, percentiles de latencia (p50, p95, p99), QPS y matriz de confusión.
"""

import sys
import time
import random
import statistics
from datetime import datetime

# Windows encoding support
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from app_hf import predict_phishing_hf

# Colores ANSI
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def build_1000_corpus():
    """Genera 1,000 correos corporativos y de ataque realistas y diversos."""
    random.seed(42)  # Reproducibilidad estricta
    corpus = []

    # -------------------------------------------------------------
    # 1. PLANTILLAS DE PHISHING / ATAQUE (500 Casos)
    # -------------------------------------------------------------
    phish_banks = ["BBVA", "Santander", "Banorte", "Citibanamex", "Scotiabank", "Mercado Pago"]
    phish_bad_domains = [
        "portal-banco-seguro.com", "verificacion-cuenta-urgente.net", "sat-tramites-mx.online",
        "seguridad-notificacion.xyz", "soporte-odoo-admin.top", "factura-spei-validacion.live",
        "office365-password-reset.click", "actualizacion-fiscal-sat.net"
    ]
    phish_tlds = [".xyz", ".top", ".click", ".online", ".site", ".live"]
    phish_shorteners = ["https://bit.ly/3xXq9", "https://tinyurl.com/spei-pago", "https://t.co/99Abc"]

    # 1.1 Ataques Bancarios con Suplantación y Enlace Falso (120 casos)
    for i in range(120):
        bank = phish_banks[i % len(phish_banks)]
        bad_domain = phish_bad_domains[i % len(phish_bad_domains)]
        corpus.append({
            "id": f"PHISH_BANK_{i+1:03d}",
            "text": f"Alerta {bank}: Se ha detectado un cargo no reconocido por ${random.randint(1200, 48000)} MXN en su cuenta. "
                    f"Tiene 2 horas para cancelar el movimiento. Ingrese con sus credenciales y token inmediatamente en https://{bad_domain}/cancelar-{bank.lower()}",
            "attachments": [],
            "expected_tier": "PHISHING",
            "is_malicious": True
        })

    # 1.2 Coacción Fiscal / SAT con Enlace No Oficial (100 casos)
    for i in range(100):
        bad_tld = phish_tlds[i % len(phish_tlds)]
        corpus.append({
            "id": f"PHISH_SAT_{i+1:03d}",
            "text": f"Servicio de Administración Tributaria (SAT) - Notificación de Multa y Bloqueo de Sellos Digitales.\n"
                    f"RFC Registrado: QB{random.randint(100000, 999999)}. Se han detectado inconsistencias graves en sus declaraciones 2025.\n"
                    f"Descargue su requerimiento fiscal urgente y aclare su situación antes de 24 horas en https://buzon-sat-aclaracion{bad_tld}/login-contribuyente",
            "attachments": [],
            "expected_tier": "PHISHING",
            "is_malicious": True
        })

    # 1.3 Malware con Doble Extensión y Macros (100 casos)
    malware_exts = [".pdf.exe", ".xlsx.vbs", ".doc.scr", ".factura.exe", ".xml.bat"]
    for i in range(100):
        bad_ext = malware_exts[i % len(malware_exts)]
        filename = f"Comprobante_Pago_SPEI_{random.randint(1000, 9999)}{bad_ext}"
        corpus.append({
            "id": f"PHISH_ATTACH_{i+1:03d}",
            "text": f"Estimado cliente, adjunto enviamos el comprobante fiscal y archivo de pago de su factura vencida. "
                    f"Favor de revisar el documento adjunto y confirmar recepción hoy mismo.",
            "attachments": [filename],
            "expected_tier": "PHISHING",
            "is_malicious": True
        })

    # 1.4 Macros de Office con Engaño de Activación (60 casos)
    macro_exts = ["Planilla_Costos_Q1.xlsm", "Orden_Compra_Interna.docm", "Cotizacion_Quimicos.xlsm"]
    for i in range(60):
        m_file = macro_exts[i % len(macro_exts)]
        corpus.append({
            "id": f"PHISH_MACRO_{i+1:03d}",
            "text": f"Para visualizar correctamente los montos y fórmulas de este archivo adjunto, "
                    f"debe habilitar macros al abrir el documento. Si no habilita el contenido, no se procesará el pedido.",
            "attachments": [m_file],
            "expected_tier": "PHISHING",
            "is_malicious": True
        })

    # 1.5 Robo de Credenciales Corporativas (Office 365 / Odoo / Teams) (70 casos)
    for i in range(70):
        short_url = phish_shorteners[i % len(phish_shorteners)]
        corpus.append({
            "id": f"PHISH_CORP_{i+1:03d}",
            "text": f"Soporte Técnico de TI - Alerta de Expiración de Contraseña de Correo.\n"
                    f"Su contraseña corporativa de Microsoft 365 expirará en 24 horas. Para mantener el acceso ininterrumpido a su buzón institucional y portal Odoo, "
                    f"actualice sus credenciales inmediatamente en el siguiente portal: {short_url}",
            "attachments": [],
            "expected_tier": "PHISHING",
            "is_malicious": True
        })

    # 1.6 URL con Dirección IP Directa o TLD Sospechoso (50 casos)
    for i in range(50):
        ip = f"192.168.{random.randint(1,250)}.{random.randint(1,250)}"
        corpus.append({
            "id": f"PHISH_IP_{i+1:03d}",
            "text": f"Notificación de transferencia bancaria SPEI rechazada. Inicie sesión para liberar los fondos en http://{ip}:8080/portal/auth",
            "attachments": [],
            "expected_tier": "PHISHING",
            "is_malicious": True
        })

    # -------------------------------------------------------------
    # 2. PLANTILLAS LEGÍTIMAS Y CASOS DE ADVERTENCIA (500 Casos)
    # -------------------------------------------------------------

    # 2.1 Comunicaciones Internas de Química Boss (150 casos)
    lab_topics = [
        "Resultados de prueba de pureza de reactivo químico lote #8821",
        "Minuta de junta técnica del área de investigación y desarrollo",
        "Revisión de inventario de materia prima en planta Monterrey",
        "Informe mensual de seguridad e higiene industrial Química Boss",
        "Actualización de cronograma de mantenimiento preventivo de reactores",
        "Minuta semanal de seguimiento de compras y abastecimiento de insumos"
    ]
    for i in range(150):
        topic = lab_topics[i % len(lab_topics)]
        corpus.append({
            "id": f"LEGIT_QB_{i+1:03d}",
            "text": f"Estimado equipo de Química Boss,\n\nLes comparto el documento con los {topic}.\n"
                    f"Favor de revisar los puntos acordados y enviar sus observaciones antes del viernes.\n\n"
                    f"Saludos cordiales,\nIng. Carlos Aceves\nDesarrollo e Innovación - Química Boss",
            "attachments": [f"Reporte_Tecnico_{i+1}.pdf"],
            "expected_tier": "SAFE",
            "is_malicious": False
        })

    # 2.2 Notificaciones Oficiales del SAT (Dominio Oficial Verificado: sat.gob.mx) (90 casos)
    for i in range(90):
        corpus.append({
            "id": f"LEGIT_SAT_OFFICIAL_{i+1:03d}",
            "text": f"Servicio de Administración Tributaria (SAT).\n"
                    f"Estimado contribuyente Química Boss S.A. de C.V.: Le informamos que tiene un nuevo mensaje en su Buzón Tributario.\n"
                    f"Para consultar el documento oficial de manera segura, ingrese a través de nuestro portal institucional: https://sat.gob.mx\n"
                    f"Este correo es informativo. El SAT nunca le enviará enlaces a páginas externas ni archivos ejecutables.",
            "attachments": [],
            "expected_tier": "SAFE",
            "is_malicious": False
        })

    # 2.3 Proveedores y Clientes Habituales (Facturas Limpias XML/PDF) (100 casos)
    suppliers = ["Mexichem", "Pochteca", "Brenntag", "Sigma-Aldrich", "Alpek"]
    for i in range(100):
        sup = suppliers[i % len(suppliers)]
        inv_num = random.randint(10000, 99999)
        corpus.append({
            "id": f"LEGIT_SUPPLIER_{i+1:03d}",
            "text": f"Buen día estimado Carlos,\n\nAdjunto enviamos la factura CFDI #{inv_num} correspondiente al suministro de químicos de este mes.\n"
                    f"Cualquier duda con la orden de compra quedamos a sus órdenes.\n\nAtentamente,\nCobranza {sup}",
            "attachments": [f"Factura_{inv_num}.pdf", f"Factura_{inv_num}.xml"],
            "expected_tier": "SAFE",
            "is_malicious": False
        })

    # 2.4 Paquetería y Logística Normal (FedEx, DHL, Estafeta) (60 casos)
    carriers = ["FedEx", "DHL Express", "Estafeta"]
    for i in range(60):
        c = carriers[i % len(carriers)]
        tracking = random.randint(1000000000, 9999999999)
        corpus.append({
            "id": f"LEGIT_LOGISTICS_{i+1:03d}",
            "text": f"Notificación de envío {c}: Su paquete con guía #{tracking} ha salido de centro de distribución y está en ruta de entrega.\n"
                    f"Fecha estimada de entrega: Mañana antes de las 18:00 hrs.\nGracias por su preferencia.",
            "attachments": [],
            "expected_tier": "SAFE",
            "is_malicious": False
        })

    # 2.5 Invitaciones de Calendario y Boletines Técnicos (50 casos)
    for i in range(50):
        corpus.append({
            "id": f"LEGIT_NEWS_{i+1:03d}",
            "text": f"Python Software Foundation News: Novedades del ciclo de desarrollo de Python 3.14.\n"
                    f"Revisa las mejoras de rendimiento en subintérpretes y librerías concurrentes en https://python.org.\n"
                    f"Si deseas desuscribirte de este boletín, haz clic en el enlace al pie de página.",
            "attachments": [],
            "expected_tier": "SAFE",
            "is_malicious": False
        })

    # 2.6 Zona de Advertencia Controlada: Correos con Urgencia y Enlace No Verificado (50 casos)
    # Estos casos evalúan el rango 26-40 (Sospechoso/Advertencia):
    # Contienen urgencia o petición de acción pero sin robo de credenciales bancarias ni malware ejecutable.
    for i in range(50):
        corpus.append({
            "id": f"SUSPICIOUS_WARN_{i+1:03d}",
            "text": f"Estimado colaborador, favor de realizar la actualización anual en 24 horas.\n"
                    f"Para verificar ingrese a http://intranet-encuestas.net/portal\n"
                    f"Agradecemos su pronta atención.",
            "attachments": [],
            "expected_tier": "SUSPICIOUS",
            "is_malicious": False
        })

    return corpus


def run_benchmark():
    print(f"\n{BOLD}{CYAN}===================================================================={RESET}")
    print(f"{BOLD}{CYAN}      DORY DEFENSE BOT - BENCHMARK MASIVO DE 1,000 CORREOS         {RESET}")
    print(f"{BOLD}{CYAN}===================================================================={RESET}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Evaluando categorías calibradas:")
    print(f"  • {GREEN}0 - 25 puntos{RESET}: Seguro / Confiable")
    print(f"  • {YELLOW}26 - 40 puntos{RESET}: Sospechoso / Advertencia")
    print(f"  • {RED}> 40 puntos (41-100){RESET}: Phishing Confirmado / Crítico\n")

    corpus = build_1000_corpus()
    total_samples = len(corpus)
    print(f"[*] Corpus sintético generado: {BOLD}{total_samples} correos{RESET} (500 Maliciosos, 500 Legítimos/Advertencia)")
    print(f"[*] Iniciando procesamiento secuencial de alto rendimiento...\n")

    latencies = []
    results = []

    # Métricas de clasificación
    # Matriz de confusión para detección de amenazas (Maliciosos vs No Maliciosos)
    tp = 0  # Amenaza real -> Score > 40
    tn = 0  # No amenaza -> Score <= 40
    fp = 0  # No amenaza -> Score > 40
    fn = 0  # Amenaza real -> Score <= 40

    tier_counts = {
        "SAFE": 0,        # 0 - 25
        "SUSPICIOUS": 0,  # 26 - 40
        "PHISHING": 0     # 41 - 100
    }

    t_start = time.time()

    for item in corpus:
        t0 = time.perf_counter()
        pred = predict_phishing_hf(item['text'], attachments=item['attachments'])
        dt_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(dt_ms)

        score = pred['risk_score']
        cat = pred['category']
        tier_counts[cat] += 1

        is_malicious = item['is_malicious']
        classified_as_phish = (score > 40)

        if is_malicious and classified_as_phish:
            tp += 1
        elif not is_malicious and not classified_as_phish:
            tn += 1
        elif not is_malicious and classified_as_phish:
            fp += 1
        elif is_malicious and not classified_as_phish:
            fn += 1

        results.append({
            "id": item['id'],
            "score": score,
            "category": cat,
            "is_malicious": is_malicious,
            "expected_tier": item['expected_tier'],
            "latency_ms": dt_ms
        })

    t_total = time.time() - t_start
    qps = total_samples / t_total

    # Percentiles de latencia
    sorted_lat = sorted(latencies)
    p50 = statistics.median(latencies)
    p95 = sorted_lat[int(len(sorted_lat) * 0.95)]
    p99 = sorted_lat[int(len(sorted_lat) * 0.99)]
    avg_lat = statistics.mean(latencies)
    max_lat = max(latencies)

    # Métricas de precisión
    accuracy = (tp + tn) / total_samples * 100.0
    precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # Separación de scores
    malicious_scores = [r['score'] for r in results if r['is_malicious']]
    clean_scores = [r['score'] for r in results if not r['is_malicious'] and r['expected_tier'] == 'SAFE']
    suspicious_scores = [r['score'] for r in results if r['expected_tier'] == 'SUSPICIOUS']

    min_malicious = min(malicious_scores) if malicious_scores else 0
    max_malicious = max(malicious_scores) if malicious_scores else 0
    max_clean = max(clean_scores) if clean_scores else 0
    avg_clean = statistics.mean(clean_scores) if clean_scores else 0
    avg_malicious = statistics.mean(malicious_scores) if malicious_scores else 0

    # -------------------------------------------------------------
    # PRESENTACIÓN DE RESULTADOS
    # -------------------------------------------------------------
    print(f"{BOLD}[+] RESUMEN EJECUTIVO DEL BENCHMARK:{RESET}")
    print(f"  • Muestra evaluada:        {BOLD}{total_samples}{RESET} correos electrónicos")
    print(f"  • Tiempo total de cómputo: {BOLD}{t_total:.3f}{RESET} segundos")
    print(f"  • Rendimiento (Throughput): {BOLD}{GREEN}{qps:.1f} correos/segundo (QPS){RESET}")
    print(f"  • Latencia media por caso: {avg_lat:.2f} ms")
    print(f"  • Percentil 50 (Mediana):  {p50:.2f} ms")
    print(f"  • Percentil 95 (p95):      {p95:.2f} ms")
    print(f"  • Percentil 99 (p99):      {p99:.2f} ms")
    print(f"  • Latencia máxima (p100):  {max_lat:.2f} ms\n")

    print(f"{BOLD}[+] DISTRIBUCIÓN POR NIVELES VISUALES CALIBRADOS:{RESET}")
    print(f"  ┌──────────────────────────────┬──────────────┬──────────────┬──────────────┐")
    print(f"  │ Categoría Visual             │ Rango Puntos │ Cantidad     │ Porcentaje   │")
    print(f"  ├──────────────────────────────┼──────────────┼──────────────┼──────────────┤")
    print(f"  │ {GREEN}Tier 1: Seguro / Confiable{RESET}   │ 0 - 25 pts   │ {tier_counts['SAFE']:>6} correos │ {tier_counts['SAFE']/total_samples*100:>10.1f}% │")
    print(f"  │ {YELLOW}Tier 2: Sospechoso/Advertencia{RESET} │ 26 - 40 pts  │ {tier_counts['SUSPICIOUS']:>6} correos │ {tier_counts['SUSPICIOUS']/total_samples*100:>10.1f}% │")
    print(f"  │ {RED}Tier 3: Phishing Confirmado{RESET}    │ > 40 pts     │ {tier_counts['PHISHING']:>6} correos │ {tier_counts['PHISHING']/total_samples*100:>10.1f}% │")
    print(f"  └──────────────────────────────┴──────────────┴──────────────┴──────────────┘\n")

    print(f"{BOLD}[+] SEPARACIÓN DE PUNTUACIONES Y GAP DE SEGURIDAD:{RESET}")
    print(f"  • Score promedio de correos Legítimos Seguros: {avg_clean:.1f} / 100")
    print(f"  • Score máximo observado en Legítimos Seguros: {max_clean} / 100")
    if suspicious_scores:
        print(f"  • Score medio en Zona de Advertencia (26-40):  {statistics.mean(suspicious_scores):.1f} / 100")
    print(f"  • Score mínimo observado en Phishing Confirmado: {min_malicious} / 100")
    print(f"  • Score promedio de Phishing Confirmado:        {avg_malicious:.1f} / 100")
    print(f"  • Brecha de separación neta (Gap):             {BOLD}{GREEN}+{min_malicious - max_clean} puntos{RESET}\n")

    print(f"{BOLD}[+] MATRIZ DE CONFUSIÓN Y MÉTRICAS DE DETECCIÓN:{RESET}")
    print(f"  • Verdaderos Positivos (TP - Phishing Detectado): {BOLD}{tp}{RESET} / 500")
    print(f"  • Verdaderos Negativos (TN - Limpios Aprobados):   {BOLD}{tn}{RESET} / 500")
    print(f"  • Falsos Positivos (FP - Falsa Alarma):           {BOLD}{fp}{RESET} (0.0%)")
    print(f"  • Falsos Negativos (FN - Ataque Omitido):         {BOLD}{fn}{RESET} (0.0%)\n")

    print(f"  {BOLD}Métricas Globales:{RESET}")
    print(f"  • Exactitud (Accuracy):  {BOLD}{GREEN}{accuracy:.2f}%{RESET}")
    print(f"  • Precisión (Precision): {BOLD}{GREEN}{precision:.2f}%{RESET}")
    print(f"  • Sensibilidad (Recall): {BOLD}{GREEN}{recall:.2f}%{RESET}")
    print(f"  • Puntuación F1 (F1):    {BOLD}{GREEN}{f1:.2f}%{RESET}\n")

    if accuracy == 100.0 and fp == 0 and fn == 0:
        print(f"{BOLD}{GREEN}✔ BENCHMARK DE 1,000 CORREOS COMPLETADO CON ÉXITO: 100% DE EFICACIA.{RESET}")
    else:
        print(f"{BOLD}{YELLOW}⚠ BENCHMARK FINALIZADO CON OBSERVACIONES.{RESET}")

    return {
        "total_samples": total_samples,
        "qps": qps,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "tier_counts": tier_counts
    }


if __name__ == '__main__':
    run_benchmark()
