#!/usr/bin/env python3
"""
stress_threshold_test.py - Prueba Intensiva de Estrés y Calibración de Umbral (Dory.lat)

Evalúa 30 casos de frontera (edge cases), spear phishing, evasiones adversarias,
fraude del CEO (BEC), y correos legítimos de alta urgencia/financieros para mapear
la frontera de decisión real y el margen de seguridad del motor heurístico.
"""

import os
import sys
import time

# UTF-8 encoding for Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

from app_hf import predict_phishing_hf

# Terminal Formatting
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# 30 Casos de Prueba Rigurosos
STRESS_CORPUS = [
    # =========================================================================
    # GRUPO 1: Phishing Crítico y Suplantación de Autoridad (Esperado: PHISHING)
    # =========================================================================
    {
        "id": "PHISH_01_SAT_BUZON",
        "category": "Phishing Fiscal",
        "expected": True,
        "text": "URGENTE: Notificación de irregularidades en su Buzón Tributario. Cuenta con 24 horas para solventar el requerimiento y evitar la revocación de Sellos Digitales y multas acumulativas: https://sat-consultas.online/buzon-tributario/login",
        "attachments": ["Requerimiento_SAT.pdf"]
    },
    {
        "id": "PHISH_02_SANTANDER_CARGO",
        "category": "Phishing Bancario",
        "expected": True,
        "text": "ALERTA SANTANDER: Se ha detectado un cargo no reconocido en su tarjeta por $8,450 MXN. Para cancelar la transacción y desbloquear su cuenta ingrese inmediatamente: https://santander-seguridad.net/desbloqueo?token=98213",
        "attachments": []
    },
    {
        "id": "PHISH_03_BBVA_TOKEN",
        "category": "Phishing Bancario",
        "expected": True,
        "text": "Estimado cliente BBVA: Su token móvil ha sido suspendido por inactividad. Evite la suspensión de su cuenta bancaria completando la validación en 2 horas: http://bbva-token.xyz/login",
        "attachments": []
    },
    {
        "id": "PHISH_04_BANORTE_TRANSFERENCIA",
        "category": "Phishing Bancario",
        "expected": True,
        "text": "Banorte Notifica: Transferencia SPEI retenida por $24,500.00 pesos. Para liberar el saldo a favor, ingrese sus claves de acceso y token en: https://banorte-validacion.live/portal",
        "attachments": []
    },
    {
        "id": "PHISH_05_MERCADOPAGO_SUSPENSION",
        "category": "FinTech / E-Commerce",
        "expected": True,
        "text": "Mercado Pago: Detectamos un acceso sospechoso desde un dispositivo no reconocido. Por su seguridad, sus fondos están retenidos. Ingrese a https://mercadopago-alertas.online/seguridad para confirmar su identidad.",
        "attachments": []
    },
    {
        "id": "PHISH_06_PREMIO_SORTEO",
        "category": "Señuelo de Ganancia",
        "expected": True,
        "text": "🎉 ¡Felicidades! Has ganado un iPhone 15 Pro Max en el sorteo anual de usuarios. Reclama tu premio antes de que expire en 24 horas: http://sorteo-apple.club/reclamar",
        "attachments": []
    },
    {
        "id": "PHISH_07_OFFICE365_PASSWORD",
        "category": "Credenciales Corporativas",
        "expected": True,
        "text": "Aviso de Seguridad TI: Su contraseña de Microsoft Office 365 expira hoy. Haga clic aquí para mantener su contraseña actual y evitar la interrupción de su correo: https://office365-login-verify.site/auth",
        "attachments": []
    },
    {
        "id": "PHISH_08_IP_URL_EXPLICITA",
        "category": "Ataque por IP Directa",
        "expected": True,
        "text": "Acceso requerido al portal de nómina y recibos fiscales. Ingrese de inmediato a su cuenta: http://194.26.29.112/portal/login para actualizar su contraseña.",
        "attachments": []
    },
    {
        "id": "PHISH_09_MALWARE_DOBLE_EXT",
        "category": "Adjunto Peligroso",
        "expected": True,
        "text": "Estimado cliente, adjunto comprobante de transferencia y factura para validación urgente.",
        "attachments": ["Comprobante_Transferencia_SPEI.pdf.exe"]
    },
    {
        "id": "PHISH_10_MACRO_MALICIOSO",
        "category": "Adjunto Peligroso",
        "expected": True,
        "text": "Les compartimos la plantilla de costos y cálculo de nómina. Habilitar macros para visualizar el contenido.",
        "attachments": ["Calculo_Nomina_2026.xlsm"]
    },

    # =========================================================================
    # GRUPO 2: Spear Phishing Sutil y Evasión Adversaria (Esperado: PHISHING)
    # =========================================================================
    {
        "id": "PHISH_11_ACORTADOR_URL",
        "category": "Evasión por Acortador",
        "expected": True,
        "text": "Estimado usuario: Su buzón corporativo está lleno al 98%. Evite la suspensión de recepción de correos confirmando su espacio aquí: https://bit.ly/3xStorageTI",
        "attachments": []
    },
    {
        "id": "PHISH_12_CLOUD_PAGES_HOSTING",
        "category": "Alojamiento en Cloud",
        "expected": True,
        "text": "Actualización obligatoria del portal del SAT: Verifique sus sellos digitales antes de 24 horas para evitar multas. Acceso: https://sat-verificacion.pages.dev/login",
        "attachments": []
    },
    {
        "id": "PHISH_13_SUBDOMINIO_ENGANOSO",
        "category": "Subdominio Tramposo",
        "expected": True,
        "text": "Comprobante fiscal CFDI emitido a su RFC. Para descargar y validar sus claves de acceso ingrese a: https://portal-sat.gob.mx.seguridad-tributaria.online/descargas",
        "attachments": []
    },
    {
        "id": "PHISH_14_DOMINIO_GUIONES_MULTI",
        "category": "Lookalike con Guiones",
        "expected": True,
        "text": "Notificación urgente Citibanamex: Transacción rechazada. Reclame o autorice la compra antes de 2 horas en: https://citibanamex-banca-segura-cliente.com/acceso",
        "attachments": []
    },
    {
        "id": "PHISH_15_ADJUNTO_HTML_SENUELO",
        "category": "Phishing por Archivo HTML",
        "expected": True,
        "text": "Adjuntamos estado de cuenta mensual encriptado. Abra el documento para visualizar su saldo y confirmar su contraseña.",
        "attachments": ["Estado_De_Cuenta_Banamex.html"]
    },

    # =========================================================================
    # GRUPO 3: Casos Grises / Frontera / Urgencia Interna (Esperado: LEGÍTIMO)
    # =========================================================================
    {
        "id": "LEGIT_16_RECORDATORIO_RRHH_URGENTE",
        "category": "Frontera: Urgencia RRHH",
        "expected": False,
        "text": "Estimado equipo: Les recordamos que hoy es el último día para entregar su Constancia de Situación Fiscal actualizada a Recursos Humanos. Por favor envíen su PDF a este mismo correo antes de las 18:00 hrs. Saludos.",
        "attachments": []
    },
    {
        "id": "LEGIT_17_AVISO_PAGO_PROVEEDORES",
        "category": "Frontera: Finanzas Internas",
        "expected": False,
        "text": "Hola Contabilidad, favor de programar la transferencia de la factura F-4902 de materias primas para el día de mañana. El saldo pendiente es de $15,200 MXN acordado con el proveedor.",
        "attachments": []
    },
    {
        "id": "LEGIT_18_SOPORTE_TI_MANTENIMIENTO",
        "category": "Frontera: Mantenimiento TI",
        "expected": False,
        "text": "Aviso a todos los usuarios: Este viernes realizaremos un mantenimiento en los enlaces de red de 20:00 a 22:00 hrs. Durante ese lapso el acceso a internet podría presentar intermitencias. No es necesario realizar ninguna acción.",
        "attachments": []
    },
    {
        "id": "LEGIT_19_COTIZACION_CON_ENLACE",
        "category": "Frontera: Cotización Comercial",
        "expected": False,
        "text": "Buenos días Ing. Aceves, le comparto la cotización de los reactivos químicos que nos solicitó la semana pasada. Puede consultar nuestro catálogo general en https://quimicaboss.com.mx/productos. Quedamos a sus órdenes.",
        "attachments": ["Cotizacion_Reactivos.pdf"]
    },
    {
        "id": "LEGIT_20_NOTIFICACION_CALENDAR",
        "category": "Frontera: Invitación Calendario",
        "expected": False,
        "text": "Invitación de Google Calendar: Sesión de planeación Q4 @ Jueves 25 de Sep 2026 11:00 - 12:00 (CDMX). Organizado por direccion@quimicaboss.com.mx.",
        "attachments": []
    },

    # =========================================================================
    # GRUPO 4: Correos Legítimos de Servicios con Dominios Oficiales (Esperado: LEGÍTIMO)
    # =========================================================================
    {
        "id": "LEGIT_21_SAT_OFICIAL_GOB",
        "category": "Servicio Oficial con Dominio Legítimo",
        "expected": False,
        "text": "Servicio de Administración Tributaria: Se le informa que se ha emitido un nuevo folio de opinión de cumplimiento. Ingrese a consultar su constancia en el portal oficial https://sat.gob.mx con su e.firma.",
        "attachments": []
    },
    {
        "id": "LEGIT_22_SANTANDER_OFICIAL",
        "category": "Servicio Oficial con Dominio Legítimo",
        "expected": False,
        "text": "Santander México: Su estado de cuenta digital correspondiente al mes de agosto ya se encuentra disponible para consulta en https://santander.com.mx. Gracias por ser nuestro cliente.",
        "attachments": []
    },
    {
        "id": "LEGIT_23_BBVA_OFICIAL",
        "category": "Servicio Oficial con Dominio Legítimo",
        "expected": False,
        "text": "BBVA México le informa que su pago de servicios por $1,250.00 fue aplicado exitosamente. Puede consultar sus movimientos en https://bbva.mx o en su app móvil.",
        "attachments": []
    },
    {
        "id": "LEGIT_24_AMAZON_OFICIAL_PEDIDO",
        "category": "Servicio Oficial con Dominio Legítimo",
        "expected": False,
        "text": "Amazon.com.mx: Tu pedido #702-839102-192 ha sido enviado y llegará mañana. Puedes rastrear tu paquete ingresando a https://amazon.com.mx/gp/your-orders.",
        "attachments": []
    },
    {
        "id": "LEGIT_25_DHL_OFICIAL_RASTREO",
        "category": "Servicio Oficial con Dominio Legítimo",
        "expected": False,
        "text": "DHL Express: Su envío con guía número 4920193821 está en reparto para entrega el día de hoy antes de las 18:00 hrs. Ver detalles en https://dhl.com.mx/tracking.",
        "attachments": []
    },

    # =========================================================================
    # GRUPO 5: Correos Operativos y Cotidianos de la Empresa (Esperado: LEGÍTIMO)
    # =========================================================================
    {
        "id": "LEGIT_26_MINUTA_INTERNA",
        "category": "Operativo Interno",
        "expected": False,
        "text": "Hola equipo de desarrollo, les comparto los acuerdos tomados en la sesión de hoy sobre la integración con Merlin y las pruebas del buzón. Buen inicio de semana.",
        "attachments": ["Minuta_Reunion_Septiembre.pdf"]
    },
    {
        "id": "LEGIT_27_ORDEN_COMPRA_ODOO",
        "category": "Operativo Interno",
        "expected": False,
        "text": "Estimado proveedor, adjunto orden de compra OC-2026-104 generada desde el sistema Odoo para el suministro regular de solventes. Favor de confirmar fecha estimada de entrega.",
        "attachments": ["OC_2026_104.pdf"]
    },
    {
        "id": "LEGIT_28_SOLICITUD_VACACIONES",
        "category": "Operativo Interno",
        "expected": False,
        "text": "Buenos días Carlos, te comparto el formato de solicitud de vacaciones para su firma y autorización cuando tengas un momento disponible.",
        "attachments": ["Formato_Vacaciones_2026.pdf"]
    },
    {
        "id": "LEGIT_29_NEWSLETTER_TECNOLOGICA",
        "category": "Contenido Técnico Externo",
        "expected": False,
        "text": "Python Software Foundation: Descubre las mejores prácticas de concurrencia y seguridad en Python 3.14 y las nuevas especificaciones de red en https://python.org.",
        "attachments": []
    },
    {
        "id": "LEGIT_30_FELICITACION_CUMPLEANOS",
        "category": "Comunicación Humana Informal",
        "expected": False,
        "text": "¡Feliz cumpleaños Carlos! De parte de todo el equipo de Química Boss te deseamos un excelente día en compañía de tu familia y que sigan los éxitos profesionales.",
        "attachments": []
    }
]


def run_threshold_stress_test():
    print(f"\n{BOLD}{CYAN}========================================================================================{RESET}")
    print(f"{BOLD}{CYAN}      DORY DEFENSE BOT - PRUEBA DE ESTRÉS RIGUROSA Y UMBRAL DE DETECCIÓN                {RESET}")
    print(f"{BOLD}{CYAN}      Evaluación de 30 Casos de Frontera, Spear Phishing y Operaciones Reales           {RESET}")
    print(f"{BOLD}{CYAN}========================================================================================{RESET}\n")

    results = []
    t_start_all = time.time()

    phishing_scores = []
    legitimate_scores = []

    print(f"{BOLD}{'ID CASO':<32} {'CATEGORÍA':<22} {'EXP':<5} {'PRED':<9} {'SCORE':<7} {'CONF':<6} {'ESTADO'}{RESET}")
    print("-" * 92)

    for case in STRESS_CORPUS:
        t0 = time.time()
        pred = predict_phishing_hf(case['text'], attachments=case.get('attachments'))
        elapsed_ms = (time.time() - t0) * 1000

        is_phishing = pred['is_phishing']
        score = pred['risk_score']
        conf = pred['confidence']
        expected = case['expected']

        is_match = (is_phishing == expected)
        status_tag = f"{GREEN}CORRECTO{RESET}" if is_match else f"{RED}ERROR{RESET}"

        if expected:
            phishing_scores.append(score)
        else:
            legitimate_scores.append(score)

        pred_str = "PHISHING" if is_phishing else "LEGÍTIMO"
        exp_str = "PHISH" if expected else "LEGIT"

        # Color score based on threat level
        if score >= 75:
            score_color = RED
        elif score >= 35:
            score_color = YELLOW
        else:
            score_color = GREEN

        print(f"{case['id']:<32} {case['category']:<22} {exp_str:<5} {pred_str:<9} {score_color}{score:>3}/100{RESET}  {conf:.2f}  [{status_tag}]")

        results.append({
            'case': case,
            'prediction': pred,
            'is_match': is_match,
            'elapsed_ms': elapsed_ms
        })

    total_time_ms = (time.time() - t_start_all) * 1000

    # =========================================================================
    # MÉTRICAS DE CLASIFICACIÓN
    # =========================================================================
    tp = sum(1 for r in results if r['case']['expected'] and r['prediction']['is_phishing'])
    tn = sum(1 for r in results if not r['case']['expected'] and not r['prediction']['is_phishing'])
    fp = sum(1 for r in results if not r['case']['expected'] and r['prediction']['is_phishing'])
    fn = sum(1 for r in results if r['case']['expected'] and not r['prediction']['is_phishing'])

    total_cases = len(results)
    accuracy = ((tp + tn) / total_cases) * 100
    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    specificity = (tn / (tn + fp)) * 100 if (tn + fp) > 0 else 0

    print("\n" + "=" * 92)
    print(f"{BOLD}{CYAN}📊 MATRIZ DE CONFUSIÓN Y RENDIMIENTO DE DETECCIÓN:{RESET}")
    print("=" * 92)
    print(f"  • Casos Totales Evaluados: {BOLD}{total_cases}{RESET} (15 Phishing / 15 Legítimos)")
    print(f"  • Verdaderos Positivos (TP): {GREEN}{tp}{RESET}  |  Verdaderos Negativos (TN): {GREEN}{tn}{RESET}")
    print(f"  • Falsos Positivos (FP):     {RED}{fp}{RESET}  |  Falsos Negativos (FN):     {RED}{fn}{RESET}")
    print("-" * 92)
    print(f"  • {BOLD}Exactitud (Accuracy):{RESET}   {GREEN if accuracy == 100 else YELLOW}{accuracy:.2f}%{RESET}")
    print(f"  • {BOLD}Precisión (Precision):{RESET}  {GREEN if precision == 100 else YELLOW}{precision:.2f}%{RESET} (Capacidad de evitar falsas alarmas)")
    print(f"  • {BOLD}Sensibilidad (Recall):{RESET}  {GREEN if recall == 100 else YELLOW}{recall:.2f}%{RESET} (Capacidad de interceptar todo el phishing)")
    print(f"  • {BOLD}Especificidad:{RESET}          {GREEN if specificity == 100 else YELLOW}{specificity:.2f}%{RESET} (Reconocimiento impecable de correos legítimos)")
    print(f"  • {BOLD}Puntaje F1 (Balance):{RESET}   {GREEN if f1 == 100 else YELLOW}{f1:.2f}%{RESET}")

    # =========================================================================
    # ANÁLISIS DE UMBRAL Y FRONTERA DE DECISIÓN
    # =========================================================================
    min_phish = min(phishing_scores) if phishing_scores else 0
    max_phish = max(phishing_scores) if phishing_scores else 0
    avg_phish = sum(phishing_scores) / len(phishing_scores) if phishing_scores else 0

    min_legit = min(legitimate_scores) if legitimate_scores else 0
    max_legit = max(legitimate_scores) if legitimate_scores else 0
    avg_legit = sum(legitimate_scores) / len(legitimate_scores) if legitimate_scores else 0

    separation_margin = min_phish - max_legit

    print("\n" + "=" * 92)
    print(f"{BOLD}{CYAN}🎯 ANÁLISIS DE LA FRONTERA DE DECISIÓN Y MARGEN DE SEGURIDAD:{RESET}")
    print("=" * 92)
    print(f"  • {BOLD}Umbral Actual de Clasificación:{RESET} Score >= {YELLOW}35{RESET} puntos.")
    print(f"  • {BOLD}Rango de Correos Phishing:{RESET}        {min_phish} a {max_phish} puntos (Promedio: {avg_phish:.1f})")
    print(f"  • {BOLD}Rango de Correos Legítimos:{RESET}       {min_legit} a {max_legit} puntos (Promedio: {avg_legit:.1f})")
    print(f"  • {BOLD}Puntaje Phishing Más Bajo Detectado:{RESET}  {BOLD}{YELLOW}{min_phish}/100{RESET}")
    print(f"  • {BOLD}Puntaje Legítimo Más Alto Registrado:{RESET} {BOLD}{GREEN}{max_legit}/100{RESET}")
    print(f"  • {BOLD}Margen de Separación Limpia:{RESET}         {BOLD}{CYAN}{separation_margin} puntos de brecha de seguridad{RESET}")

    # =========================================================================
    # HISTOGRAMA VISUAL DE DISTRIBUCIÓN
    # =========================================================================
    print("\n" + "-" * 92)
    print(f"{BOLD}📈 HISTOGRAMA DE DISTRIBUCIÓN DE PUNTAJES (0 a 100):{RESET}")
    print("-" * 92)

    buckets = [(0, 10), (11, 20), (21, 30), (31, 40), (41, 50), (51, 60), (61, 70), (71, 80), (81, 90), (91, 100)]
    for low, high in buckets:
        l_count = sum(1 for s in legitimate_scores if low <= s <= high)
        p_count = sum(1 for s in phishing_scores if low <= s <= high)
        
        l_bar = f"{GREEN}{'█' * (l_count * 2)}{RESET}" if l_count > 0 else ""
        p_bar = f"{RED}{'█' * (p_count * 2)}{RESET}" if p_count > 0 else ""
        
        threshold_marker = f" {YELLOW}◄── UMBRAL (35 pts){RESET}" if low <= 35 <= high else ""
        print(f"  [{low:>3} - {high:>3} pts] | {l_bar}{p_bar:<30} (Legítimos: {l_count}, Phishing: {p_count}){threshold_marker}")

    print("-" * 92)
    print(f"  Tiempo total de procesamiento de los 30 casos: {total_time_ms:.2f} ms ({total_time_ms / total_cases:.2f} ms/caso)\n")

    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'min_phish': min_phish,
        'max_legit': max_legit,
        'separation_margin': separation_margin
    }


if __name__ == '__main__':
    run_threshold_stress_test()
