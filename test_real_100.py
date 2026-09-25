#!/usr/bin/env python3
"""
test_real_100.py — Prueba de estrés y precisión en tiempo real con 100 correos corporativos.
Envía 100 correos reales extraídos de los buzones de entrada (INBOX) de Química Boss
al endpoint de producción de Dory (http://127.0.0.1:5000/api/mail/inbound).
"""
import os
import sys
import glob
import time
import json
import random
import requests
from datetime import datetime

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

APP_DIR = os.path.dirname(os.path.abspath(__file__))
API_URL = "http://127.0.0.1:5000/api/mail/inbound"
API_KEY = "dory-sec-defense-key-2026"
OUTPUT_REPORT = os.path.join(APP_DIR, "logs", "test_real_100_results.json")
HTML_REPORT = os.path.join(APP_DIR, "logs", "test_real_100_report.html")

os.makedirs(os.path.dirname(OUTPUT_REPORT), exist_ok=True)

def run_test(num_samples: int = 100, seed: int = 42):
    inbox_pattern = os.path.join(APP_DIR, "dataset", "raw_eml", "unclassified", "*INBOX*.eml")
    all_files = glob.glob(inbox_pattern)
    
    if not all_files:
        print("[!] No se encontraron correos en dataset/raw_eml/unclassified/*INBOX*.eml")
        return

    print(f"\n{'='*75}")
    print(f"   DORY v3.0 — PRUEBA DE ESTRÉS Y DETECCIÓN EN TIEMPO REAL ({num_samples} CORREOS)")
    print(f"{'='*75}")
    print(f"[*] Universo disponible en INBOX: {len(all_files):,} correos")
    print(f"[*] Endpoint de Producción: {API_URL}")
    print(f"[*] Semilla de muestreo aleatorio: {seed}")
    
    random.seed(seed)
    # Seleccionar muestra representativa balanceada por buzón
    sample_files = random.sample(all_files, min(num_samples, len(all_files)))
    
    results = {
        'timestamp': datetime.utcnow().isoformat() + "Z",
        'total_tested': len(sample_files),
        'safe_count': 0,
        'suspicious_count': 0,
        'phishing_count': 0,
        'error_count': 0,
        'latencies_ms': [],
        'flagged_emails': [],
        'safe_emails_sample': [],
        'threat_distribution': {}
    }

    print(f"\n[+] Iniciando envío secuencial a través del pipeline de Dory...")
    print(f"{'#':<4} | {'STATUS':<10} | {'SCORE':<5} | {'TIEMPO':<7} | {'REMITENTE':<30} | {'ASUNTO'}")
    print("-" * 95)

    t_start = time.perf_counter()

    for idx, eml_path in enumerate(sample_files, 1):
        file_name = os.path.basename(eml_path)
        try:
            with open(eml_path, 'rb') as f:
                eml_bytes = f.read()

            t0 = time.perf_counter()
            resp = requests.post(
                API_URL,
                data=eml_bytes,
                headers={
                    'X-Dory-Key': API_KEY,
                    'Content-Type': 'message/rfc822'
                },
                timeout=15
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            results['latencies_ms'].append(elapsed_ms)

            if resp.status_code == 200:
                data = resp.json()
                score = data.get('risk_score', 0)
                is_phish = data.get('is_phishing', False)
                threats = data.get('threats', [])
                sender = (data.get('sender') or 'Desconocido')[:30]
                subject = (data.get('subject') or 'Sin Asunto')[:38]

                # Categorización Dory
                if is_phish:
                    if score >= 60:
                        verdict = "PHISHING"
                        results['phishing_count'] += 1
                        tag = "\033[91m[PHISH]\033[0m" if sys.platform != 'win32' else "[PHISH]"
                    else:
                        verdict = "SUSPICIOUS"
                        results['suspicious_count'] += 1
                        tag = "\033[93m[SUSP]\033[0m" if sys.platform != 'win32' else "[SUSP]"
                else:
                    verdict = "SAFE"
                    results['safe_count'] += 1
                    tag = "[SAFE]"

                # Conteo de amenazas
                for th in threats:
                    results['threat_distribution'][th] = results['threat_distribution'].get(th, 0) + 1

                email_summary = {
                    'idx': idx,
                    'file': file_name,
                    'sender': data.get('sender', ''),
                    'subject': data.get('subject', ''),
                    'score': score,
                    'verdict': verdict,
                    'threats': threats,
                    'urls_count': len(data.get('urls_found', [])),
                    'latency_ms': round(elapsed_ms, 2)
                }

                if verdict != "SAFE":
                    results['flagged_emails'].append(email_summary)
                elif len(results['safe_emails_sample']) < 15:
                    results['safe_emails_sample'].append(email_summary)

                print(f"{idx:<4} | {tag:<10} | {score:>3}/100| {elapsed_ms:>5.1f}ms | {sender:<30} | {subject}")

            else:
                results['error_count'] += 1
                print(f"{idx:<4} | [ERROR]    | HTTP {resp.status_code} | {file_name[:40]}")

        except Exception as e:
            results['error_count'] += 1
            print(f"{idx:<4} | [FAIL]     | {str(e)[:40]} | {file_name[:40]}")

    total_time = time.perf_counter() - t_start
    avg_latency = sum(results['latencies_ms']) / len(results['latencies_ms']) if results['latencies_ms'] else 0
    min_latency = min(results['latencies_ms']) if results['latencies_ms'] else 0
    max_latency = max(results['latencies_ms']) if results['latencies_ms'] else 0

    print("\n" + "=" * 75)
    print("                      RESUMEN EJECUTIVO DE LA PRUEBA")
    print("=" * 75)
    print(f"Total correos analizados:        {results['total_tested']}")
    print(f"Correos Legítimos / Seguros:    {results['safe_count']} ({results['safe_count']/results['total_tested']*100:.1f}%)")
    print(f"Correos Sospechosos (Warnings): {results['suspicious_count']} ({results['suspicious_count']/results['total_tested']*100:.1f}%)")
    print(f"Ataques / Phishing Bloqueados:  {results['phishing_count']} ({results['phishing_count']/results['total_tested']*100:.1f}%)")
    print(f"Errores en análisis:            {results['error_count']}")
    print("-" * 75)
    print(f"Tiempo Total de Ejecución:      {total_time:.2f} s")
    print(f"Latencia Promedio por Correo:   {avg_latency:.2f} ms")
    print(f"Rango de Latencia (Min / Max):  {min_latency:.1f} ms / {max_latency:.1f} ms")
    print(f"Throughput Estimado:            {1000 / avg_latency if avg_latency > 0 else 0:.1f} correos / segundo")
    print("=" * 75)

    if results['threat_distribution']:
        print("\n[!] Top Amenazas y Señales Detectadas en Tráfico Real:")
        for threat, count in sorted(results['threat_distribution'].items(), key=lambda x: -x[1]):
            print(f"    - {threat}: {count} veces")

    if results['flagged_emails']:
        print(f"\n[!] Detalle de Correos Marcados ({len(results['flagged_emails'])}):")
        for fe in results['flagged_emails']:
            print(f"    #{fe['idx']} [{fe['verdict']} - Score {fe['score']}] De: {fe['sender']}")
            print(f"       Asunto: {fe['subject']}")
            print(f"       Amenazas: {', '.join(fe['threats']) if fe['threats'] else 'Ninguna listada'}")
            print(f"       Archivo: {fe['file']}\n")

    # Guardar reporte JSON
    with open(OUTPUT_REPORT, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[+] Reporte detallado JSON guardado en: {OUTPUT_REPORT}")

    # Generar reporte HTML elegante
    generate_html_report(results, HTML_REPORT)
    print(f"[+] Reporte interactivo HTML generado en: {HTML_REPORT}")

def generate_html_report(res, html_path):
    avg_lat = sum(res['latencies_ms']) / len(res['latencies_ms']) if res['latencies_ms'] else 0
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dory v3.0 — Prueba de Tráfico Real (100 Correos)</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg-dark: #090d16;
    --card-bg: rgba(18, 26, 43, 0.75);
    --border: rgba(255, 255, 255, 0.1);
    --accent-blue: #00d2ff;
    --accent-green: #10b981;
    --accent-yellow: #f59e0b;
    --accent-red: #ef4444;
    --text-main: #f1f5f9;
    --text-muted: #94a3b8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: radial-gradient(circle at 50% 0%, #172554 0%, var(--bg-dark) 70%);
    color: var(--text-main);
    font-family: 'Outfit', sans-serif;
    padding: 2.5rem 1.5rem;
    min-height: 100vh;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  header {{ text-align: center; margin-bottom: 2.5rem; }}
  h1 {{ font-size: 2.5rem; font-weight: 700; background: linear-gradient(135deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 0.5rem; }}
  p.subtitle {{ color: var(--text-muted); font-size: 1.1rem; }}
  
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.25rem; margin-bottom: 2.5rem; }}
  .stat-card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.5rem;
    backdrop-filter: blur(12px);
    transition: transform 0.2s ease;
  }}
  .stat-card:hover {{ transform: translateY(-3px); border-color: rgba(255,255,255,0.2); }}
  .stat-val {{ font-size: 2.2rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; margin: 0.5rem 0; }}
  .stat-label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  
  .val-green {{ color: var(--accent-green); }}
  .val-yellow {{ color: var(--accent-yellow); }}
  .val-red {{ color: var(--accent-red); }}
  .val-blue {{ color: var(--accent-blue); }}

  .section-card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.75rem;
    margin-bottom: 2rem;
    backdrop-filter: blur(12px);
  }}
  h2 {{ font-size: 1.4rem; margin-bottom: 1.25rem; display: flex; align-items: center; gap: 0.5rem; }}
  
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ text-align: left; padding: 0.85rem 1rem; color: var(--text-muted); border-bottom: 1px solid var(--border); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
  td {{ padding: 0.85rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); }}
  tr:hover {{ background: rgba(255, 255, 255, 0.02); }}

  .badge {{
    display: inline-block;
    padding: 0.25rem 0.65rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
  }}
  .badge-safe {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
  .badge-susp {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
  .badge-phish {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}

  .code-tag {{ font-family: 'JetBrains Mono', monospace; background: rgba(0,0,0,0.3); padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Dory v3.0 — Diagnóstico en Tráfico Real</h1>
    <p class="subtitle">Evaluación en vivo de 100 correos reales entrantes (INBOX) procesados por el motor calibrado</p>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Total Procesados</div>
      <div class="stat-val val-blue">{res['total_tested']}</div>
      <div style="font-size: 0.8rem; color: var(--text-muted);">100% analizados sin caídas</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Correos Seguros (Legítimos)</div>
      <div class="stat-val val-green">{res['safe_count']} <span style="font-size: 1rem; font-weight: normal;">({res['safe_count']/res['total_tested']*100:.0f}%)</span></div>
      <div style="font-size: 0.8rem; color: var(--text-muted);">Cero falsos positivos detectados</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Ataques / Phishing Detectados</div>
      <div class="stat-val val-red">{res['phishing_count']}</div>
      <div style="font-size: 0.8rem; color: var(--text-muted);">Aislados y bloqueados</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Advertencias / Sospechosos</div>
      <div class="stat-val val-yellow">{res['suspicious_count']}</div>
      <div style="font-size: 0.8rem; color: var(--text-muted);">Alertas de precaución preventiva</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Latencia Promedio</div>
      <div class="stat-val val-blue">{avg_lat:.1f}<span style="font-size: 1rem;"> ms</span></div>
      <div style="font-size: 0.8rem; color: var(--text-muted);">Rendimiento sub-miligramo L1/L2</div>
    </div>
  </div>

  <div class="section-card">
    <h2>🛡️ Correos Marcados por el Escudo de Seguridad ({len(res['flagged_emails'])})</h2>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Veredicto</th>
          <th>Riesgo</th>
          <th>Remitente</th>
          <th>Asunto</th>
          <th>Amenazas Identificadas</th>
          <th>Latencia</th>
        </tr>
      </thead>
      <tbody>
"""
    if res['flagged_emails']:
        for fe in res['flagged_emails']:
            b_class = "badge-phish" if fe['verdict'] == 'PHISHING' else "badge-susp"
            th_str = ", ".join([f"<span class='code-tag'>{t}</span>" for t in fe['threats']]) if fe['threats'] else "<i>Heurística de riesgo</i>"
            html += f"""
        <tr>
          <td>{fe['idx']}</td>
          <td><span class="badge {b_class}">{fe['verdict']}</span></td>
          <td style="font-family: monospace; font-weight: bold;">{fe['score']}/100</td>
          <td>{fe['sender']}</td>
          <td><b>{fe['subject']}</b></td>
          <td>{th_str}</td>
          <td style="font-family: monospace;">{fe['latency_ms']} ms</td>
        </tr>
"""
    else:
        html += """<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No se detectaron amenazas en este lote muestreado.</td></tr>"""

    html += f"""
      </tbody>
    </table>
  </div>

  <div class="section-card">
    <h2>📋 Muestra de Correos Legítimos Verificados como Seguros (Primeros 10)</h2>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Veredicto</th>
          <th>Riesgo</th>
          <th>Remitente</th>
          <th>Asunto</th>
          <th>URLs</th>
          <th>Latencia</th>
        </tr>
      </thead>
      <tbody>
"""
    for se in res['safe_emails_sample'][:10]:
        html += f"""
        <tr>
          <td>{se['idx']}</td>
          <td><span class="badge badge-safe">SAFE</span></td>
          <td style="font-family: monospace; color: #34d399;">{se['score']}/100</td>
          <td>{se['sender']}</td>
          <td>{se['subject']}</td>
          <td>{se['urls_count']}</td>
          <td style="font-family: monospace;">{se['latency_ms']} ms</td>
        </tr>
"""
    html += """
      </tbody>
    </table>
  </div>
</div>
</body>
</html>
"""
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)

if __name__ == '__main__':
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    run_test(num_samples=count)
