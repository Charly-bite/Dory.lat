#!/usr/bin/env python3
"""
eml_dataset_processor.py - Procesador y Entrenador de Lotes .EML para Química Boss

Escanea la carpeta dataset/raw_eml/ e ingesta automáticamente todos los archivos .eml
depositados por el equipo de seguridad o los empleados.
Extrae cabeceras MIME, adjuntos, HTML, y ejecuta la suite completa de Dory, registrando
los casos en la base de datos feedback.db (tabla company_phishing_corpus).
"""

import sys
import os
import glob
import email
from email import policy
import sqlite3
import time
import json
import logging
from typing import Dict, Any, List

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] [EMLProcessor] %(message)s")
logger = logging.getLogger("EMLProcessor")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(APP_DIR, 'dataset', 'raw_eml')
DATABASE_PATH = os.path.join(APP_DIR, 'feedback.db')


def init_corpus_table():
    """Crea la tabla company_phishing_corpus en feedback.db."""
    conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
    cursor = conn.cursor()
    cursor.execute('PRAGMA journal_mode=WAL;')
    cursor.execute('PRAGMA synchronous=NORMAL;')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS company_phishing_corpus (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_name TEXT UNIQUE NOT NULL,
        file_hash TEXT,
        subject TEXT,
        sender TEXT,
        recipient TEXT,
        date TEXT,
        spf_status TEXT,
        attachments_found TEXT,
        urls_found TEXT,
        risk_score INTEGER,
        verdict TEXT,
        threats_breakdown TEXT,
        l2_status TEXT,
        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_corpus_file ON company_phishing_corpus(file_name);')
    conn.commit()
    conn.close()


def parse_and_evaluate_eml(eml_path: str) -> Dict[str, Any]:
    """Lee y evalúa un archivo .eml con el motor Dory."""
    import hashlib
    from app_hf import predict_phishing_hf
    from mail_service import EmailMIMEParser

    with open(eml_path, 'rb') as f:
        raw_bytes = f.read()

    file_hash = hashlib.sha256(raw_bytes).hexdigest()
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    
    # Extraer campos MIME usando el parser calibrado
    parsed = EmailMIMEParser.parse_message_object(msg)
    
    # Evaluar con Dory
    result = predict_phishing_hf(
        text=parsed['body_text'],
        attachments=parsed['attachments'],
        raw_html=parsed['body_html'],
        email_info=parsed
    )

    return {
        'file_name': os.path.basename(eml_path),
        'file_hash': file_hash,
        'subject': parsed.get('subject', ''),
        'sender': parsed.get('sender_email', ''),
        'recipient': parsed.get('recipient_email') or str(msg.get('To', '')),
        'date': parsed.get('date', ''),
        'spf_status': parsed.get('received_spf', ''),
        'attachments': parsed.get('attachments', []),
        'urls': parsed.get('urls', []),
        'risk_score': result['risk_score'],
        'verdict': result['category'],
        'threats': result['threats'],
        'l2_analysis': result.get('l2_analysis')
    }


def process_dataset(directory: str = DATASET_DIR) -> List[Dict[str, Any]]:
    """Procesa en lote todos los archivos .eml del directorio especificado."""
    init_corpus_table()
    eml_files = glob.glob(os.path.join(directory, '*.eml'))
    
    if not eml_files:
        print(f"[!] No se encontraron archivos .eml en {directory}")
        print("    Deposita correos de phishing en esa carpeta para su procesamiento automático.")
        return []

    print(f"\n====================================================================")
    print(f"  DORY DEFENSE BOT - PROCESAMIENTO EN LOTE DE CORPUS .EML            ")
    print(f"====================================================================")
    print(f"Directorio: {directory}")
    print(f"Total de correos a analizar: {len(eml_files)}\n")

    conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
    cursor = conn.cursor()
    
    results = []
    phishing_count = 0
    safe_count = 0
    warning_count = 0

    for i, path in enumerate(eml_files, 1):
        t0 = time.perf_counter()
        try:
            res = parse_and_evaluate_eml(path)
            lat_ms = (time.perf_counter() - t0) * 1000
            
            # Guardar en base de datos
            l2_status = res['l2_analysis']['status'] if res.get('l2_analysis') else 'N/A'
            cursor.execute('''
            INSERT OR REPLACE INTO company_phishing_corpus (
                file_name, file_hash, subject, sender, recipient, date,
                spf_status, attachments_found, urls_found, risk_score,
                verdict, threats_breakdown, l2_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                res['file_name'],
                res['file_hash'],
                res['subject'],
                res['sender'],
                res['recipient'],
                res['date'],
                res['spf_status'],
                json.dumps(res['attachments']),
                json.dumps(res['urls']),
                res['risk_score'],
                res['verdict'],
                json.dumps(res['threats']),
                l2_status
            ))
            conn.commit()

            if res['verdict'] == 'PHISHING':
                phishing_count += 1
                badge = "[🚨 PHISHING]"
            elif res['verdict'] == 'SUSPICIOUS':
                warning_count += 1
                badge = "[⚠️ ADVERTENCIA]"
            else:
                safe_count += 1
                badge = "[🛡️ SEGURO]"

            print(f"[{i}/{len(eml_files)}] {badge} {res['file_name'][:30]:<30} | Score: {res['risk_score']:>3}/100 | {lat_ms:.2f} ms")
            if res['threats']:
                print(f"      Amenazas ({len(res['threats'])}): {', '.join(res['threats'][:3])}...")
            results.append(res)

        except Exception as e:
            print(f"[!] Error procesando {os.path.basename(path)}: {e}")

    conn.close()

    print(f"\n====================================================================")
    print(f"  RESUMEN DE INGESTA DE CORPUS (.EML)")
    print(f"====================================================================")
    print(f"Total procesados:  {len(results)}")
    print(f"Phishing detectado: {phishing_count} ({phishing_count/max(len(results),1)*100:.1f}%)")
    print(f"En Advertencia:    {warning_count} ({warning_count/max(len(results),1)*100:.1f}%)")
    print(f"Seguros / Limpios: {safe_count} ({safe_count/max(len(results),1)*100:.1f}%)")
    print(f"Todos los registros quedaron archivados en: feedback.db (tabla company_phishing_corpus).")
    print(f"====================================================================\n")

    return results


if __name__ == '__main__':
    process_dataset()
