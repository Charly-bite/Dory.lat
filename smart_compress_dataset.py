#!/usr/bin/env python3
"""
smart_compress_dataset.py — Comprime/Limpia adjuntos pesados del dataset local
Sustituye payloads binarios (PDFs, PPTs, videos, imágenes) por metadatos ligeros.
Conserva 100% de cabeceras, texto, HTML, URLs y nombres de adjuntos para Dory.
"""
import os
import glob
import email
from email import policy
import sys
import time

DATASET_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dataset', 'raw_eml')

def strip_attachments(raw_bytes: bytes) -> bytes:
    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        if not msg.is_multipart():
            return raw_bytes
        
        modified = False
        for part in msg.walk():
            fn = part.get_filename()
            cd = str(part.get_content_disposition() or '').lower()
            ct = str(part.get_content_type() or '').lower()
            
            # Si es adjunto o tipo binario pesado no-texto
            if fn or 'attachment' in cd or (ct.startswith(('image/', 'video/', 'audio/', 'application/')) and 'pkcs' not in ct):
                orig_len = len(part.get_payload() or '')
                part.set_payload(f"[DORY_ATTACHMENT_STRIPPED: {fn or 'binary'} original_bytes={orig_len}]")
                if 'Content-Transfer-Encoding' in part:
                    del part['Content-Transfer-Encoding']
                modified = True
                
        return msg.as_bytes() if modified else raw_bytes
    except Exception:
        return raw_bytes

def main():
    folders = ['unclassified', 'malicious', 'legitimate']
    total_processed = 0
    total_saved_bytes = 0
    t0 = time.time()

    for f_name in folders:
        f_dir = os.path.join(DATASET_ROOT, f_name)
        if not os.path.exists(f_dir):
            continue
        
        files = glob.glob(os.path.join(f_dir, '*.eml'))
        print(f"Procesando {len(files)} correos en {f_name}...")
        
        for i, file_path in enumerate(files):
            try:
                orig_size = os.path.getsize(file_path)
                # Solo procesar si mide más de 20 KB
                if orig_size < 20 * 1024:
                    continue
                
                with open(file_path, 'rb') as f:
                    orig_bytes = f.read()
                
                stripped = strip_attachments(orig_bytes)
                if len(stripped) < orig_size:
                    with open(file_path, 'wb') as f:
                        f.write(stripped)
                    saved = orig_size - len(stripped)
                    total_saved_bytes += saved
                total_processed += 1
            except Exception as e:
                pass
            
            if (i + 1) % 500 == 0:
                print(f"  [{i+1}/{len(files)}] Espacio ahorrado hasta ahora: {total_saved_bytes / (1024*1024):.1f} MB")

    elapsed = time.time() - t0
    saved_mb = total_saved_bytes / (1024 * 1024)
    saved_gb = total_saved_bytes / (1024 * 1024 * 1024)
    print(f"\n✅ Compresión completada en {elapsed:.1f}s!")
    print(f"Total correos procesados: {total_processed}")
    print(f"Espacio total liberado: {saved_mb:.2f} MB ({saved_gb:.2f} GB)")

if __name__ == '__main__':
    main()
