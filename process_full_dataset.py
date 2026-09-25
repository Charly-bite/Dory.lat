#!/usr/bin/env python3
"""
process_full_dataset.py — Procesa todo el dataset con Dory y genera métricas.
Evalúa correos de malicious/ y legitimate/ y mide precision/recall/F1.
"""
import sys
import os
import json
import time
import logging
import glob

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(APP_DIR, 'dataset', 'raw_eml')
MALICIOUS_DIR = os.path.join(DATASET_DIR, 'malicious')
LEGITIMATE_DIR = os.path.join(DATASET_DIR, 'legitimate')
RESULTS_FILE = os.path.join(APP_DIR, 'dataset', 'processed', 'evaluation_results.json')
LOG_FILE = os.path.join(APP_DIR, 'logs', 'dataset_processing.log')

os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("DatasetProcessor")

# Import Dory engine
sys.path.insert(0, APP_DIR)
try:
    from eml_dataset_processor import parse_and_evaluate_eml, init_corpus_table
    logger.info("Motor Dory importado correctamente")
except ImportError as e:
    logger.critical(f"No se pudo importar el motor Dory: {e}")
    sys.exit(1)


def process_folder(folder: str, expected_label: str, results: dict):
    """Procesa todos los .eml de una carpeta."""
    eml_files = sorted(glob.glob(os.path.join(folder, '*.eml')))
    total = len(eml_files)
    logger.info(f"\n{'='*60}")
    logger.info(f"  Procesando: {expected_label.upper()} ({total} correos)")
    logger.info(f"  Carpeta: {folder}")
    logger.info(f"{'='*60}")

    processed = 0
    errors = 0

    for i, path in enumerate(eml_files, 1):
        fname = os.path.basename(path)
        try:
            t0 = time.perf_counter()
            res = parse_and_evaluate_eml(path)
            elapsed_ms = (time.perf_counter() - t0) * 1000

            verdict = res.get('verdict', 'UNKNOWN')
            score = res.get('risk_score', 0)

            # Clasificar resultado
            is_flagged = verdict in ('PHISHING', 'SUSPICIOUS')

            entry = {
                'file': fname,
                'expected': expected_label,
                'verdict': verdict,
                'score': score,
                'threats': res.get('threats', []),
                'subject': res.get('subject', '')[:80],
                'sender': res.get('sender', ''),
                'elapsed_ms': round(elapsed_ms, 1)
            }
            results['entries'].append(entry)

            # Confusion matrix
            if expected_label == 'malicious':
                if is_flagged:
                    results['tp'] += 1
                    badge = "TP"
                else:
                    results['fn'] += 1
                    badge = "FN"
            else:  # legitimate
                if is_flagged:
                    results['fp'] += 1
                    badge = "FP"
                else:
                    results['tn'] += 1
                    badge = "TN"

            # Log cada 10 o si es interesante
            if i % 10 == 0 or badge in ('FN', 'FP'):
                marker = "!!!" if badge in ('FN', 'FP') else ""
                logger.info(f"  [{i}/{total}] [{badge}]{marker} Score:{score:>3} {verdict:>10} | {fname[:40]}")

            processed += 1

        except Exception as e:
            errors += 1
            logger.warning(f"  [{i}/{total}] ERROR: {fname[:35]} -> {str(e)[:60]}")
            results['errors'].append({'file': fname, 'error': str(e)[:200]})

        # Guardar checkpoint cada 50
        if processed % 50 == 0 and processed > 0:
            save_results(results)
            logger.info(f"  Checkpoint: {processed}/{total} procesados")

    results['processed'] += processed
    results['error_count'] += errors
    logger.info(f"  Completado: {processed}/{total} (errores: {errors})")


def save_results(results: dict):
    """Guarda resultados parciales/finales."""
    # Calcular métricas
    tp = results['tp']
    tn = results['tn']
    fp = results['fp']
    fn = results['fn']

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)

    results['metrics'] = {
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1_score': round(f1, 4),
        'accuracy': round(accuracy, 4),
        'confusion_matrix': {
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn
        }
    }
    results['last_updated'] = time.strftime('%Y-%m-%dT%H:%M:%S')

    with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def main():
    logger.info("\n" + "=" * 60)
    logger.info("  DORY DATASET PROCESSOR — Evaluación Completa del Corpus")
    logger.info("=" * 60)

    mal_count = len(glob.glob(os.path.join(MALICIOUS_DIR, '*.eml')))
    leg_count = len(glob.glob(os.path.join(LEGITIMATE_DIR, '*.eml')))
    total = mal_count + leg_count

    logger.info(f"  Maliciosos: {mal_count}")
    logger.info(f"  Legítimos:  {leg_count}")
    logger.info(f"  Total:      {total}")
    logger.info(f"  Motor:      Dory L1+L2 (HuggingFace + Heurísticas)")

    results = {
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'last_updated': None,
        'dataset': {'malicious': mal_count, 'legitimate': leg_count, 'total': total},
        'processed': 0,
        'error_count': 0,
        'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0,
        'metrics': {},
        'entries': [],
        'errors': []
    }

    init_corpus_table()

    # Procesar maliciosos primero
    if mal_count > 0:
        process_folder(MALICIOUS_DIR, 'malicious', results)
        save_results(results)

    # Procesar legítimos
    if leg_count > 0:
        process_folder(LEGITIMATE_DIR, 'legitimate', results)
        save_results(results)

    # Resumen final
    m = results['metrics']
    logger.info("\n" + "=" * 60)
    logger.info("  RESULTADOS FINALES")
    logger.info("=" * 60)
    logger.info(f"  Procesados:        {results['processed']}/{total}")
    logger.info(f"  Errores:           {results['error_count']}")
    logger.info(f"  ---")
    logger.info(f"  True Positives:    {results['tp']} (phishing detectado correctamente)")
    logger.info(f"  True Negatives:    {results['tn']} (legítimo clasificado bien)")
    logger.info(f"  False Positives:   {results['fp']} (legítimo marcado como phishing)")
    logger.info(f"  False Negatives:   {results['fn']} (phishing NO detectado)")
    logger.info(f"  ---")
    logger.info(f"  Precision:         {m.get('precision', 0):.2%}")
    logger.info(f"  Recall:            {m.get('recall', 0):.2%}")
    logger.info(f"  F1 Score:          {m.get('f1_score', 0):.2%}")
    logger.info(f"  Accuracy:          {m.get('accuracy', 0):.2%}")
    logger.info("=" * 60)
    logger.info(f"  Resultados guardados en: {RESULTS_FILE}")


if __name__ == '__main__':
    main()
