import json
import sys

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

with open("logs/test_real_100_results.json", "r", encoding="utf-8") as f:
    d = json.load(f)

print(f"Total analizados: {d['total_tested']}")
print(f"Total Safe: {d['safe_count']}")
print(f"Total Suspicious: {d['suspicious_count']}")
print(f"Total Phishing: {d['phishing_count']}")
print("=" * 80)

for e in d["flagged_emails"]:
    idx = e["idx"]
    v = e["verdict"]
    s = e["score"]
    sender = e["sender"]
    subject = e["subject"]
    threats = e["threats"]
    print(f"#{idx:<2} [{v:<10} {s:>3} pts] De: {sender}")
    print(f"    Asunto: {subject}")
    print(f"    Amenazas: {threats}")
    print("-" * 80)
