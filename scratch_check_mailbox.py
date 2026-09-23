import imaplib
import json
import email
from email.header import decode_header

cfg = json.load(open('mail_config.json'))['imap']
imap = imaplib.IMAP4_SSL(cfg['server'], cfg['port'])
imap.login(cfg['user'], cfg['password'])

for folder in ['INBOX', 'Junk', 'INBOX.spam', 'Sent', 'Trash']:
    try:
        res, count = imap.select(folder)
        typ, data = imap.search(None, 'ALL')
        ids = data[0].split()
        print(f"=== {folder} ({len(ids)} messages) ===")
        for mid in ids[-5:]:
            _, mdata = imap.fetch(mid, '(RFC822.HEADER)')
            h = email.message_from_bytes(mdata[0][1])
            raw_subj = h.get('Subject', '')
            subj_parts = decode_header(raw_subj)
            subj = ""
            for p, enc in subj_parts:
                if isinstance(p, bytes):
                    subj += p.decode(enc or 'utf-8', errors='replace')
                else:
                    subj += str(p)
            print(f"  ID {mid.decode()}: Date: {h.get('Date')} | From: {h.get('From')} | Subject: {subj[:70]}")
    except Exception as e:
        print(f"Error checking {folder}: {e}")

imap.logout()
