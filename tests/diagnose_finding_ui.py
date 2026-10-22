from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def short_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()[:12]


def check_live_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or (parsed.hostname or '').lower() not in {'localhost', '127.0.0.1', '::1'}:
        print('LIVE: Refused URL outside localhost. Supply the exact local browser URL.')
        return
    print('LIVE: checking GET', url)
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method='GET'), timeout=7) as res:
            text = res.read(1_000_000).decode('utf-8', errors='replace')
            print('LIVE: HTTP', res.status)
    except urllib.error.HTTPError as exc:
        print('LIVE: HTTP', exc.code, '(open this analysis from Scan History and retry)')
        return
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print('LIVE: not reachable:', type(exc).__name__)
        return

    markers = {
        'new-column-label': 'LLM Severity' in text,
        'new-explanatory-note': 'Different proposed CWEs may refer to the same endpoint' in text,
        'old-column-label': '<th>Severity</th>' in text or '>Severity</th>' in text,
        'old-OTHER-cell': '>OTHER</td>' in text or '>OTHER\n' in text,
    }
    for name, present in markers.items():
        print(f'LIVE: {name} = {present}')
    if not markers['new-column-label'] or not markers['new-explanatory-note']:
        print('DIAGNOSIS: Browser is receiving a template older than the current ZIP source.')
        print('             Find and stop the old Flask PID, then start app.web.server from this repo.')
    else:
        print('DIAGNOSIS: Live page contains current template markers.')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='', help='Optional complete URL from browser address bar; localhost only')
    args = parser.parse_args()
    root = Path.cwd().resolve()
    src = root / 'app' / 'web' / 'server.py'
    template = root / 'app' / 'web' / 'templates' / 'analysis_results.html'
    print('=== FINDING UI / RUNNING VERSION CHECK ===')
    print('Working directory:', root)
    for p in (src, template):
        if not p.is_file():
            print('MISSING:', p)
            print('Run this script from the root of the evidence-gated-appsec-assistant repository.')
            return 2
        content = p.read_bytes()
        print('ON DISK:', p, 'sha256-prefix=', short_hash(content), 'bytes=', len(content))

    text = template.read_text(encoding='utf-8')
    print('SOURCE: LLM Severity heading =', '<th>LLM Severity</th>' in text)
    print('SOURCE: new CWE explanatory note =', 'Different proposed CWEs may refer to the same endpoint' in text)
    if not ('<th>LLM Severity</th>' in text and 'Different proposed CWEs may refer to the same endpoint' in text):
        print('SOURCE: Current folder does not contain the expected updated template.')
        return 3

    sys.path.insert(0, str(root))
    try:
        from app.analysis.finding_presentation import finding_label
        from app.models.finding import Finding, FindingType, ScanType
    except ImportError as exc:
        print('IMPORT FAILED:', exc)
        return 4
    for cwe in ('CWE-434', 'CWE-307', 'CWE-352', 'CWE-200', 'CWE-425', 'CWE-94'):
        f = Finding(finding_type=FindingType.OTHER, scan_type=ScanType.DYNAMIC, explanation='Unverified candidate')
        print('MODEL:', cwe, '=>', finding_label(f, {'proposed_cwe': cwe}))

    if args.url:
        check_live_url(args.url)
    else:
        print('LIVE: not checked; run with --url "<full localhost results page URL>".')
    print('Reminder: Flask in app/web/server.py uses use_reloader=False; file changes require a server restart.')
    print('=== END CHECK ===')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
