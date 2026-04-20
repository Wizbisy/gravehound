import re
import math
import asyncio
import urllib.parse
import httpx
from gravehound import http
from gravehound.config import DEFAULT_TIMEOUT

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'
MAX_URLS = 50
_CONCURRENCY = 8
TARGET_EXTENSIONS = (
    '.js', '.json', '.txt', '.env', '.sql', '.xml', '.yml', '.yaml',
    '.ini', '.conf', '.config', '.bak', '.log', '.sh', '.php',
    '.properties', '.toml', '.pem', '.key', '.crt', '.cer',
)
SECRETS_PATTERNS: list[dict] = [
    {'name': 'AWS Access Key ID',        'pattern': r'AKIA[0-9A-Z]{16}',                                                        'severity': 'CRITICAL'},
    {'name': 'AWS Secret Key',           'pattern': r'(?i)aws.{0,20}secret.{0,5}[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?',       'severity': 'CRITICAL'},
    {'name': 'GitHub Personal Token',    'pattern': r'ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82}',                        'severity': 'CRITICAL'},
    {'name': 'GitLab Token',             'pattern': r'glpat-[0-9A-Za-z\-_]{20}',                                               'severity': 'CRITICAL'},
    {'name': 'Google API Key',           'pattern': r'AIza[0-9A-Za-z\-_]{35}',                                                 'severity': 'CRITICAL'},
    {'name': 'Google OAuth Token',       'pattern': r'ya29\.[0-9A-Za-z\-_]+',                                                  'severity': 'CRITICAL'},
    {'name': 'Stripe Live Key',          'pattern': r'(?:sk|rk)_live_[0-9a-zA-Z]{24,}',                                       'severity': 'CRITICAL'},
    {'name': 'Stripe Publishable Key',   'pattern': r'pk_live_[0-9a-zA-Z]{24,}',                                               'severity': 'HIGH'},
    {'name': 'Slack Bot Token',          'pattern': r'xoxb-[0-9]{11}-[0-9]{11,13}-[a-zA-Z0-9]{24}',                           'severity': 'CRITICAL'},
    {'name': 'Slack Webhook',            'pattern': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', 'severity': 'HIGH'},
    {'name': 'SendGrid API Key',         'pattern': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',                           'severity': 'CRITICAL'},
    {'name': 'Mailgun API Key',          'pattern': r'key-[0-9a-zA-Z]{32}',                                                    'severity': 'HIGH'},
    {'name': 'Twilio Account SID',       'pattern': r'AC[a-z0-9]{32}',                                                         'severity': 'HIGH'},
    {'name': 'Twilio Auth Token',        'pattern': r'(?i)twilio.{0,20}(?:auth.?token|secret)[=:]\s*["\']?([a-f0-9]{32})',     'severity': 'CRITICAL'},
    {'name': 'NPM Auth Token',           'pattern': r'npm_[A-Za-z0-9]{36}|//registry\.npmjs\.org/:_authToken=.+',             'severity': 'HIGH'},
    {'name': 'PyPI API Token',           'pattern': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]+',                                   'severity': 'HIGH'},
    {'name': 'Heroku API Key',           'pattern': r'(?i)heroku.{0,20}[=:]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'severity': 'CRITICAL'},
    {'name': 'Cloudflare API Token',     'pattern': r'(?i)cloudflare.{0,10}(?:token|key|api)[=:]\s*["\']?([A-Za-z0-9_\-]{40})', 'severity': 'CRITICAL'},
    {'name': 'DigitalOcean Token',       'pattern': r'dop_v1_[a-f0-9]{64}',                                                   'severity': 'CRITICAL'},
    {'name': 'Okta API Token',           'pattern': r'(?i)okta.{0,20}(?:token|key)[=:]\s*["\']?([A-Za-z0-9_\-]{40,})',       'severity': 'CRITICAL'},
    {'name': 'Firebase Secret',          'pattern': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',                 'severity': 'HIGH'},
    {'name': 'Azure SAS Token',          'pattern': r'sig=[A-Za-z0-9%/+]{43,}={0,2}&',                                        'severity': 'HIGH'},
    {'name': 'Azure Connection String',  'pattern': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}', 'severity': 'CRITICAL'},
    {'name': 'GCP Service Acct Key',     'pattern': r'"type":\s*"service_account"',                                            'severity': 'CRITICAL'},
    {'name': 'JWT Token',                'pattern': r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+',       'severity': 'MEDIUM'},
    {'name': 'RSA / EC Private Key',     'pattern': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                              'severity': 'CRITICAL'},
    {'name': 'SSH Private Key',          'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',                                    'severity': 'CRITICAL'},
    {'name': 'PGP Private Key',          'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',                                  'severity': 'CRITICAL'},
    {'name': 'Basic Auth in URL',        'pattern': r'https?://[^:]+:[^@]+@[^/\s]+',                                           'severity': 'HIGH'},
    {'name': 'Database DSN (Postgres)',  'pattern': r'postgres(?:ql)?://[^:]+:[^@]+@[^\s]+',                                   'severity': 'CRITICAL'},
    {'name': 'Database DSN (MySQL)',     'pattern': r'mysql://[^:]+:[^@]+@[^\s]+',                                             'severity': 'CRITICAL'},
    {'name': 'Database DSN (MongoDB)',   'pattern': r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+',                                 'severity': 'CRITICAL'},
    {'name': 'Generic API Key/Secret',   'pattern': r'(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)[^\w]{1,5}[=:]\s*["\']?([A-Za-z0-9/\-_+.]{20,80})["\']?', 'severity': 'MEDIUM'},
    {'name': 'Generic Password Field',   'pattern': r'(?i)(?:password|passwd|pwd)[^\w]{1,5}[=:]\s*["\']([^"\'\\]{8,64})["\']', 'severity': 'MEDIUM'},
]
_COMPILED = [
    {**p, '_re': re.compile(p['pattern'])}
    for p in SECRETS_PATTERNS

]
_PRIORITY_EXTS = {'.env', '.yml', '.yaml', '.ini', '.bak', '.sql', '.conf', '.config', '.properties', '.toml', '.pem', '.key'}
_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())

def _redact(value: str) -> str:
    if len(value) <= 6:
        return value[:2] + '***'
    return value[:8] + '...[REDACTED]'

def _parse_archived_date(archive_url: str) -> str:
    try:
        parts = archive_url.split('/web/')
        if len(parts) > 1:
            ts = parts[1].split('/')[0].replace('id_', '').strip()
            if len(ts) >= 8:
                return f'{ts[:4]}-{ts[4:6]}-{ts[6:8]}'
    except Exception:
        pass
    return ''

def _fetch_cdx_urls(target: str) -> list[str]:
    urls: list[str] = []
    try:
        cdx_url = (
            f'https://web.archive.org/cdx/search/cdx'
            f'?url=*.{target}/*'
            f'&output=json'
            f'&limit=500'
            f'&fl=original,timestamp,statuscode'
            f'&collapse=urlkey'
            f'&filter=statuscode:200'
            f'&matchType=domain'
        )
        with http.Client(timeout=15, headers={'User-Agent': _UA}) as client:
            resp = client.get(cdx_url)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    headers = data[0]
                    for row in data[1:]:
                        entry = dict(zip(headers, row))
                        original_url = entry.get('original', '')
                        parsed = urllib.parse.urlparse(original_url)
                        path = parsed.path.lower().split('?')[0]
                        if any(path.endswith(ext) for ext in TARGET_EXTENSIONS):
                            ts = entry.get('timestamp', 'X')
                            archive_url = f'https://web.archive.org/web/{ts}id_/{original_url}'
                            urls.append(archive_url)
    except Exception:
        pass
    return urls

def _priority(url: str) -> int:
    lower = url.lower()
    if any(ext in lower for ext in _PRIORITY_EXTS):
        return 0
    if '.json' in lower or '.xml' in lower:
        return 1
    return 2

async def _fetch_and_scan(url: str, sem: asyncio.Semaphore, client: httpx.AsyncClient) -> list[dict]:
    findings = []
    async with sem:
        try:
            resp = await client.get(url, timeout=10)
            if resp.status_code != 200:
                return findings
            text = resp.text
            archived_date = _parse_archived_date(url)
            for pat in _COMPILED:
                for match in pat['_re'].finditer(text):
                    raw = match.group(0) if match.lastindex is None else (match.group(1) or match.group(0))
                    if not raw or len(raw) > 200:
                        continue
                    if pat['name'] in ('Generic API Key/Secret', 'Generic Password Field', 'JWT Token'):
                        if _entropy(raw) < 3.5:
                            continue
                    findings.append({
                        'pattern': pat['name'],
                        'severity': pat['severity'],
                        'value_redacted': _redact(raw),
                        'source_url': url,
                        'archived_date': archived_date,
                    })
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
    return findings

def _deduplicate(raw: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for item in raw:
        key = (item['pattern'], item['value_redacted'])
        if key not in seen:
            seen[key] = {**item, 'source_urls': [item['source_url']]}
        else:
            if item['source_url'] not in seen[key]['source_urls']:
                seen[key]['source_urls'].append(item['source_url'])
    for item in seen.values():
        item.pop('source_url', None)
    return sorted(seen.values(), key=lambda x: _SEVERITY_ORDER.get(x['severity'], 99))

async def _run_async(target: str) -> tuple[list[str], list[dict]]:
    raw_urls = _fetch_cdx_urls(target)
    urls = sorted(raw_urls, key=_priority)[:MAX_URLS]
    sem = asyncio.Semaphore(_CONCURRENCY)
    async with http.AsyncClient(verify=False,
        follow_redirects=True,
        headers={'User-Agent': _UA},
        timeout=10,
    ) as client:
        tasks = [_fetch_and_scan(url, sem, client) for url in urls]
        results_nested = await asyncio.gather(*tasks, return_exceptions=True)
    raw: list[dict] = []
    for item in results_nested:
        if isinstance(item, list):
            raw.extend(item)
    return urls, raw

def run(target: str) -> dict:
    results = {
        'module': 'Wayback Secrets',
        'target': target,
        'leaks_found': [],
        'urls_scanned': 0,
        'total_urls_found': 0,
        'severity_summary': {},
        'ssl_warning': 'TLS verification disabled for Wayback Machine (mixed-cert archive)',
        'errors': [],
    }
    try:
        urls, raw_findings = asyncio.run(_run_async(target))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            urls, raw_findings = loop.run_until_complete(_run_async(target))
        finally:
            loop.close()
    results['urls_scanned'] = len(urls)
    results['total_urls_found'] = len(urls)
    deduped = _deduplicate(raw_findings)
    results['leaks_found'] = deduped
    severity_summary: dict[str, int] = {}
    for leak in deduped:
        sev = leak['severity']
        severity_summary[sev] = severity_summary.get(sev, 0) + 1
    results['severity_summary'] = severity_summary
    return results
