import re
import math
import asyncio
import httpx
from gravehound import http
from urllib.parse import urljoin

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'
_CONCURRENCY = 10
_MAX_JS_FILES = 30

SECRETS_PATTERNS = [
    {'name': 'AWS Access Key ID',        'pattern': r'AKIA[0-9A-Z]{16}',                                                        'severity': 'CRITICAL'},
    {'name': 'AWS Secret Key',           'pattern': r'(?i)aws.{0,20}secret.{0,5}[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?',       'severity': 'CRITICAL'},
    {'name': 'GitHub Personal Token',    'pattern': r'ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82}',                        'severity': 'CRITICAL'},
    {'name': 'Google API Key',           'pattern': r'AIza[0-9A-Za-z\-_]{35}',                                                  'severity': 'CRITICAL'},
    {'name': 'Google OAuth Token',       'pattern': r'ya29\.[0-9A-Za-z\-_]+',                                                   'severity': 'CRITICAL'},
    {'name': 'Stripe Live Key',          'pattern': r'(?:sk|rk)_live_[0-9a-zA-Z]{24,}',                                        'severity': 'CRITICAL'},
    {'name': 'Stripe Publishable Key',   'pattern': r'pk_live_[0-9a-zA-Z]{24,}',                                                'severity': 'HIGH'},
    {'name': 'Slack Bot Token',          'pattern': r'xoxb-[0-9]{11}-[0-9]{11,13}-[a-zA-Z0-9]{24}',                            'severity': 'CRITICAL'},
    {'name': 'Slack Webhook',            'pattern': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',  'severity': 'HIGH'},
    {'name': 'SendGrid API Key',         'pattern': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',                            'severity': 'CRITICAL'},
    {'name': 'Twilio Account SID',       'pattern': r'AC[a-z0-9]{32}',                                                          'severity': 'HIGH'},
    {'name': 'Firebase Secret',          'pattern': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',                  'severity': 'HIGH'},
    {'name': 'Infura Project ID',        'pattern': r'(?i)infura.{0,20}[=:]\s*["\']?([a-f0-9]{32})["\']?',                     'severity': 'HIGH'},
    {'name': 'Alchemy API Key',          'pattern': r'(?i)alchemy.{0,20}[=:]\s*["\']?([A-Za-z0-9_\-]{32,})["\']?',            'severity': 'HIGH'},
    {'name': 'Mapbox Token',             'pattern': r'pk\.eyJ[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+',                                'severity': 'MEDIUM'},
    {'name': 'RSA / EC Private Key',     'pattern': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                               'severity': 'CRITICAL'},
    {'name': 'Basic Auth in URL',        'pattern': r'https?://[^:]+:[^@]+@[^/\s]+',                                            'severity': 'HIGH'},
    {'name': 'Database DSN (Postgres)',  'pattern': r'postgres(?:ql)?://[^:]+:[^@]+@[^\s]+',                                    'severity': 'CRITICAL'},
    {'name': 'Database DSN (MySQL)',     'pattern': r'mysql://[^:]+:[^@]+@[^\s]+',                                              'severity': 'CRITICAL'},
    {'name': 'Database DSN (MongoDB)',   'pattern': r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+',                                  'severity': 'CRITICAL'},
    {'name': 'Paystack Secret Key',      'pattern': r'sk_(?:live|test)_[0-9a-zA-Z]{40,}',                                      'severity': 'CRITICAL'},
    {'name': 'Paystack Public Key',      'pattern': r'pk_(?:live|test)_[0-9a-zA-Z]{40,}',                                      'severity': 'HIGH'},
    {'name': 'Flutterwave Secret Key',   'pattern': r'FLWSECK(?:_TEST)?-[a-zA-Z0-9]{32,}-X',                                   'severity': 'CRITICAL'},
    {'name': 'Flutterwave Public Key',   'pattern': r'FLWPUBK(?:_TEST)?-[a-zA-Z0-9]{32,}-X',                                   'severity': 'HIGH'},
    {'name': 'Generic API Key/Secret',   'pattern': r'(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)[^\w]{1,5}[=:]\s*["\']?([A-Za-z0-9/\-_+.]{20,80})["\']?', 'severity': 'MEDIUM'},
    {'name': 'Generic Password Field',   'pattern': r'(?i)(?:password|passwd|pwd)[^\w]{1,5}[=:]\s*["\']([^"\'\\]{8,64})["\']', 'severity': 'MEDIUM'},
]

_COMPILED_SECRETS = [
    {**p, '_re': re.compile(p['pattern'])}
    for p in SECRETS_PATTERNS
]

ENDPOINT_PATTERNS = [
    re.compile(r'["\']([/\\]{1,2}(?:api|admin|internal|graphql|debug|swagger|v[0-9]|rest|backstage|dashboard|manage|config|settings|healthz?|metrics|actuator)[/\\][a-zA-Z0-9/_\-.*]*)["\']'),
    re.compile(r'["\']([/\\]{1,2}(?:__[a-zA-Z]+__|\.well-known|_debug|_internal|_admin|_config|_status)[/\\]?[a-zA-Z0-9/_\-]*)["\']'),
    re.compile(r'["\'](https?://[^"\'<>\s]{5,}(?:/api/|/admin/|/internal/|/graphql|/v[0-9]/)[^"\'<>\s]*)["\']'),
]

INTERNAL_URI_PATTERNS = [
    re.compile(r'https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})[:/][^\s"\'<>]*'),
    re.compile(r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[:/][^\s"\'<>]*'),
    re.compile(r'https?://[a-zA-Z0-9\-]+\.(?:internal|local|corp|intra|lan|home|private|test)[:/\s"\'<>]'),
    re.compile(r'(?:s3\.amazonaws\.com|\.blob\.core\.windows\.net|storage\.googleapis\.com|\.digitaloceanspaces\.com|\.s3\.wasabisys\.com)/[^\s"\'<>]+'),
]

_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

_CHUNK_PATTERN = re.compile(
    r'["\']([^\s"\'<>]*(?:chunk|vendor|runtime|main|app|index)\.[a-f0-9]{6,}\.(js)(?:\?[^\s"\'<>]*)?)["\']',
    re.IGNORECASE
)


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


def _extract_js_urls(html: str, base_url: str) -> tuple[list[str], int]:
    urls = set()
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = match.group(1)
        if src.startswith('//'):
            src = 'https:' + src
        elif not src.startswith('http'):
            src = urljoin(base_url, src)
        urls.add(src)
    for match in re.finditer(r'["\'](https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?)["\']', html):
        urls.add(match.group(1))
    for match in _CHUNK_PATTERN.finditer(html):
        src = match.group(1)
        if not src.startswith('http'):
            src = urljoin(base_url, src)
        urls.add(src)
    total = len(urls)
    return list(urls)[:_MAX_JS_FILES], total


def _is_javascript_response(resp: httpx.Response) -> bool:
    ct = resp.headers.get('content-type', '').lower()
    return 'javascript' in ct or 'text/plain' in ct or ct == ''


def _scan_js_content(text: str, source_url: str) -> dict:
    secrets = []
    endpoints = set()
    internal_uris = set()
    for pat in _COMPILED_SECRETS:
        for match in pat['_re'].finditer(text):
            raw = match.group(0) if match.lastindex is None else (match.group(1) or match.group(0))
            if not raw or len(raw) > 200:
                continue
            if pat['name'] in ('Generic API Key/Secret', 'Generic Password Field'):
                if _entropy(raw) < 3.5:
                    continue
            secrets.append({
                'pattern': pat['name'],
                'severity': pat['severity'],
                'value_redacted': _redact(raw),
                'source': source_url,
            })
    for pat in ENDPOINT_PATTERNS:
        for match in pat.finditer(text):
            ep = match.group(1)
            if len(ep) < 4 or len(ep) > 200:
                continue
            endpoints.add(ep)
    for pat in INTERNAL_URI_PATTERNS:
        for match in pat.finditer(text):
            uri = match.group(0)
            if len(uri) > 200:
                continue
            internal_uris.add(uri)
    return {
        'secrets': secrets,
        'endpoints': list(endpoints),
        'internal_uris': list(internal_uris),
    }


async def _fetch_and_scan(url: str, sem: asyncio.Semaphore, client: httpx.AsyncClient) -> dict:
    async with sem:
        try:
            resp = await client.get(url, timeout=10)
            if resp.status_code != 200:
                return {'secrets': [], 'endpoints': [], 'internal_uris': [], 'url': url, 'size': 0}
            if not _is_javascript_response(resp):
                return {'secrets': [], 'endpoints': [], 'internal_uris': [], 'url': url, 'size': 0, 'skipped': True}
            text = resp.text
            result = _scan_js_content(text, url)
            result['url'] = url
            result['size'] = len(text)
            return result
        except Exception:
            return {'secrets': [], 'endpoints': [], 'internal_uris': [], 'url': url, 'size': 0}


async def _run_async(js_urls: list[str]) -> list[dict]:
    sem = asyncio.Semaphore(_CONCURRENCY)
    async with http.AsyncClient(verify=False,
        follow_redirects=True,
        headers={'User-Agent': _UA},
        timeout=10,
    ) as client:
        tasks = [_fetch_and_scan(url, sem, client) for url in js_urls]
        return await asyncio.gather(*tasks, return_exceptions=True)


def _collect_js_urls_from_target(target_url: str, errors: list) -> tuple[str | None, str | None]:
    for proto in ('https', 'http'):
        url = f'{proto}://{target_url}' if not target_url.startswith('http') else target_url
        try:
            with http.Client(timeout=10, verify=False, follow_redirects=True, headers={'User-Agent': _UA}) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    return resp.text, str(resp.url)
        except Exception:
            continue
    errors.append(f'Could not fetch homepage for {target_url}')
    return None, None


def run(target: str, context: dict | None = None) -> dict:
    results = {
        'module': 'JS Analyzer',
        'target': target,
        'js_files_scanned': 0,
        'js_files_capped': False,
        'js_files': [],
        'secrets': [],
        'endpoints': [],
        'internal_uris': [],
        'severity_summary': {},
        'findings': [],
        'errors': [],
    }
    targets_to_scan = [target]
    if context and isinstance(context, dict):
        ctx_results = context.get('results', {})
        sub_data = ctx_results.get('subdomains', {})
        if isinstance(sub_data, dict):
            found_subs = sub_data.get('subdomains', [])
            api_keywords = ('api', 'app', 'admin', 'dashboard', 'portal', 'web', 'static', 'cdn', 'assets')
            for sub in found_subs:
                hostname = sub if isinstance(sub, str) else sub.get('subdomain', '')
                if any(kw in hostname.lower() for kw in api_keywords):
                    targets_to_scan.append(hostname)
    all_js_urls = set()
    base_url = None
    for t in targets_to_scan:
        html, burl = _collect_js_urls_from_target(t, results['errors'])
        if html and burl:
            if base_url is None:
                base_url = burl
            urls, total = _extract_js_urls(html, burl)
            if total > _MAX_JS_FILES and t == target:
                results['js_files_capped'] = True
                results['errors'].append(
                    f'Found {total} JS files on {t}, capped at {_MAX_JS_FILES} for performance'
                )
            all_js_urls.update(urls)
    js_urls = list(all_js_urls)[:_MAX_JS_FILES]
    if not js_urls:
        results['errors'].append('No JavaScript files found on the page')
        return results
    try:
        scan_results = asyncio.run(_run_async(js_urls))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            scan_results = loop.run_until_complete(_run_async(js_urls))
        finally:
            loop.close()
    all_secrets = []
    all_endpoints = set()
    all_internal = set()
    for item in scan_results:
        if isinstance(item, Exception):
            continue
        if isinstance(item, dict):
            if not item.get('skipped'):
                results['js_files'].append({
                    'url': item.get('url', ''),
                    'size': item.get('size', 0),
                    'secrets_found': len(item.get('secrets', [])),
                    'endpoints_found': len(item.get('endpoints', [])),
                })
            all_secrets.extend(item.get('secrets', []))
            all_endpoints.update(item.get('endpoints', []))
            all_internal.update(item.get('internal_uris', []))
    results['js_files_scanned'] = len(results['js_files'])
    seen_secrets = set()
    deduped = []
    for s in all_secrets:
        key = (s['pattern'], s['value_redacted'])
        if key not in seen_secrets:
            seen_secrets.add(key)
            deduped.append(s)
    deduped.sort(key=lambda x: _SEVERITY_ORDER.get(x.get('severity', 'LOW'), 99))
    results['secrets'] = deduped
    results['endpoints'] = sorted(all_endpoints)
    results['internal_uris'] = sorted(all_internal)
    severity_summary = {}
    for s in deduped:
        sev = s['severity']
        severity_summary[sev] = severity_summary.get(sev, 0) + 1
    results['severity_summary'] = severity_summary
    if deduped:
        results['findings'].append(f'{len(deduped)} hardcoded secret(s) found in JavaScript files')
    if all_endpoints:
        results['findings'].append(f'{len(all_endpoints)} hidden/admin endpoint(s) discovered in JS bundles')
    if all_internal:
        results['findings'].append(f'{len(all_internal)} internal/private URI(s) leaked in JS bundles')
    return results
