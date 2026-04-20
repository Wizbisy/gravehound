import httpx
from gravehound import http
from concurrent.futures import ThreadPoolExecutor, as_completed

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'

CORS_TESTS = [
    {
        'name': 'Reflected Origin',
        'origin': 'https://evil.com',
        'description': 'Server reflects arbitrary Origin — full CORS bypass',
        'severity': 'CRITICAL',
    },
    {
        'name': 'Null Origin',
        'origin': 'null',
        'description': 'Server trusts null Origin — exploitable via sandboxed iframes',
        'severity': 'HIGH',
    },
    {
        'name': 'Subdomain Trust',
        'origin': 'https://evil.{target}',
        'description': 'Server trusts any subdomain — subdomain takeover → CORS bypass chain',
        'severity': 'HIGH',
    },
    {
        'name': 'Prefix Match Bypass',
        'origin': 'https://{target}.evil.com',
        'description': 'Server uses prefix matching — attacker-controlled domain bypass',
        'severity': 'HIGH',
    },
    {
        'name': 'HTTP Downgrade',
        'origin': 'http://{target}',
        'description': 'Server trusts HTTP origin on HTTPS endpoint — MitM attack vector',
        'severity': 'MEDIUM',
    },
    {
        'name': 'Backtick Bypass',
        'origin': 'https://evil.com`.{target}',
        'description': 'Backtick in origin bypasses some regex validators',
        'severity': 'HIGH',
    },
    {
        'name': 'Postfix Match',
        'origin': 'https://not{target}',
        'description': 'Server uses endsWith check — bypassed with domain embedding',
        'severity': 'HIGH',
    },
]

_API_PREFIXES = ['api', 'app', 'admin', 'dashboard', 'portal', 'rest', 'graphql', 'v1', 'v2']
_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


def _test_endpoint(url: str, test: dict, target: str, method: str = 'GET') -> dict | None:
    origin = test['origin'].replace('{target}', target)
    try:
        with http.Client(timeout=8,
            verify=False,
            follow_redirects=True,
            headers={
                'User-Agent': _UA,
                'Origin': origin,
            },
        ) as client:
            if method == 'OPTIONS':
                resp = client.options(url, headers={
                    'User-Agent': _UA,
                    'Origin': origin,
                    'Access-Control-Request-Method': 'GET',
                    'Access-Control-Request-Headers': 'Authorization',
                })
            else:
                resp = client.get(url)
            acao = resp.headers.get('access-control-allow-origin', '')
            acac = resp.headers.get('access-control-allow-credentials', '').lower()
            if not acao:
                return None
            is_vulnerable = False
            vuln_detail = ''
            if acao == origin:
                is_vulnerable = True
                vuln_detail = f'Origin "{origin}" reflected in ACAO'
            elif acao == 'null' and test['name'] == 'Null Origin':
                is_vulnerable = True
                vuln_detail = 'ACAO set to "null" — exploitable via sandboxed iframe'
            elif acao == '*':
                if acac == 'true':
                    is_vulnerable = True
                    vuln_detail = 'Wildcard ACAO with credentials=true — browser rejects but indicates server misconfiguration'
                else:
                    return None
            if not is_vulnerable:
                return None
            severity = test['severity']
            if acac == 'true' and severity != 'CRITICAL':
                severity = 'CRITICAL'
            test_label = f'{test["name"]} ({method})' if method == 'OPTIONS' else test['name']
            return {
                'url': url,
                'test_name': test_label,
                'severity': severity,
                'origin_sent': origin,
                'acao_received': acao,
                'acac': acac == 'true',
                'description': test['description'],
                'detail': vuln_detail,
                'status_code': resp.status_code,
                'method': method,
            }
    except Exception:
        pass
    return None


def run(target: str, context: dict | None = None) -> dict:
    results = {
        'module': 'CORS Misconfiguration',
        'target': target,
        'vulnerabilities': [],
        'total_tested': 0,
        'endpoints_tested': [],
        'findings': [],
        'errors': [],
    }
    endpoints = set()
    for proto in ('https', 'http'):
        endpoints.add(f'{proto}://{target}')
        endpoints.add(f'{proto}://{target}/')
    if context and isinstance(context, dict):
        ctx_results = context.get('results', {})
        sub_data = ctx_results.get('subdomains', {})
        if isinstance(sub_data, dict):
            discovered_subs = sub_data.get('subdomains', [])
            for sub in discovered_subs:
                sub_lower = sub.lower()
                if any(sub_lower.startswith(f'{p}.') for p in _API_PREFIXES):
                    for proto in ('https', 'http'):
                        endpoints.add(f'{proto}://{sub}')
    endpoint_list = sorted(endpoints)[:20]
    results['endpoints_tested'] = endpoint_list
    all_tasks = []
    for endpoint in endpoint_list:
        for test in CORS_TESTS:
            all_tasks.append((endpoint, test, 'GET'))
            all_tasks.append((endpoint, test, 'OPTIONS'))
    results['total_tested'] = len(all_tasks)
    seen = set()
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {
            executor.submit(_test_endpoint, endpoint, test, target, method): (endpoint, test['name'], method)
            for endpoint, test, method in all_tasks
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    dedup_key = (result['url'], result['test_name'])
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        results['vulnerabilities'].append(result)
            except Exception as e:
                results['errors'].append(f'CORS test failed: {str(e)}')
    results['vulnerabilities'].sort(key=lambda x: _SEVERITY_ORDER.get(x.get('severity', 'INFO'), 99))
    critical = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'CRITICAL')
    high = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'HIGH')
    if critical:
        results['findings'].insert(0, f'{critical} CRITICAL CORS misconfiguration(s) — account takeover risk')
    if high:
        results['findings'].append(f'{high} HIGH severity CORS issue(s) detected')
    for vuln in results['vulnerabilities']:
        host = vuln['url'].split('://')[1].split('/')[0]
        results['findings'].append(
            f'[{vuln["severity"]}] {vuln["test_name"]} on {host} — {vuln["detail"]}'
        )
    return results
