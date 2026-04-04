import httpx
from twilight_orbit.config import SECURITY_HEADERS, DEFAULT_TIMEOUT

_UA = 'Mozilla/5.0 (compatible; TwilightOrbit/1.0)'

_INFO_LEAKING_HEADERS = [
    'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
    'x-generator', 'x-drupal-cache', 'server', 'x-runtime',
    'x-version', 'x-app-version', 'x-build', 'x-fw-version',
]

_CSP_UNSAFE = ['unsafe-inline', 'unsafe-eval', 'unsafe-hashes', "'unsafe-inline'", "'unsafe-eval'"]


def _grade(score: int, max_score: int) -> str:
    ratio = score / max_score if max_score else 0
    if ratio >= 0.875:
        return 'A'
    if ratio >= 0.75:
        return 'B'
    if ratio >= 0.5:
        return 'C'
    if ratio >= 0.25:
        return 'D'
    return 'F'


def _analyse_csp(value: str) -> list[str]:
    findings = []
    lower = value.lower()
    for unsafe in _CSP_UNSAFE:
        if unsafe in lower:
            findings.append(f"CSP contains '{unsafe}' — reduces XSS protection")
    if 'http:' in lower:
        findings.append("CSP allows http: scheme — downgrade risk")
    if '*' in lower:
        findings.append("CSP contains wildcard (*) — overly permissive")
    if 'default-src' not in lower and 'script-src' not in lower:
        findings.append("CSP missing default-src or script-src directive")
    return findings


def _analyse_hsts(value: str) -> list[str]:
    findings = []
    lower = value.lower()
    try:
        max_age_part = [p for p in lower.split(';') if 'max-age' in p][0]
        max_age = int(max_age_part.split('=')[1].strip())
        if max_age < 31536000:
            findings.append(f'HSTS max-age={max_age} is less than 1 year (31536000 seconds)')
    except (IndexError, ValueError):
        findings.append('HSTS header present but max-age could not be parsed')
    if 'includesubdomains' not in lower:
        findings.append('HSTS missing includeSubDomains — subdomains not protected')
    if 'preload' not in lower:
        findings.append('HSTS missing preload directive')
    return findings


def run(target: str) -> dict:
    results = {
        'module': 'HTTP Headers',
        'target': target,
        'url': None,
        'status_code': None,
        'headers': {},
        'security_analysis': [],
        'score': 0,
        'max_score': len(SECURITY_HEADERS),
        'grade': 'F',
        'server': None,
        'interesting_headers': {},
        'findings': [],
        'errors': [],
    }

    headers = {'User-Agent': _UA}
    urls = [f'https://{target}', f'http://{target}']

    for url in urls:
        try:
            with httpx.Client(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=True,
                verify=False,
                headers=headers,
            ) as client:
                response = client.get(url)
                results['url'] = str(response.url)
                results['status_code'] = response.status_code
                results['headers'] = dict(response.headers)
                results['server'] = response.headers.get('server', 'Not disclosed')

                present_count = 0
                for header_name, info in SECURITY_HEADERS.items():
                    header_value = response.headers.get(header_name.lower())
                    is_present = header_value is not None
                    if is_present:
                        present_count += 1

                    entry = {
                        'header': header_name,
                        'present': is_present,
                        'value': header_value or 'Not set',
                        'description': info['description'],
                        'severity': info['severity'],
                        'sub_findings': [],
                    }

                    if is_present and header_name == 'Content-Security-Policy':
                        entry['sub_findings'] = _analyse_csp(header_value)
                    elif is_present and header_name == 'Strict-Transport-Security':
                        entry['sub_findings'] = _analyse_hsts(header_value)
                    elif not is_present and info['severity'] == 'HIGH':
                        results['findings'].append(f'Missing {header_name} ({info["severity"]} severity)')

                    results['security_analysis'].append(entry)

                results['score'] = present_count
                results['grade'] = _grade(present_count, len(SECURITY_HEADERS))

                for key in _INFO_LEAKING_HEADERS:
                    val = response.headers.get(key)
                    if val:
                        results['interesting_headers'][key] = val
                        if key in ('x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
                                   'x-generator', 'x-runtime', 'x-version', 'x-app-version'):
                            results['findings'].append(
                                f'Technology disclosure via {key}: {val}'
                            )

                if response.history:
                    first = response.history[0]
                    if str(first.url).startswith('http://') and str(response.url).startswith('https://'):
                        results['findings'].append('HTTP→HTTPS redirect present (good)')
                    hops = len(response.history)
                    if hops > 3:
                        results['findings'].append(f'Excessive redirects ({hops} hops) — may indicate misconfiguration')

                cookie_header = response.headers.get('set-cookie', '')
                if cookie_header:
                    lower_ck = cookie_header.lower()
                    if 'secure' not in lower_ck:
                        results['findings'].append('Set-Cookie missing Secure flag')
                    if 'httponly' not in lower_ck:
                        results['findings'].append('Set-Cookie missing HttpOnly flag')
                    if 'samesite' not in lower_ck:
                        results['findings'].append('Set-Cookie missing SameSite attribute')

                return results

        except httpx.ConnectError:
            continue
        except httpx.TimeoutException:
            results['errors'].append(f'Timeout connecting to {url}')
            continue
        except Exception as e:
            results['errors'].append(f'Error connecting to {url}: {type(e).__name__}: {str(e)}')
            continue

    if not results['url']:
        results['errors'].append(f'Could not connect to {target} on HTTP or HTTPS')

    return results