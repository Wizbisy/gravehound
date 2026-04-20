import re
import httpx
from gravehound import http
from gravehound.config import DEFAULT_TIMEOUT

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'
_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_VERSION_RE = re.compile(r'(?:^|[-/@])([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9.]+)?)(?:$|[/\-?]|\.min|\.js)')
_KNOWN_VULNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r'^jquery$'), lambda v: _semver_lt(v, '3.5.0'), 'CVE-2020-11022 / CVE-2020-11023 — XSS via .html()', 'HIGH'),
    (re.compile(r'^jquery$'), lambda v: _semver_lt(v, '3.0.0'), 'EOL jQuery 1.x/2.x — multiple XSS CVEs', 'CRITICAL'),
    (re.compile(r'^angular$'), lambda v: v.startswith('1.'), 'AngularJS 1.x is EOL since 2021 — numerous XSS/template-injection CVEs', 'CRITICAL'),
    (re.compile(r'^react(?:-dom)?$'), lambda v: _semver_lt(v, '16.4.2'), 'React < 16.4.2 — CVE-2018-6341 potential XSS', 'HIGH'),
    (re.compile(r'^vue$'), lambda v: v.startswith('1.'), 'Vue.js 1.x is EOL — upgrade to 3.x', 'HIGH'),
    (re.compile(r'^lodash$'), lambda v: _semver_lt(v, '4.17.21'), 'Lodash < 4.17.21 — prototype pollution CVE-2020-28500', 'HIGH'),
    (re.compile(r'^handlebars$'), lambda v: _semver_lt(v, '4.7.7'), 'Handlebars < 4.7.7 — prototype pollution RCE', 'CRITICAL'),
    (re.compile(r'^moment$'), lambda v: _semver_lt(v, '2.29.4'), 'Moment.js < 2.29.4 — ReDoS CVE-2022-31129, also deprecated', 'MEDIUM'),
    (re.compile(r'^bootstrap$'), lambda v: _semver_lt(v, '4.3.1'), 'Bootstrap < 4.3.1 — XSS vulnerabilities in tooltip/popover', 'MEDIUM'),
    (re.compile(r'^axios$'), lambda v: _semver_lt(v, '0.21.1'), 'Axios < 0.21.1 — SSRF/ReDoS CVE-2021-3749', 'HIGH'),
    (re.compile(r'^underscore$'), lambda v: _semver_lt(v, '1.13.0'), 'Underscore < 1.13.0 — arbitrary code execution', 'CRITICAL'),
    (re.compile(r'^dompurify$'), lambda v: _semver_lt(v, '2.4.0'), 'DOMPurify < 2.4.0 — mXSS bypass', 'HIGH'),
]

def _semver_lt(version: str, threshold: str) -> bool:
    try:
        v = tuple(int(x) for x in version.split('-')[0].split('.')[:3])
        t = tuple(int(x) for x in threshold.split('.')[:3])
        while len(v) < 3:
            v += (0,)
        while len(t) < 3:
            t += (0,)
        return v < t
    except (ValueError, AttributeError):
        return False

def _extract_deps(html: str) -> list[dict]:
    deps: dict[str, str] = {}
    for src in _SCRIPT_RE.findall(html):
        src_lower = src.lower()
        m = _VERSION_RE.search(src_lower)
        if not m:
            continue
        version = m.group(1)
        path_part = src_lower.split('?')[0]
        parts = re.split(r'[/@\-]', path_part.rsplit('/', 1)[-1].replace('.min.js', '').replace('.js', ''))
        lib_name = None
        for part in parts:
            part = re.sub(r'[^a-z0-9]', '', part)
            if part and len(part) >= 2 and not re.match(r'^\d+$', part) and part not in ('min', 'js', 'cdn'):
                lib_name = part
                break
        if lib_name and version:
            if lib_name not in deps:
                deps[lib_name] = version
    return [{'name': k, 'version': v} for k, v in deps.items()]

def _check_vulns(deps: list[dict]) -> list[dict]:
    vulnerabilities = []
    for dep in deps:
        name = dep['name'].lower()
        version = dep['version']
        for name_re, check_fn, description, severity in _KNOWN_VULNS:
            if name_re.match(name):
                try:
                    if check_fn(version):
                        vulnerabilities.append({
                            'library': dep['name'],
                            'version': version,
                            'description': description,
                            'severity': severity,
                        })
                except Exception:
                    pass
    return vulnerabilities

def run(target: str) -> dict:
    results = {
        'module': 'Dependency Chain',
        'target': target,
        'dependencies': [],
        'vulnerabilities': [],
        'vuln_count': 0,
        'findings': [],
        'errors': [],
    }
    html = ''
    for proto in ('https', 'http'):
        try:
            with http.Client(timeout=DEFAULT_TIMEOUT,
                verify=False,
                follow_redirects=True,
                headers={'User-Agent': _UA},
            ) as client:
                resp = client.get(f'{proto}://{target}')
                if resp.status_code == 200:
                    html = resp.text
                    break
        except httpx.TimeoutException:
            results['errors'].append(f'Timeout fetching {proto}://{target}')
            continue
        except httpx.ConnectError:
            continue
        except Exception as e:
            results['errors'].append(f'{proto} fetch error: {type(e).__name__}: {str(e)}')
            continue
    if not html:
        return results
    try:
        deps = _extract_deps(html)
        results['dependencies'] = deps
        vulns = _check_vulns(deps)
        results['vulnerabilities'] = vulns
        results['vuln_count'] = len(vulns)
        for v in vulns:
            results['findings'].append(
                f'[{v["severity"]}] {v["library"]} v{v["version"]}: {v["description"]}'
            )
        critical = [v for v in vulns if v['severity'] == 'CRITICAL']
        if critical:
            results['findings'].insert(0, f'{len(critical)} CRITICAL vulnerable librar(ies) detected — immediate action required')
    except Exception as e:
        results['errors'].append(f'Dependency analysis error: {type(e).__name__}: {str(e)}')
    return results
