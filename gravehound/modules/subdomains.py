import os
import re
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from gravehound.config import DEFAULT_DNS_TIMEOUT, DEFAULT_TIMEOUT, CRT_SH_URL, SECURITYTRAILS_API_URL
import dns.resolver
import dns.exception

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'
DEFAULT_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'dns', 'dns1', 'dns2',
    'mx', 'mx1', 'mx2', 'ntp', 'imap', 'pop3', 'admin', 'administrator', 'api', 'app',
    'apps', 'beta', 'blog', 'cdn', 'cloud', 'cms', 'cpanel', 'dashboard', 'db', 'dev',
    'developer', 'docs', 'email', 'exchange', 'files', 'forum', 'git', 'gitlab', 'help',
    'home', 'hub', 'images', 'img', 'internal', 'intranet', 'jenkins', 'jira', 'lab',
    'labs', 'ldap', 'legacy', 'login', 'manage', 'media', 'mobile', 'monitor', 'mysql',
    'new', 'news', 'office', 'old', 'ops', 'oracle', 'panel', 'portal', 'preview', 'prod',
    'production', 'proxy', 'rdp', 'redis', 'registry', 'remote', 'repo', 'reports', 'rest',
    'sandbox', 'search', 'secure', 'server', 'shop', 'sip', 'ssh', 'ssl', 'staging',
    'static', 'status', 'store', 'support', 'sync', 'syslog', 'test', 'testing', 'ticket',
    'tools', 'tracker', 'upload', 'vault', 'video', 'vm', 'vpn', 'web', 'webdisk', 'wiki',
    'www1', 'www2', 'www3', 'vpn2', 'remote2', 'owa', 'autodiscover', 'lyncdiscover',
    'sharepoint', 'confluence', 'sonar', 'grafana', 'kibana', 'prometheus', 'vault',
    'consul', 'k8s', 'kube', 'rancher', 'argocd', 'harbor',
]
_TAKEOVER_CNAMES = [
    'amazonaws.com', 'github.io', 'heroku.com', 'azurewebsites.net', 'cloudapp.azure.com',
    'shopify.com', 'fastly.net', 'pantheon.io', 'surge.sh', 'netlify.app', 'fly.dev',
    'vercel.app', 'render.com', 'readthedocs.io', 'smugmug.com', 'tumblr.com',
]

def _build_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ['1.1.1.1', '8.8.8.8', '8.8.4.4', '1.0.0.1']
    r.timeout = DEFAULT_DNS_TIMEOUT
    r.lifetime = DEFAULT_DNS_TIMEOUT * 2
    return r

def _resolve_subdomain(subdomain: str, target: str) -> dict | None:
    fqdn = f'{subdomain}.{target}'
    resolver = _build_resolver()
    try:
        a_answers = resolver.resolve(fqdn, 'A')
        ips = [str(r) for r in a_answers]
        cname = None
        try:
            cn = resolver.resolve(fqdn, 'CNAME')
            cname = str(cn[0].target).rstrip('.')
        except Exception:
            pass
        return {'fqdn': fqdn, 'ips': ips, 'cname': cname}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None

def _check_takeover(fqdn: str, cname: str | None) -> str | None:
    if not cname:
        return None
    cname_lower = cname.lower()
    for pattern in _TAKEOVER_CNAMES:
        if pattern in cname_lower:
            return f'{fqdn} → CNAME {cname} (possible subdomain takeover: {pattern})'
    return None

def _query_crt_sh(target: str) -> list[str]:
    subdomains: set[str] = set()
    try:
        url = CRT_SH_URL.replace('{domain}', target)
        with httpx.Client(timeout=15, verify=False, headers={'User-Agent': _UA}) as client:
            response = client.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    for name in entry.get('name_value', '').split('\n'):
                        name = name.strip().lower().lstrip('*').lstrip('.')
                        if name.endswith(f'.{target}') or name == target:
                            if '*' not in name:
                                subdomains.add(name)
    except Exception:
        pass
    return list(subdomains)

def _load_wordlist(wordlist_path: str | None) -> list[str]:
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return DEFAULT_SUBDOMAINS

def run(target: str, wordlist: str | None = None, threads: int = 30) -> dict:
    results = {
        'module': 'Subdomain Discovery',
        'target': target,
        'subdomains': [],
        'resolved': [],
        'sources': {'bruteforce': [], 'crt_sh': [], 'securitytrails': []},
        'total': 0,
        'takeover_candidates': [],
        'findings': [],
        'errors': [],
    }
    discovered: dict[str, dict] = {}
    wordlist_items = _load_wordlist(wordlist)
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(_resolve_subdomain, sub, target): sub
                for sub in wordlist_items
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        fqdn = result['fqdn']
                        if fqdn not in discovered:
                            discovered[fqdn] = result
                            results['sources']['bruteforce'].append(fqdn)
                except Exception:
                    pass
    except Exception as e:
        results['errors'].append(f'Brute-force error: {type(e).__name__}: {str(e)}')
    try:
        crt_results = _query_crt_sh(target)
        for sub in crt_results:
            if sub not in discovered:
                resolved = _resolve_subdomain('', target) if sub == target else None
                rdns = _build_resolver()
                try:
                    a = rdns.resolve(sub, 'A')
                    cname = None
                    try:
                        cn = rdns.resolve(sub, 'CNAME')
                        cname = str(cn[0].target).rstrip('.')
                    except Exception:
                        pass
                    discovered[sub] = {'fqdn': sub, 'ips': [str(r) for r in a], 'cname': cname}
                except Exception:
                    discovered[sub] = {'fqdn': sub, 'ips': [], 'cname': None}
                results['sources']['crt_sh'].append(sub)
    except Exception as e:
        results['errors'].append(f'crt.sh error: {type(e).__name__}: {str(e)}')
    st_key = os.getenv('SECURITYTRAILS_API_KEY')
    if st_key:
        try:
            url = SECURITYTRAILS_API_URL.replace('{target}', target)
            with httpx.Client(
                timeout=10,
                headers={'APIKEY': st_key, 'User-Agent': _UA},
                verify=False,
            ) as client:
                res = client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    for prefix in data.get('subdomains', []):
                        full_sub = f'{prefix}.{target}'
                        if full_sub not in discovered:
                            discovered[full_sub] = {'fqdn': full_sub, 'ips': [], 'cname': None}
                            results['sources']['securitytrails'].append(full_sub)
                elif res.status_code in (401, 403):
                    results['errors'].append('SecurityTrails API key invalid or unauthorized')
        except Exception as e:
            results['errors'].append(f'SecurityTrails error: {type(e).__name__}: {str(e)}')
    for fqdn, info in discovered.items():
        cname = info.get('cname')
        takeover = _check_takeover(fqdn, cname)
        if takeover:
            results['takeover_candidates'].append(takeover)
            results['findings'].append(f'SUBDOMAIN TAKEOVER CANDIDATE: {takeover}')
    results['subdomains'] = sorted(discovered.keys())
    results['resolved'] = [
        v for v in discovered.values()
        if v.get('ips')
    ]
    results['total'] = len(discovered)
    if results['takeover_candidates']:
        results['findings'].insert(0, f'{len(results["takeover_candidates"])} potential subdomain takeover(s) found')
    return results
