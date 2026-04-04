import httpx
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed

_UA = 'Mozilla/5.0 (compatible; TwilightOrbit/1.0)'

TAKEOVER_FINGERPRINTS = {
    'GitHub Pages':        {'cnames': ['.github.io'],            'fingerprints': ["There isn't a GitHub Pages site here", "404 There is no GitHub Pages site"],                         'severity': 'HIGH'},
    'AWS S3':              {'cnames': ['.s3.amazonaws.com', '.s3-website'],       'fingerprints': ['NoSuchBucket', 'The specified bucket does not exist'],                              'severity': 'CRITICAL'},
    'AWS CloudFront':      {'cnames': ['.cloudfront.net'],       'fingerprints': ['Bad Request: The request could not be satisfied'],                                                    'severity': 'HIGH'},
    'Heroku':              {'cnames': ['.herokuapp.com', '.herokudns.com'],       'fingerprints': ['No such app', 'herokucdn.com/error-pages/no-such-app'],                            'severity': 'CRITICAL'},
    'Zendesk':             {'cnames': ['.zendesk.com'],          'fingerprints': ['Help Center Closed', 'Oops, this help center no longer exists'],                                    'severity': 'HIGH'},
    'Squarespace':         {'cnames': ['.squarespace.com'],      'fingerprints': ['Squarespace - Claim This Domain', "Looks like you may have taken a wrong turn"],                    'severity': 'HIGH'},
    'Pantheon':            {'cnames': ['.pantheonsite.io', '.getpantheon.com'],   'fingerprints': ['The gods are wise', "404 error unknown site"],                                     'severity': 'HIGH'},
    'Tumblr':              {'cnames': ['.tumblr.com'],           'fingerprints': ["Whatever you were looking for doesn't live here"],                                                  'severity': 'MEDIUM'},
    'Shopify':             {'cnames': ['.myshopify.com'],        'fingerprints': ['Sorry, this shop is currently unavailable.'],                                                        'severity': 'HIGH'},
    'Ghost':               {'cnames': ['.ghost.io'],             'fingerprints': ["The thing you were looking for is no longer here"],                                                 'severity': 'MEDIUM'},
    'ReadTheDocs':         {'cnames': ['.readthedocs.io'],       'fingerprints': ['unknown to Read the Docs'],                                                                         'severity': 'MEDIUM'},
    'Fastly':              {'cnames': ['.fastly.net'],           'fingerprints': ['Fastly error: unknown domain'],                                                                     'severity': 'HIGH'},
    'Azure (App Svc)':     {'cnames': ['.azurewebsites.net', '.cloudapp.net', '.cloudapp.azure.com'], 'fingerprints': ['Error 404 - Web app not found', "did not have a subscription associated"], 'severity': 'CRITICAL'},
    'Azure (Traffic Mgr)': {'cnames': ['.trafficmanager.net'],   'fingerprints': ['404 Not Found'],                                                                                    'severity': 'HIGH'},
    'Surge.sh':            {'cnames': ['.surge.sh'],             'fingerprints': ["project not found"],                                                                               'severity': 'HIGH'},
    'Netlify':             {'cnames': ['.netlify.app', '.netlify.com'],           'fingerprints': ['Not Found - Request ID', "Oh no! The page you're looking for could not be found"], 'severity': 'HIGH'},
    'Vercel':              {'cnames': ['.vercel.app', '.now.sh'],                 'fingerprints': ['The deployment you are looking for', 'HOST_NOT_FOUND'],                           'severity': 'HIGH'},
    'Fly.io':              {'cnames': ['.fly.dev', '.fly.io'],   'fingerprints': ["404 Not Found"],                                                                                   'severity': 'HIGH'},
    'Render':              {'cnames': ['.onrender.com'],         'fingerprints': ['Service Unavailable', 'Not Found'],                                                                'severity': 'HIGH'},
    'DigitalOcean Spaces': {'cnames': ['.digitaloceanspaces.com'],               'fingerprints': ['NoSuchBucket', 'The specified bucket does not exist'],                            'severity': 'HIGH'},
    'HubSpot':             {'cnames': ['.hubspot.com', '.hs-sites.com'],          'fingerprints': ['does not exist in our system'],                                                   'severity': 'MEDIUM'},
    'Webflow':             {'cnames': ['.proxy.webflow.com', '.webflow.io'],      'fingerprints': ["The page you are looking for doesn't exist or has been moved"],                   'severity': 'MEDIUM'},
    'Cargo':               {'cnames': ['.cargocollective.com'],  'fingerprints': ['404 Not Found'],                                                                                   'severity': 'LOW'},
    'BitBucket':           {'cnames': ['.bitbucket.io'],         'fingerprints': ['Repository not found'],                                                                            'severity': 'MEDIUM'},
    'Campaign Monitor':    {'cnames': ['.createsend.com'],       'fingerprints': ['Double check the URL'],                                                                            'severity': 'MEDIUM'},
    'Intercom':            {'cnames': ['.custom.intercom.help'], 'fingerprints': ['This page is reserved for artistic'],                                                              'severity': 'MEDIUM'},
    'Unbounce':            {'cnames': ['.unbouncepages.com'],    'fingerprints': ["The requested URL was not found on this server"],                                                  'severity': 'MEDIUM'},
    'Wordpress.com':       {'cnames': ['.wordpress.com'],        'fingerprints': ["Do you want to register"],                                                                         'severity': 'MEDIUM'},
    'SmugMug':             {'cnames': ['.domains.smugmug.com'],  'fingerprints': ['Page Not Found'],                                                                                  'severity': 'LOW'},
    'Strikingly':          {'cnames': ['.s.strikinglydns.com'],  'fingerprints': ["But if you're looking to build your own website"],                                                 'severity': 'LOW'},
}

_BUILD_SUBDOMAINS = [
    'www', 'blog', 'docs', 'help', 'shop', 'cdn', 'api', 'status', 'app',
    'dev', 'staging', 'beta', 'portal', 'admin', 'mail', 'support', 'forum',
    'wiki', 'media', 'assets', 'img', 'static', 'jobs', 'careers', 'community',
]

_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def _build_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ['1.1.1.1', '8.8.8.8', '8.8.4.4']
    r.timeout = 5
    r.lifetime = 8
    return r


def _get_crt_sh_subs(target: str) -> set[str]:
    subs: set[str] = set()
    try:
        url = f'https://crt.sh/?q=%.{target}&output=json'
        with httpx.Client(timeout=15, verify=False, headers={'User-Agent': _UA}) as client:
            res = client.get(url)
            if res.status_code == 200:
                for entry in res.json():
                    for line in entry.get('name_value', '').split('\n'):
                        line = line.strip().lower().lstrip('*').lstrip('.')
                        if line.endswith(f'.{target}') and '*' not in line:
                            subs.add(line)
    except Exception:
        pass
    return subs


def _check_subdomain(subdomain: str) -> dict | None:
    resolver = _build_resolver()

    # --- NXDOMAIN / no-A-record check: dangling DNS pointing nowhere ---
    try:
        resolver.resolve(subdomain, 'A')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        # Has a CNAME but no A record — classic dangling DNS setup
        pass
    except dns.exception.Timeout:
        return None
    except Exception:
        return None

    # --- CNAME resolution ---
    cnames: list[str] = []
    try:
        answers = resolver.resolve(subdomain, 'CNAME')
        cnames = [str(r.target).rstrip('.').lower() for r in answers]
    except Exception:
        return None

    if not cnames:
        return None

    for cname in cnames:
        for service, data in TAKEOVER_FINGERPRINTS.items():
            if not any(cname.endswith(c) for c in data['cnames']):
                continue

            # Matched provider CNAME — now verify fingerprint in HTTP response
            fingerprints = data['fingerprints']
            for proto in ('https', 'http'):
                try:
                    with httpx.Client(
                        timeout=8,
                        verify=False,
                        follow_redirects=True,
                        headers={'User-Agent': _UA},
                    ) as client:
                        resp = client.get(f'{proto}://{subdomain}')
                        body = resp.text
                        for fp in fingerprints:
                            if fp.lower() in body.lower():
                                return {
                                    'subdomain': subdomain,
                                    'service': service,
                                    'cname': cname,
                                    'severity': data['severity'],
                                    'fingerprint_matched': fp,
                                    'status_code': resp.status_code,
                                    'proto': proto,
                                }
                except Exception:
                    continue

            # CNAME points to provider but fingerprint check failed — still suspicious
            return {
                'subdomain': subdomain,
                'service': service,
                'cname': cname,
                'severity': data['severity'],
                'fingerprint_matched': None,
                'note': 'CNAME points to provider but response fingerprint not confirmed — manual verification required',
            }

    return None


def run(target: str) -> dict:
    results = {
        'module': 'Ghost Assets',
        'target': target,
        'subdomains_checked': 0,
        'takeovers': [],
        'unconfirmed_candidates': [],
        'findings': [],
        'errors': [],
    }

    subs: set[str] = _get_crt_sh_subs(target)
    for prefix in _BUILD_SUBDOMAINS:
        subs.add(f'{prefix}.{target}')
    subs.discard(target)
    subdomain_list = sorted(subs)
    results['subdomains_checked'] = len(subdomain_list)

    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {executor.submit(_check_subdomain, sub): sub for sub in subdomain_list}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    if result.get('fingerprint_matched'):
                        results['takeovers'].append(result)
                        results['findings'].append(
                            f'[{result["severity"]}] CONFIRMED TAKEOVER: {result["subdomain"]} '
                            f'→ {result["service"]} via {result["cname"]}'
                        )
                    else:
                        results['unconfirmed_candidates'].append(result)
                        results['findings'].append(
                            f'[{result["severity"]}] UNCONFIRMED: {result["subdomain"]} '
                            f'→ {result["service"]} — manual check recommended'
                        )
            except Exception as e:
                results['errors'].append(f'Check failed: {str(e)}')

    results['takeovers'].sort(key=lambda x: _SEVERITY_ORDER.get(x.get('severity', 'LOW'), 99))
    results['findings'].sort()

    confirmed = len(results['takeovers'])
    if confirmed:
        results['findings'].insert(
            0,
            f'{confirmed} CONFIRMED subdomain takeover(s) — immediate remediation required'
        )

    return results
