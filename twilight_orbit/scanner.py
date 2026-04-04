import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from twilight_orbit.modules import dns_lookup, whois_lookup, subdomains, port_scanner, http_headers, ssl_info, tech_detect, geo_lookup, email_harvest, wayback, threat_intel, shodan_vt, wayback_secrets, dom_fingerprint, dependency_chain, ghost_assets

console = Console()
MODULES = {
    'dns':              {'name': 'DNS Lookup',             'description': 'Query DNS records (A, MX, NS, TXT, etc.)',                     'function': dns_lookup.run},
    'whois':            {'name': 'WHOIS Lookup',           'description': 'Domain registration information',                              'function': whois_lookup.run},
    'subdomains':       {'name': 'Subdomain Discovery',    'description': 'Find subdomains via DNS brute-force & crt.sh',                 'function': subdomains.run},
    'ports':            {'name': 'Port Scanner',           'description': 'TCP scan of top 100 ports',                                    'function': port_scanner.run},
    'headers':          {'name': 'HTTP Headers',           'description': 'Security header analysis & grading',                           'function': http_headers.run},
    'ssl':              {'name': 'SSL/TLS Info',           'description': 'Certificate details, ciphers & expiry',                        'function': ssl_info.run},
    'tech':             {'name': 'Tech Detection',         'description': 'Detect web technologies & frameworks',                         'function': tech_detect.run},
    'geo':              {'name': 'IP Geolocation',         'description': 'Locate server IP address & classify network',                  'function': geo_lookup.run},
    'emails':           {'name': 'Email Harvesting',       'description': 'Discover & classify email addresses',                          'function': email_harvest.run},
    'wayback':          {'name': 'Wayback Machine',        'description': 'Internet Archive historical snapshots',                        'function': wayback.run},
    'wayback_secrets':  {'name': 'Wayback Secrets',        'description': 'Hunt leaked secrets in historical archives (33 patterns)',     'function': wayback_secrets.run},
    'dom_fingerprint':  {'name': 'DOM Fingerprint',        'description': 'Headless browser DOM & framework version analysis',            'function': dom_fingerprint.run},
    'dependency_chain': {'name': 'Dependency Chain',       'description': 'Frontend library CVE analysis (semver-aware)',                 'function': dependency_chain.run},
    'threat':           {'name': 'Threat Intelligence',    'description': 'AlienVault OTX, URLScan.io, ThreatFox, HackerTarget APIs',    'function': threat_intel.run},
    'shodan':           {'name': 'Shodan / VT / AbuseIPDB','description': 'Premium APIs (free keys via env vars)',                       'function': shodan_vt.run},
    'ghost_assets':     {'name': 'Ghost Assets',           'description': 'Subdomain takeover scanner (31 providers)',                   'function': ghost_assets.run},
}

DEFAULT_MODULES = [
    'dns', 'whois', 'geo', 'ports', 'headers', 'ssl', 'tech',
    'subdomains', 'emails', 'wayback', 'wayback_secrets',
    'dom_fingerprint', 'dependency_chain', 'threat', 'shodan',
    'ghost_assets',
]

def get_module_list() -> list[str]:
    return list(MODULES.keys())

def run_scan(target: str, modules: list[str] | None=None) -> dict:
    scan_modules = modules or DEFAULT_MODULES
    valid_modules = []
    for mod in scan_modules:
        if mod in MODULES:
            valid_modules.append(mod)
        else:
            console.print(f'  [yellow]⚠ Unknown module: {mod} (skipping)[/yellow]')
    scan_results = {'target': target, 'modules_run': [], 'results': {}, 'start_time': None, 'end_time': None, 'duration': None, 'total_modules': len(valid_modules), 'successful_modules': 0, 'failed_modules': 0}
    start = time.time()
    scan_results['start_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
    console.print()
    with Progress(SpinnerColumn(style='cyan'), TextColumn('[bold blue]{task.description}'), BarColumn(complete_style='green', finished_style='bright_green'), TextColumn('[bold]{task.percentage:>3.0f}%'), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task('Scanning...', total=len(valid_modules))
        for mod_key in valid_modules:
            mod_info = MODULES[mod_key]
            progress.update(task, description=f"  ⟐ {mod_info['name']}...")
            try:
                result = mod_info['function'](target)
                scan_results['results'][mod_key] = result
                scan_results['modules_run'].append(mod_key)
                scan_results['successful_modules'] += 1
            except KeyboardInterrupt:
                console.print("\n  [yellow]⚠ Scan aborted by user (KeyboardInterrupt)[/yellow]")
                break
            except Exception as e:
                import socket
                import httpx
                
                err_msg = str(e)
                if isinstance(e, socket.gaierror) or "getaddrinfo failed" in str(e):
                    err_msg = f"Failed to resolve hostname '{target}'. Ensure the target is a valid domain (e.g. example.com, not example,com)."
                    
                scan_results['results'][mod_key] = {'module': mod_info['name'], 'target': target, 'errors': [f'Module crashed: {err_msg}']}
                scan_results['failed_modules'] += 1
            progress.advance(task)
    end = time.time()
    scan_results['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
    scan_results['duration'] = round(end - start, 2)
    return scan_results