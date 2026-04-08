import os
import socket
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from gravehound.config import DEFAULT_TIMEOUT

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'

def _query_shodan(ip: str, api_key: str) -> dict:
    data: dict = {'available': True, 'ip': ip}
    try:
        url = f'https://api.shodan.io/shodan/host/{ip}?key={api_key}'
        with httpx.Client(timeout=DEFAULT_TIMEOUT, headers={'User-Agent': _UA}) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                result = resp.json()
                data['organization'] = result.get('org', '')
                data['os'] = result.get('os') or 'Unknown'
                data['ports'] = sorted(result.get('ports', []))
                data['hostnames'] = result.get('hostnames', [])
                data['country'] = result.get('country_name', '')
                data['city'] = result.get('city', '')
                data['isp'] = result.get('isp', '')
                data['asn'] = result.get('asn', '')
                data['last_update'] = result.get('last_update', '')
                vulns = result.get('vulns', [])
                data['vulns'] = list(vulns) if isinstance(vulns, (list, dict)) else []
                data['vuln_count'] = len(data['vulns'])
                services = []
                for item in result.get('data', [])[:15]:
                    svc = {
                        'port': item.get('port', 0),
                        'transport': item.get('transport', 'tcp'),
                        'product': item.get('product', ''),
                        'version': item.get('version', ''),
                        'cpe': item.get('cpe', ''),
                        'banner': (item.get('data', '') or '')[:200].strip(),
                    }
                    services.append(svc)
                data['services'] = services
                tags = result.get('tags', [])
                data['tags'] = list(tags) if tags else []
            elif resp.status_code == 401:
                data['error'] = 'Invalid Shodan API key'
            elif resp.status_code == 404:
                data['note'] = 'No Shodan data for this IP (not yet indexed)'
            else:
                data['error'] = f'Shodan returned HTTP {resp.status_code}'
    except httpx.TimeoutException:
        data['error'] = 'Shodan API request timed out'
    except Exception as e:
        data['error'] = f'{type(e).__name__}: {str(e)}'
    return data

def _query_virustotal(target: str, api_key: str) -> dict:
    data: dict = {'available': True}
    try:
        url = f'https://www.virustotal.com/api/v3/domains/{target}'
        with httpx.Client(timeout=DEFAULT_TIMEOUT, headers={'x-apikey': api_key, 'User-Agent': _UA}) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                result = resp.json()
                attrs = result.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                data.update({
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_engines': sum(stats.values()),
                    'reputation': attrs.get('reputation', 0),
                    'categories': attrs.get('categories', {}),
                    'registrar': attrs.get('registrar', ''),
                    'whois': (attrs.get('whois', '') or '')[:500],
                    'last_analysis_date': attrs.get('last_analysis_date', ''),
                    'creation_date': attrs.get('creation_date', ''),
                    'popularity_rank': attrs.get('popularity_ranks', {}),
                })
                if malicious > 5:
                    data['verdict'] = 'MALICIOUS'
                elif malicious > 0 or suspicious > 2:
                    data['verdict'] = 'SUSPICIOUS'
                elif malicious > 0 or suspicious > 0:
                    data['verdict'] = 'POSSIBLY_SUSPICIOUS'
                else:
                    data['verdict'] = 'CLEAN'
            elif resp.status_code == 401:
                data['error'] = 'Invalid VirusTotal API key'
            elif resp.status_code == 429:
                data['error'] = 'VirusTotal rate limit exceeded — consider upgrading API plan'
            else:
                data['error'] = f'VirusTotal returned HTTP {resp.status_code}'
    except httpx.TimeoutException:
        data['error'] = 'VirusTotal request timed out'
    except Exception as e:
        data['error'] = f'{type(e).__name__}: {str(e)}'
    return data

def _query_abuseipdb(ip: str, api_key: str) -> dict:
    data: dict = {'available': True, 'ip': ip}
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': api_key, 'Accept': 'application/json', 'User-Agent': _UA}
        params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True}
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            resp = client.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                result = resp.json().get('data', {})
                score = result.get('abuseConfidenceScore', 0)
                data.update({
                    'is_public': result.get('isPublic', True),
                    'abuse_confidence_score': score,
                    'country': result.get('countryCode', ''),
                    'isp': result.get('isp', ''),
                    'domain': result.get('domain', ''),
                    'is_tor': result.get('isTor', False),
                    'total_reports': result.get('totalReports', 0),
                    'last_reported': result.get('lastReportedAt', ''),
                    'usage_type': result.get('usageType', ''),
                    'verdict': 'HIGH_RISK' if score >= 75 else ('MEDIUM_RISK' if score >= 25 else 'LOW_RISK'),
                })
                reports = result.get('reports', [])[:5]
                data['recent_reports'] = [
                    {
                        'reported_at': r.get('reportedAt', ''),
                        'comment': (r.get('comment', '') or '')[:200],
                        'categories': r.get('categories', []),
                    }
                    for r in reports
                ]
            elif resp.status_code == 401:
                data['error'] = 'Invalid AbuseIPDB API key'
            elif resp.status_code == 429:
                data['error'] = 'AbuseIPDB rate limit exceeded'
            else:
                data['error'] = f'AbuseIPDB returned HTTP {resp.status_code}'
    except httpx.TimeoutException:
        data['error'] = 'AbuseIPDB request timed out'
    except Exception as e:
        data['error'] = f'{type(e).__name__}: {str(e)}'
    return data

def run(target: str) -> dict:
    results = {
        'module': 'Shodan / VirusTotal / AbuseIPDB',
        'target': target,
        'shodan': {},
        'virustotal': {},
        'abuseipdb': {},
        'api_keys_configured': [],
        'findings': [],
        'errors': [],
    }
    shodan_key = os.environ.get('SHODAN_API_KEY')
    vt_key = os.environ.get('VIRUSTOTAL_API_KEY')
    abuse_key = os.environ.get('ABUSEIPDB_API_KEY')
    if shodan_key:
        results['api_keys_configured'].append('Shodan')
    else:
        results['shodan'] = {'available': False, 'note': 'Set SHODAN_API_KEY in .env for Shodan data'}
    if vt_key:
        results['api_keys_configured'].append('VirusTotal')
    else:
        results['virustotal'] = {'available': False, 'note': 'Set VIRUSTOTAL_API_KEY in .env for VirusTotal data'}
    if abuse_key:
        results['api_keys_configured'].append('AbuseIPDB')
    else:
        results['abuseipdb'] = {'available': False, 'note': 'Set ABUSEIPDB_API_KEY in .env for AbuseIPDB data'}
    ip = None
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        results['errors'].append(f'Could not resolve {target}')
    tasks = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        if ip and shodan_key:
            tasks['shodan'] = executor.submit(_query_shodan, ip, shodan_key)
        if vt_key:
            tasks['virustotal'] = executor.submit(_query_virustotal, target, vt_key)
        if ip and abuse_key:
            tasks['abuseipdb'] = executor.submit(_query_abuseipdb, ip, abuse_key)
        for key, future in tasks.items():
            try:
                results[key] = future.result()
            except Exception as e:
                results['errors'].append(f'{key} error: {str(e)}')
    vt = results.get('virustotal', {})
    if vt.get('verdict') in ('MALICIOUS', 'SUSPICIOUS'):
        results['findings'].append(
            f'VirusTotal verdict: {vt["verdict"]} — {vt.get("malicious", 0)} engine(s) flagged'
        )
    shodan = results.get('shodan', {})
    if shodan.get('vulns'):
        results['findings'].append(
            f'Shodan: {shodan["vuln_count"]} CVE(s) associated — {", ".join(list(shodan["vulns"])[:5])}'
        )
    if 'honeypot' in shodan.get('tags', []):
        results['findings'].append('Shodan tags this IP as a honeypot')
    abuse = results.get('abuseipdb', {})
    score = abuse.get('abuse_confidence_score', 0)
    if score >= 25:
        results['findings'].append(
            f'AbuseIPDB: confidence score {score}% — {abuse.get("total_reports", 0)} report(s)'
        )
    if abuse.get('is_tor'):
        results['findings'].append('IP is a Tor exit node (AbuseIPDB)')
    return results
