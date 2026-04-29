import socket
import httpx
from gravehound import http, tor
from gravehound.config import (
    OTX_DOMAIN_URL, OTX_IP_URL, THREATFOX_API_URL,
    HACKERTARGET_REVERSE_DNS, HACKERTARGET_PAGE_LINKS,
    URLSCAN_SEARCH_URL, DEFAULT_TIMEOUT,
)

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'

def _safe_get(client: httpx.Client, url: str) -> httpx.Response | None:
    try:
        return client.get(url)
    except httpx.TimeoutException:
        return None
    except httpx.HTTPError:
        return None
    except Exception:
        return None

def _safe_post(client: httpx.Client, url: str, **kwargs) -> httpx.Response | None:
    try:
        return client.post(url, **kwargs)
    except Exception:
        return None

def _query_otx(target: str, client: httpx.Client) -> dict:
    out = {'pulses': 0, 'reputation': None, 'tags': [], 'references': [], 'malware_families': []}
    try:
        resp = _safe_get(client, OTX_DOMAIN_URL.replace('{domain}', target))
        if resp and resp.status_code == 200:
            data = resp.json()
            pulse_info = data.get('pulse_info', {})
            out['pulses'] = pulse_info.get('count', 0)
            out['reputation'] = data.get('reputation', 0)
            out['alexa_rank'] = data.get('alexa', 'N/A')
            tags: set[str] = set()
            refs: set[str] = set()
            malware: set[str] = set()
            for pulse in pulse_info.get('pulses', [])[:10]:
                tags.update(pulse.get('tags', []))
                refs.update(pulse.get('references', [])[:3])
                for mf in pulse.get('malware_families', []):
                    if mf:
                        malware.add(str(mf))
            out['tags'] = sorted(tags)[:20]
            out['references'] = sorted(refs)[:10]
            out['malware_families'] = sorted(malware)
    except Exception:
        pass
    return out

def _query_urlscan(target: str, client: httpx.Client) -> list:
    scans = []
    try:
        resp = _safe_get(client, URLSCAN_SEARCH_URL.replace('{domain}', target))
        if resp and resp.status_code == 200:
            data = resp.json()
            for result in data.get('results', [])[:5]:
                page = result.get('page', {})
                task = result.get('task', {})
                uid = result.get('_id', '')
                scans.append({
                    'url': page.get('url', ''),
                    'domain': page.get('domain', ''),
                    'ip': page.get('ip', ''),
                    'server': page.get('server', ''),
                    'country': page.get('country', ''),
                    'asn': page.get('asn', ''),
                    'asnname': page.get('asnname', ''),
                    'scan_date': task.get('time', ''),
                    'report_url': f'https://urlscan.io/result/{uid}/',
                    'screenshot': f'https://urlscan.io/screenshots/{uid}.png',
                })
    except Exception:
        pass
    return scans

def _query_threatfox(target: str, client: httpx.Client) -> dict:
    out = {'iocs': [], 'is_malicious': False, 'threat_types': set()}
    try:
        resp = _safe_post(
            client, THREATFOX_API_URL,
            json={'query': 'search_ioc', 'search_term': target},
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get('query_status') == 'ok':
                iocs = data.get('data', [])
                if iocs:
                    out['is_malicious'] = True
                    for ioc in iocs[:10]:
                        threat_type = ioc.get('threat_type', '')
                        out['threat_types'].add(threat_type)
                        out['iocs'].append({
                            'ioc': ioc.get('ioc', ''),
                            'threat_type': threat_type,
                            'malware': ioc.get('malware_printable', ''),
                            'confidence': ioc.get('confidence_level', 0),
                            'first_seen': ioc.get('first_seen_utc', ''),
                            'reporter': ioc.get('reporter', ''),
                        })
                    out['threat_types'] = sorted(out['threat_types'])
    except Exception:
        pass
    return out

def _query_reverse_dns(ip: str, client: httpx.Client) -> list[str]:
    domains: list[str] = []
    try:
        resp = _safe_get(client, HACKERTARGET_REVERSE_DNS.replace('{ip}', ip))
        if resp and resp.status_code == 200 and 'error' not in resp.text.lower():
            for line in resp.text.strip().splitlines():
                line = line.strip()
                if line and 'API count' not in line and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 2:
                        domains.append(parts[1].strip())
                elif line and 'API count' not in line:
                    domains.append(line)
    except Exception:
        pass
    return domains[:30]

def _query_page_links(target: str, client: httpx.Client) -> dict:
    internal: list[str] = []
    external: list[str] = []
    try:
        resp = _safe_get(client, HACKERTARGET_PAGE_LINKS.replace('{target}', target))
        if resp and resp.status_code == 200 and 'error' not in resp.text.lower():
            for line in resp.text.strip().splitlines():
                line = line.strip()
                if not line or 'API count' in line:
                    continue
                if not line.startswith('http'):
                    continue
                if target in line:
                    internal.append(line)
                else:
                    external.append(line)
    except Exception:
        pass
    return {'internal': internal[:20], 'external': external[:20]}

def run(target: str) -> dict:
    results = {
        'module': 'Threat Intelligence',
        'target': target,
        'risk_level': 'UNKNOWN',
        'risk_score': 0,
        'otx': {},
        'urlscan': [],
        'threatfox': {},
        'reverse_dns': [],
        'page_links': {'internal': [], 'external': []},
        'findings': [],
        'errors': [],
    }
    ip = None
    try:
        ip = tor.resolve(target)
    except Exception:
        results['errors'].append(f'Could not resolve {target} to IP')
    with http.Client(timeout=DEFAULT_TIMEOUT, headers={'User-Agent': _UA}) as client:
        try:
            results['otx'] = _query_otx(target, client)
        except Exception as e:
            results['errors'].append(f'OTX error: {str(e)}')
        try:
            results['urlscan'] = _query_urlscan(target, client)
        except Exception as e:
            results['errors'].append(f'URLScan error: {str(e)}')
        try:
            results['threatfox'] = _query_threatfox(target, client)
        except Exception as e:
            results['errors'].append(f'ThreatFox error: {str(e)}')
        if ip:
            try:
                results['reverse_dns'] = _query_reverse_dns(ip, client)
            except Exception as e:
                results['errors'].append(f'Reverse DNS error: {str(e)}')
        try:
            results['page_links'] = _query_page_links(target, client)
        except Exception as e:
            results['errors'].append(f'Page links error: {str(e)}')
    risk_score = 0
    if results['threatfox'].get('is_malicious'):
        risk_score += 5
        threat_types = results['threatfox'].get('threat_types', [])
        results['findings'].append(
            f'ThreatFox: listed as malicious — threat types: {", ".join(threat_types) or "unknown"}'
        )
    otx_pulses = results['otx'].get('pulses', 0)
    otx_malware = results['otx'].get('malware_families', [])
    if otx_pulses > 10:
        risk_score += 3
        results['findings'].append(f'OTX: {otx_pulses} threat pulses — high exposure')
    elif otx_pulses > 0:
        risk_score += 1
        results['findings'].append(f'OTX: {otx_pulses} threat pulse(s)')
    if otx_malware:
        risk_score += 2
        results['findings'].append(f'Associated malware families: {", ".join(otx_malware)}')
    if ip and results['reverse_dns']:
        n = len(results['reverse_dns'])
        if n > 50:
            risk_score += 1
            results['findings'].append(f'{n} reverse-DNS neighbours — may be shared hosting or botnet infra')
    results['risk_score'] = risk_score
    if risk_score >= 5:
        results['risk_level'] = 'HIGH'
    elif risk_score >= 3:
        results['risk_level'] = 'MEDIUM'
    elif risk_score >= 1:
        results['risk_level'] = 'LOW'
    else:
        results['risk_level'] = 'CLEAN'
    return results
