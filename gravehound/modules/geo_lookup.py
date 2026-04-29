import socket
import httpx
from gravehound import http, tor
from gravehound.config import GEO_API_URL, DEFAULT_TIMEOUT, IPINFO_URL

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'
_CLOUD_ASN_KEYWORDS = ['amazon', 'aws', 'google', 'microsoft', 'azure', 'cloudflare',
                       'fastly', 'akamai', 'digitalocean', 'linode', 'vultr', 'ovh',
                       'hetzner', 'alibaba', 'tencent']
_HOSTING_TYPES = {
    'DataCenter': 'Dedicated datacenter / hosting',
    'ISP': 'Residential or business ISP',
    'CDN': 'Content Delivery Network',
    'Business': 'Business network',
    'Mobile': 'Mobile/cellular network',
    'Educational': 'Educational institution',
    'Government': 'Government network',
}

def _classify_network(isp: str, org: str, asn: str) -> str:
    combined = f'{isp} {org} {asn}'.lower()
    for kw in _CLOUD_ASN_KEYWORDS:
        if kw in combined:
            return 'cloud_provider'
    if any(w in combined for w in ['university', 'college', 'edu', 'school']):
        return 'educational'
    if any(w in combined for w in ['government', 'ministry', 'federal', 'police']):
        return 'government'
    if any(w in combined for w in ['hosting', 'server', 'datacenter', 'data center', 'vps']):
        return 'datacenter'
    return 'unknown'

def run(target: str) -> dict:
    results = {
        'module': 'IP Geolocation',
        'target': target,
        'ip': None,
        'all_ips': [],
        'location': {},
        'network_classification': None,
        'findings': [],
        'errors': [],
    }
    try:
        ip = tor.resolve(target)
        results['ip'] = ip
    except socket.gaierror as e:
        results['errors'].append(f'Could not resolve {target}: {str(e)}')
        return results
    try:
        all_ips = sorted(tor.resolve_all(target)) or [ip]
        results['all_ips'] = all_ips
        if len(all_ips) > 1:
            results['findings'].append(f'Target resolves to {len(all_ips)} IPs — possible load balancer or CDN')
    except Exception:
        results['all_ips'] = [ip]
    headers = {'User-Agent': _UA}
    with http.Client(timeout=DEFAULT_TIMEOUT, headers=headers) as client:
        try:
            url = GEO_API_URL.replace('{ip}', ip)
            response = client.get(url)
            response.raise_for_status()
            data = response.json()
            if data.get('status') == 'success':
                isp = data.get('isp', 'Unknown')
                org = data.get('org', 'Unknown')
                asn = data.get('as', '')
                results['location'] = {
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'zip': data.get('zip', ''),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'timezone': data.get('timezone', ''),
                    'isp': isp,
                    'organization': org,
                    'as_number': asn,
                    'query_ip': data.get('query', ip),
                }
                results['network_classification'] = _classify_network(isp, org, asn)
                if results['network_classification'] == 'cloud_provider':
                    results['findings'].append(f'IP is hosted on a cloud/CDN provider ({isp}) — real origin may be hidden')
            else:
                results['errors'].append(f"ip-api.com: {data.get('message', 'Unknown error')}")
        except httpx.HTTPStatusError as e:
            results['errors'].append(f'ip-api.com HTTP {e.response.status_code}')
        except httpx.TimeoutException:
            results['errors'].append('ip-api.com request timed out')
        except Exception as e:
            results['errors'].append(f'Geolocation error: {type(e).__name__}: {str(e)}')
        if not results['location']:
            try:
                url2 = IPINFO_URL.replace('{ip}', ip)
                resp2 = client.get(url2)
                if resp2.status_code == 200:
                    d = resp2.json()
                    loc_parts = d.get('loc', ',').split(',')
                    results['location'] = {
                        'country': d.get('country', 'Unknown'),
                        'region': d.get('region', 'Unknown'),
                        'city': d.get('city', 'Unknown'),
                        'timezone': d.get('timezone', ''),
                        'isp': d.get('org', 'Unknown'),
                        'organization': d.get('org', 'Unknown'),
                        'latitude': float(loc_parts[0]) if len(loc_parts) == 2 else None,
                        'longitude': float(loc_parts[1]) if len(loc_parts) == 2 else None,
                        'source': 'ipinfo.io_fallback',
                    }
            except Exception as e:
                results['errors'].append(f'ipinfo.io fallback error: {str(e)}')
    return results
