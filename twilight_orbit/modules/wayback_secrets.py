import httpx
import re
import urllib.parse
from twilight_orbit.config import DEFAULT_TIMEOUT

SECRETS_REGEX = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Stripe Key': r'(?:sk_live|rk_live)_[0-9a-zA-Z]{24}',
    'RSA Private Key': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
    'Generic Secret': r'(?i)(?:password|api_key|token|secret)[^a-zA-Z0-9]{1,4}?[=\:]\s*[\'"]?([A-Za-z0-9\-_]{16,64})[\'"]?'
}

TARGET_EXTENSIONS = ('.js', '.json', '.txt', '.env', '.sql', '.xml', '.yml', '.yaml', '.ini', '.conf', '.config', '.bak', '.log')

def _fetch_cdx_urls(target: str) -> list[str]:
    urls = []
    try:
        cdx_url = f'https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&limit=1000&fl=original,timestamp,statuscode&collapse=urlkey'
        with httpx.Client(timeout=15) as client:
            response = client.get(cdx_url)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    headers = data[0]
                    for row in data[1:]:
                        entry = dict(zip(headers, row))
                        original_url = entry.get('original', '')
                        parsed = urllib.parse.urlparse(original_url)
                        if any(parsed.path.lower().endswith(ext) for ext in TARGET_EXTENSIONS):
                            if entry.get('statuscode') == '200':
                                ts = entry.get('timestamp')
                                archive_url = f"https://web.archive.org/web/{ts}id_/{original_url}"
                                urls.append(archive_url)
    except Exception:
        pass
    return urls

def run(target: str) -> dict:
    results = {
        'module': 'Wayback Secrets',
        'target': target,
        'leaks_found': [],
        'urls_scanned': 0,
        'errors': []
    }
    
    urls = _fetch_cdx_urls(target)
    
    def priority(u):
        lower_u = u.lower()
        if any(ext in lower_u for ext in ['.env', '.yml', '.ini', '.bak', '.sql', '.conf', '.config']):
            return 0
        if '.json' in lower_u or '.xml' in lower_u:
            return 1
        return 2
        
    urls = sorted(urls, key=priority)[:20]
    results['urls_scanned'] = len(urls)

    if not urls:
        return results

    with httpx.Client(timeout=10, verify=False) as client:
        for archive_url in urls:
            try:
                resp = client.get(archive_url)
                if resp.status_code == 200:
                    text = resp.text
                    for secret_name, pattern in SECRETS_REGEX.items():
                        matches = re.findall(pattern, text)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            if not match or len(match) > 100:
                                continue
                            
                            display_val = match[:20] + '...' if len(match) > 20 else match[:5] + '***'
                            
                            leak = {
                                'type': secret_name,
                                'value': display_val,
                                'source_url': archive_url
                            }
                            if leak not in results['leaks_found']:
                                results['leaks_found'].append(leak)
            except Exception as e:
                continue

    return results
