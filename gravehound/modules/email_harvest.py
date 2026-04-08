import re
import os
import httpx
from gravehound.config import DEFAULT_TIMEOUT, HUNTER_API_URL

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'
_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_SCRAPE_PATHS = [
    '', '/contact', '/about', '/about-us', '/contact-us', '/team', '/people',
    '/privacy', '/privacy-policy', '/security', '/security.txt', '/.well-known/security.txt',
    '/humans.txt', '/sitemap.xml',
]
_COMMON_PREFIXES = [
    'info', 'admin', 'contact', 'support', 'hello', 'sales', 'webmaster',
    'security', 'abuse', 'noreply', 'noc', 'postmaster', 'billing',
    'help', 'careers', 'jobs', 'press', 'media', 'legal', 'privacy',
]
_DISPOSABLE_DOMAINS = {'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email'}

def _extract_emails(text: str, domain: str) -> set[str]:
    all_emails = set(_EMAIL_RE.findall(text.lower()))
    return {e for e in all_emails if domain.lower() in e and len(e) <= 254}

def _classify_email(email: str) -> str:
    local = email.split('@')[0].lower()
    domain = email.split('@')[1].lower() if '@' in email else ''
    if domain in _DISPOSABLE_DOMAINS:
        return 'disposable'
    if local in ('security', 'abuse', 'noc', 'postmaster'):
        return 'operational'
    if local in ('admin', 'webmaster', 'root'):
        return 'administrative'
    if local in ('sales', 'billing', 'support', 'hello', 'info', 'contact'):
        return 'business'
    if local in ('noreply', 'no-reply', 'donotreply'):
        return 'automated'
    return 'personal_or_role'

def _scrape_website(target: str) -> set[str]:
    found: set[str] = set()
    with httpx.Client(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=True,
        verify=False,
        headers={'User-Agent': _UA},
    ) as client:
        for path in _SCRAPE_PATHS:
            for proto in ('https', 'http'):
                try:
                    url = f'{proto}://{target}{path}'
                    resp = client.get(url)
                    if resp.status_code == 200:
                        found.update(_extract_emails(resp.text, target))
                        break
                except Exception:
                    continue
    return found

def run(target: str) -> dict:
    results = {
        'module': 'Email Harvesting',
        'target': target,
        'emails': [],
        'classified': {},
        'common_patterns': [f'{p}@{target}' for p in _COMMON_PREFIXES],
        'total': 0,
        'sources': {'website': [], 'hunter': []},
        'errors': [],
    }
    discovered: set[str] = set()
    try:
        web_emails = _scrape_website(target)
        discovered.update(web_emails)
        results['sources']['website'] = sorted(web_emails)
    except Exception as e:
        results['errors'].append(f'Website scraping error: {type(e).__name__}: {str(e)}')
    hunter_key = os.getenv('HUNTER_API_KEY')
    if hunter_key:
        try:
            url = HUNTER_API_URL.replace('{target}', target).replace('{api_key}', hunter_key)
            with httpx.Client(timeout=10, verify=False, headers={'User-Agent': _UA}) as client:
                res = client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    hunter_emails = [
                        e.get('value', '') for e in data.get('data', {}).get('emails', [])
                        if e.get('value')
                    ]
                    discovered.update(hunter_emails)
                    results['sources']['hunter'] = sorted(hunter_emails)
                elif res.status_code == 401:
                    results['errors'].append('Hunter.io API key is invalid')
                elif res.status_code == 429:
                    results['errors'].append('Hunter.io rate limit exceeded')
                else:
                    results['errors'].append(f'Hunter.io returned HTTP {res.status_code}')
        except Exception as e:
            results['errors'].append(f'Hunter.io error: {type(e).__name__}: {str(e)}')
    classified: dict[str, list[str]] = {}
    for email in sorted(discovered):
        cat = _classify_email(email)
        classified.setdefault(cat, []).append(email)
    results['emails'] = sorted(discovered)
    results['classified'] = classified
    results['total'] = len(discovered)
    return results
