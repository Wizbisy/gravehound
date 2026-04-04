import datetime
import whois

_PRIVACY_KEYWORDS = [
    'redacted', 'privacy', 'protect', 'withheld', 'not disclosed',
    'data protected', 'gdpr', 'proxy',
]


def _normalize(value) -> list[str] | str | None:
    if value is None:
        return None
    if isinstance(value, list):
        seen = set()
        out = []
        for v in value:
            s = str(v).strip()
            if s and s.lower() not in seen:
                seen.add(s.lower())
                out.append(s)
        return out if out else None
    s = str(value).strip()
    return s if s else None


def _is_privacy_redacted(value: str | None) -> bool:
    if not value:
        return False
    low = value.lower()
    return any(kw in low for kw in _PRIVACY_KEYWORDS)


def _days_until(date_str: str | None) -> int | None:
    if not date_str:
        return None
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            dt = datetime.datetime.strptime(str(date_str).split('+')[0].strip(), fmt)
            return (dt - datetime.datetime.utcnow()).days
        except ValueError:
            continue
    return None


def run(target: str) -> dict:
    results = {
        'module': 'WHOIS Lookup',
        'target': target,
        'data': {},
        'findings': [],
        'errors': [],
    }

    try:
        w = whois.whois(target)

        expiration_raw = _normalize(w.expiration_date)
        expiration_str = expiration_raw[0] if isinstance(expiration_raw, list) else expiration_raw

        creation_raw = _normalize(w.creation_date)
        creation_str = creation_raw[0] if isinstance(creation_raw, list) else creation_raw

        results['data'] = {
            'domain_name': _normalize(w.domain_name),
            'registrar': _normalize(w.registrar),
            'whois_server': _normalize(w.whois_server),
            'creation_date': creation_str,
            'expiration_date': expiration_str,
            'updated_date': _normalize(w.updated_date),
            'name_servers': _normalize(w.name_servers),
            'status': _normalize(w.status),
            'emails': _normalize(w.emails),
            'registrant': _normalize(getattr(w, 'name', None)),
            'organization': _normalize(getattr(w, 'org', None)),
            'country': _normalize(getattr(w, 'country', None)),
            'state': _normalize(getattr(w, 'state', None)),
            'city': _normalize(getattr(w, 'city', None)),
            'dnssec': _normalize(getattr(w, 'dnssec', None)),
        }
        results['data'] = {k: v for k, v in results['data'].items() if v is not None}

        days_left = _days_until(expiration_str)
        if days_left is not None:
            results['data']['days_until_expiry'] = days_left
            if days_left < 0:
                results['findings'].append('Domain has EXPIRED')
            elif days_left < 30:
                results['findings'].append(f'Domain expires in {days_left} days — CRITICAL: renewal required')
            elif days_left < 90:
                results['findings'].append(f'Domain expires in {days_left} days — renewal recommended soon')

        registrar = results['data'].get('registrar', '')
        if registrar and _is_privacy_redacted(str(registrar)):
            results['findings'].append('Registrant protected by WHOIS privacy service')

        dnssec = results['data'].get('dnssec', '')
        if dnssec and 'unsigned' in str(dnssec).lower():
            results['findings'].append('DNSSEC is unsigned — zone is vulnerable to cache poisoning')
        elif not dnssec:
            results['findings'].append('DNSSEC status unknown — could not determine from WHOIS')

        status_val = results['data'].get('status', [])
        if isinstance(status_val, list):
            statuses = [s.lower() for s in status_val]
        else:
            statuses = [str(status_val).lower()]

        if not any('clienttransferprohibited' in s for s in statuses):
            results['findings'].append('clientTransferProhibited lock not set — domain may be vulnerable to hijacking')
        if not any('clientdeleteprohibited' in s for s in statuses):
            results['findings'].append('clientDeleteProhibited lock not set')

    except Exception as e:
        results['errors'].append(f'WHOIS lookup failed: {type(e).__name__}: {str(e)}')

    return results