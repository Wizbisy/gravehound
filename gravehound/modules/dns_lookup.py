import dns.resolver
import dns.exception
import httpx
from gravehound import tor
from gravehound.config import DNS_RECORD_TYPES, DEFAULT_DNS_TIMEOUT

_RESOLVERS = ['1.1.1.1', '8.8.8.8', '8.8.4.4', '1.0.0.1', '9.9.9.9']

def _build_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = _RESOLVERS
    resolver.timeout = DEFAULT_DNS_TIMEOUT
    resolver.lifetime = DEFAULT_DNS_TIMEOUT * 2
    return resolver

def _parse_rdata(record_type: str, rdata) -> dict | str:
    if record_type == 'MX':
        return {
            'priority': int(rdata.preference),
            'exchange': str(rdata.exchange).rstrip('.'),
        }
    if record_type == 'SOA':
        return {
            'mname': str(rdata.mname).rstrip('.'),
            'rname': str(rdata.rname).rstrip('.'),
            'serial': int(rdata.serial),
            'refresh': int(rdata.refresh),
            'retry': int(rdata.retry),
            'expire': int(rdata.expire),
            'minimum_ttl': int(rdata.minimum),
        }
    if record_type == 'TXT':
        return ' '.join(part.decode('utf-8', errors='replace') for part in rdata.strings)
    return str(rdata)

def _flag_interesting(record_type: str, records: list) -> list[str]:
    findings = []
    if record_type == 'TXT':
        for rec in records:
            val = str(rec).lower()
            if 'v=spf1' in val:
                if '+all' in val:
                    findings.append('SPF uses +all — allows ANY server to send mail (critical misconfiguration)')
                elif '~all' in val:
                    findings.append('SPF uses ~all softfail — consider upgrading to -all')
            if 'v=dmarc1' in val:
                if 'p=none' in val:
                    findings.append('DMARC policy is p=none — no enforcement, monitoring only')
            if '_domainkey' in val or 'v=dkim1' in val:
                findings.append('DKIM record found')
    if record_type == 'NS':
        for rec in records:
            if any(word in str(rec).lower() for word in ['amazonaws', 'azure', 'cloudflare', 'digitalocean']):
                findings.append(f'Cloud-hosted nameserver: {rec}')
    return findings

def _resolve_via_tor(target: str, record_type: str) -> list:
    proxy_url = tor.get_proxy()
    if not proxy_url:
        return []
        
    try:
        with httpx.Client(proxy=proxy_url, timeout=DEFAULT_DNS_TIMEOUT) as client:
            resp = client.get(
                'https://cloudflare-dns.com/dns-query',
                params={'name': target, 'type': record_type},
                headers={'Accept': 'application/dns-json'}
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get('Answer', [])
                results = []
                for ans in answers:
                    val = ans.get('data', '')
                    if record_type == 'MX':
                        parts = val.split(' ', 1)
                        if len(parts) == 2:
                            results.append({
                                'priority': int(parts[0]),
                                'exchange': parts[1].rstrip('.')
                            })
                    elif record_type == 'TXT':
                        if val.startswith('"') and val.endswith('"'):
                            val = val[1:-1]
                        results.append(val)
                    else:
                        results.append(val.rstrip('.'))
                return results
    except Exception:
        pass
    return []


def run(target: str) -> dict:
    results = {
        'module': 'DNS Lookup',
        'target': target,
        'records': {},
        'findings': [],
        'record_count': 0,
        'errors': [],
    }
    
    use_tor = tor.is_active()
    resolver = None
    if not use_tor:
        resolver = _build_resolver()
        
    domain_exists = True
    for record_type in DNS_RECORD_TYPES:
        if use_tor:
            parsed = _resolve_via_tor(target, record_type)
            if parsed:
                results['records'][record_type] = {
                    'values': parsed,
                    'ttl': None,
                    'count': len(parsed),
                }
                results['record_count'] += len(parsed)
                interesting = _flag_interesting(record_type, parsed)
                results['findings'].extend(interesting)
            continue
            
        try:
            answers = resolver.resolve(target, record_type)
            ttl = answers.rrset.ttl if answers.rrset else None
            parsed = [_parse_rdata(record_type, rdata) for rdata in answers]
            if parsed:
                results['records'][record_type] = {
                    'values': parsed,
                    'ttl': ttl,
                    'count': len(parsed),
                }
                results['record_count'] += len(parsed)
                interesting = _flag_interesting(record_type, parsed)
                results['findings'].extend(interesting)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            if domain_exists:
                results['errors'].append(f'Domain {target} does not exist (NXDOMAIN)')
                domain_exists = False
            break
        except dns.resolver.NoNameservers:
            results['errors'].append(f'No nameservers available for {target}')
            break
        except dns.exception.Timeout:
            results['errors'].append(f'Timeout querying {record_type} record')
        except dns.resolver.LifetimeTimeout:
            results['errors'].append(f'Lifetime timeout querying {record_type} record')
        except Exception as e:
            results['errors'].append(f'Error querying {record_type}: {type(e).__name__}: {str(e)}')
    results['findings'] = list(dict.fromkeys(results['findings']))
    return results
