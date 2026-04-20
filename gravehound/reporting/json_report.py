import json
import datetime
from gravehound.config import APP_NAME, APP_VERSION, APP_URL
_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

def _build_findings_index(results: dict) -> list[dict]:
    index: list[dict] = []
    for mod_key, data in results.items():
        if not isinstance(data, dict):
            continue
        module_name = data.get('module', mod_key)
        for finding in data.get('findings', []):
            sev = 'INFO'
            f_lower = str(finding).lower()
            if any(w in f_lower for w in ('critical', 'confirmed takeover', 'expired', 'rce', 'sqli')):
                sev = 'CRITICAL'
            elif any(w in f_lower for w in ('high', 'exposed', 'malicious', 'takeover', 'leaked', 'missing hsts', 'missing csp')):
                sev = 'HIGH'
            elif any(w in f_lower for w in ('medium', 'missing', 'suspicious', 'softfail', 'weak')):
                sev = 'MEDIUM'
            elif any(w in f_lower for w in ('low', 'info', 'disclosed', 'note')):
                sev = 'LOW'
            index.append({'severity': sev, 'module': module_name, 'finding': finding})
        for leak in data.get('leaks_found', []):
            index.append({
                'severity': leak.get('severity', 'MEDIUM'),
                'module': module_name,
                'finding': f'{leak.get("pattern","Secret")} detected: {leak.get("value_redacted","")}',
                'archived_date': leak.get('archived_date', ''),
                'source_urls': leak.get('source_urls', []),
            })
        for t in data.get('takeovers', []):
            index.append({
                'severity': t.get('severity', 'HIGH'),
                'module': module_name,
                'finding': f'Subdomain takeover: {t.get("subdomain")} \u2192 {t.get("service")} (CNAME: {t.get("cname")})',
                'fingerprint': t.get('fingerprint_matched'),
            })
        for v in data.get('vulnerabilities', []):
            if v.get('library'):
                index.append({
                    'severity': v.get('severity', 'MEDIUM'),
                    'module': module_name,
                    'finding': f'{v.get("library")} v{v.get("version")}: {v.get("description")}',
                })
            elif v.get('test_name'):
                index.append({
                    'severity': v.get('severity', 'MEDIUM'),
                    'module': module_name,
                    'finding': f'CORS {v.get("test_name")}: {v.get("detail", "")}',
                    'url': v.get('url', ''),
                    'origin_sent': v.get('origin_sent', ''),
                    'credentials': v.get('acac', False),
                })
        for b in data.get('buckets_found', []):
            index.append({
                'severity': b.get('severity', 'HIGH'),
                'module': module_name,
                'finding': f'Open bucket: {b.get("provider")} \u2014 {b.get("name")}',
                'url': b.get('url', ''),
                'listable': b.get('listable', False),
            })
        for sh in data.get('self_hosted', []):
            index.append({
                'severity': sh.get('severity', 'HIGH'),
                'module': module_name,
                'finding': f'Self-hosted storage: {sh.get("service", sh.get("provider", ""))} at {sh.get("name", "")}',
                'url': sh.get('url', ''),
            })
        for s in data.get('secrets', []):
            index.append({
                'severity': s.get('severity', 'HIGH'),
                'module': module_name,
                'finding': f'{s.get("pattern", "Secret")} in JS: {s.get("value_redacted", "")}',
                'source': s.get('source', ''),
            })
        for e in data.get('exposed', []):
            index.append({
                'severity': e.get('severity', 'MEDIUM'),
                'module': module_name,
                'finding': f'Exposed config: {e.get("path", "")} on {e.get("url", "").split("://")[1].split("/")[0] if "://" in e.get("url", "") else ""}',
                'category': e.get('category', ''),
                'url': e.get('url', ''),
            })
        for rpc in data.get('exposed_rpc', []):
            index.append({
                'severity': rpc.get('severity', 'HIGH'),
                'module': module_name,
                'finding': f'Exposed RPC: {rpc.get("chain_name", "")} at {rpc.get("url", "")}',
                'chain_id': rpc.get('chain_id', ''),
            })
    index.sort(key=lambda x: _SEVERITY_ORDER.get(x.get('severity', 'INFO'), 99))
    return index

def _build_severity_summary(findings_index: list[dict]) -> dict:
    summary: dict[str, int] = {}
    for f in findings_index:
        sev = f.get('severity', 'INFO')
        summary[sev] = summary.get(sev, 0) + 1
    return summary

def _build_assets(results: dict) -> dict:
    """Compact asset inventory extracted from scan results."""
    assets: dict = {}
    geo = results.get('geo', {})
    if geo.get('ip'):
        assets['ip'] = geo['ip']
    if geo.get('all_ips'):
        assets['all_ips'] = geo['all_ips']
    if geo.get('network_classification'):
        assets['network_classification'] = geo['network_classification']
    ssl = results.get('ssl', {})
    cert = ssl.get('certificate', {})
    if cert:
        assets['certificate'] = {
            'common_name': cert.get('subject', {}).get('commonName', ''),
            'issuer': cert.get('issuer', {}).get('organizationName', ''),
            'expiry': cert.get('not_after', ''),
            'days_until_expiry': cert.get('days_until_expiry'),
            'fingerprint_sha256': cert.get('fingerprint_sha256', ''),
            'protocol': cert.get('protocol', ''),
            'san_count': cert.get('san_count', 0),
        }
    subs = results.get('subdomains', {})
    if subs.get('subdomains'):
        assets['subdomains'] = {
            'total': subs.get('total', 0),
            'list': subs.get('subdomains', []),
            'takeover_candidates': subs.get('takeover_candidates', []),
        }
    ports = results.get('ports', {})
    if ports.get('open_ports'):
        assets['open_ports'] = [
            {'port': p['port'], 'service': p['service'], 'banner': p.get('banner', '')[:100]}
            for p in ports['open_ports']
        ]
    tech = results.get('tech', {})
    if tech.get('technologies'):
        assets['technologies'] = tech['technologies']
        assets['tech_categories'] = tech.get('categories', {})
    emails = results.get('emails', {})
    if emails.get('emails'):
        assets['emails'] = emails['emails']
        assets['email_classified'] = emails.get('classified', {})
    whois = results.get('whois', {})
    if whois.get('data'):
        d = whois['data']
        assets['registration'] = {
            'registrar': d.get('registrar', ''),
            'creation_date': d.get('creation_date', ''),
            'expiration_date': d.get('expiration_date', ''),
            'days_until_expiry': d.get('days_until_expiry'),
            'name_servers': d.get('name_servers', []),
            'dnssec': d.get('dnssec', ''),
        }
    return assets

def export(scan_results: dict, output_path: str | None = None) -> str:
    results = scan_results.get('results', {})
    findings_index = _build_findings_index(results)
    report = {
        'meta': {
            'tool': APP_NAME,
            'version': APP_VERSION,
            'url': APP_URL,
            'generated_at': datetime.datetime.utcnow().isoformat() + 'Z',
            'schema_version': '2.0',
        },
        'scan': {
            'target': scan_results.get('target', ''),
            'start_time': scan_results.get('start_time', ''),
            'end_time': scan_results.get('end_time', ''),
            'duration_seconds': scan_results.get('duration', 0),
            'modules_run': scan_results.get('modules_run', []),
            'total_modules': scan_results.get('total_modules', 0),
            'successful_modules': scan_results.get('successful_modules', 0),
            'failed_modules': scan_results.get('failed_modules', 0),
        },
        'summary': {
            'severity_counts': _build_severity_summary(findings_index),
            'total_findings': len(findings_index),
            'risk_level': results.get('threat', {}).get('risk_level', 'UNKNOWN'),
            'risk_score': results.get('threat', {}).get('risk_score', 0),
            'header_grade': results.get('headers', {}).get('grade', ''),
            'open_ports': len(results.get('ports', {}).get('open_ports', [])),
            'subdomains_found': results.get('subdomains', {}).get('total', 0),
            'secrets_found': len(results.get('wayback_secrets', {}).get('leaks_found', [])),
            'takeovers_confirmed': len(results.get('ghost_assets', {}).get('takeovers', [])),
            'vulnerable_dependencies': results.get('dependency_chain', {}).get('vuln_count', 0),
            'open_buckets': len(results.get('cloud_storage', {}).get('buckets_found', [])),
            'self_hosted_storage': len(results.get('cloud_storage', {}).get('self_hosted', [])),
            'js_secrets': len(results.get('js_analyzer', {}).get('secrets', [])),
            'exposed_configs': len(results.get('dotfiles', {}).get('exposed', [])),
            'cors_vulns': len(results.get('cors_check', {}).get('vulnerabilities', [])),
            'exposed_rpc': len(results.get('web3_recon', {}).get('exposed_rpc', [])),
        },
        'findings': findings_index,
        'assets': _build_assets(results),
        'modules': results,
    }
    json_str = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(json_str)
    return json_str
