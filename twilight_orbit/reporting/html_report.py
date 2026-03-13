import json
from datetime import datetime
from twilight_orbit.config import APP_VERSION

def export(scan_results: dict, output_path: str) -> str:
    target = scan_results.get('target', 'Unknown')
    duration = scan_results.get('duration', 0)
    start_time = scan_results.get('start_time', '')
    results = scan_results.get('results', {})
    html = f"""<!DOCTYPE html>\n<html lang="en">\n<head>\n    <meta charset="UTF-8">\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <title>Twilight Orbit: Scan Report: {target}</title>\n    <style>\n        * {{ margin: 0; padding: 0; box-sizing: border-box; }}\n        \n        body {{\n            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;\n            background: #0a0e17;\n            color: #e0e0e0;\n            line-height: 1.6;\n        }}\n        \n        .container {{\n            max-width: 1100px;\n            margin: 0 auto;\n            padding: 2rem;\n        }}\n        \n        /* Header */\n        .header {{\n            text-align: center;\n            padding: 3rem 0;\n            border-bottom: 1px solid #1a2035;\n            margin-bottom: 2rem;\n        }}\n        \n        .header h1 {{\n            font-size: 2.5rem;\n            margin-bottom: 0.5rem;\n            display: flex;\n            align-items: center;\n            justify-content: center;\n            gap: 0.5rem;\n        }}\n        \n        .header h1 .gradient-text {{\n            background: linear-gradient(135deg, #00d4ff, #7b2ff7);\n            -webkit-background-clip: text;\n            -webkit-text-fill-color: transparent;\n        }}\n        \n        .header .tagline {{\n            color: #6b7280;\n            font-size: 1.1rem;\n        }}\n        \n        /* Summary card */\n        .summary-card {{\n            background: linear-gradient(135deg, #111827, #1a2035);\n            border: 1px solid #2a3050;\n            border-radius: 12px;\n            padding: 2rem;\n            margin-bottom: 2rem;\n            display: grid;\n            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));\n            gap: 1.5rem;\n        }}\n        \n        .summary-item {{\n            text-align: center;\n        }}\n        \n        .summary-item .label {{\n            color: #6b7280;\n            font-size: 0.85rem;\n            text-transform: uppercase;\n            letter-spacing: 1px;\n        }}\n        \n        .summary-item .value {{\n            font-size: 1.5rem;\n            font-weight: bold;\n            color: #00d4ff;\n            margin-top: 0.3rem;\n        }}\n        \n        /* Sections */\n        .section {{\n            background: #111827;\n            border: 1px solid #1e293b;\n            border-radius: 12px;\n            margin-bottom: 1.5rem;\n            overflow: hidden;\n        }}\n        \n        .section-header {{\n            background: linear-gradient(135deg, #1a2035, #0f172a);\n            padding: 1.2rem 1.5rem;\n            border-bottom: 1px solid #1e293b;\n            cursor: pointer;\n            display: flex;\n            align-items: center;\n            gap: 0.8rem;\n        }}\n        \n        .section-header:hover {{\n            background: linear-gradient(135deg, #1e2842, #131d32);\n        }}\n        \n        .section-header h2 {{\n            font-size: 1.2rem;\n            color: #f0f0f0;\n        }}\n        \n        .section-header .icon {{\n            font-size: 1.3rem;\n        }}\n        \n        .section-body {{\n            padding: 1.5rem;\n        }}\n        \n        /* Tables */\n        table {{\n            width: 100%;\n            border-collapse: collapse;\n        }}\n        \n        th {{\n            text-align: left;\n            padding: 0.8rem 1rem;\n            background: #0d1117;\n            color: #00d4ff;\n            font-size: 0.85rem;\n            text-transform: uppercase;\n            letter-spacing: 0.5px;\n            border-bottom: 2px solid #1e293b;\n        }}\n        \n        td {{\n            padding: 0.7rem 1rem;\n            border-bottom: 1px solid #1e293b;\n            font-size: 0.95rem;\n        }}\n        \n        tr:hover td {{\n            background: #0d1117;\n        }}\n        \n        /* Status badges */\n        .badge {{\n            display: inline-block;\n            padding: 0.2rem 0.6rem;\n            border-radius: 4px;\n            font-size: 0.8rem;\n            font-weight: 600;\n        }}\n        \n        .badge-green {{ background: #064e3b; color: #34d399; }}\n        .badge-red {{ background: #450a0a; color: #f87171; }}\n        .badge-yellow {{ background: #422006; color: #fbbf24; }}\n        .badge-blue {{ background: #0c2d48; color: #60a5fa; }}\n        \n        /* Footer */\n        .footer {{\n            text-align: center;\n            padding: 2rem 0;\n            color: #4b5563;\n            font-size: 0.85rem;\n            border-top: 1px solid #1a2035;\n            margin-top: 2rem;\n        }}\n        \n        .footer a {{\n            color: #7b2ff7;\n            text-decoration: none;\n        }}\n\n        /* Tags */\n        .tag {{\n            display: inline-block;\n            background: #1e293b;\n            color: #94a3b8;\n            padding: 0.2rem 0.5rem;\n            border-radius: 4px;\n            font-size: 0.8rem;\n            margin: 0.15rem;\n        }}\n\n        .no-data {{\n            color: #6b7280;\n            font-style: italic;\n            padding: 1rem;\n        }}\n        \n        .error {{\n            color: #f87171;\n            padding: 0.5rem;\n        }}\n    </style>\n</head>\n<body>\n    <div class="container">\n        <div class="header">\n            <h1><span style="color: initial; -webkit-text-fill-color: initial;">🌑</span> <span class="gradient-text">Twilight Orbit</span></h1>\n            <p class="tagline">Automated OSINT Recon Report</p>\n        </div>\n        \n        <div class="summary-card">\n            <div class="summary-item">\n                <div class="label">Target</div>\n                <div class="value">{target}</div>\n            </div>\n            <div class="summary-item">\n                <div class="label">Scan Duration</div>\n                <div class="value">{duration}s</div>\n            </div>\n            <div class="summary-item">\n                <div class="label">Modules Run</div>\n                <div class="value">{scan_results.get('successful_modules', 0)}</div>\n            </div>\n            <div class="summary-item">\n                <div class="label">Scan Date</div>\n                <div class="value" style="font-size: 1rem;">{start_time}</div>\n            </div>\n        </div>\n"""
    dns = results.get('dns', {})
    if dns:
        html += _section('🔍', 'DNS Records', _render_dns(dns))
    whois = results.get('whois', {})
    if whois:
        html += _section('📋', 'WHOIS Information', _render_whois(whois))
    geo = results.get('geo', {})
    if geo:
        html += _section('🌍', 'IP Geolocation', _render_geo(geo))
    ports = results.get('ports', {})
    if ports:
        html += _section('🔓', 'Open Ports', _render_ports(ports))
    headers = results.get('headers', {})
    if headers:
        html += _section('🛡️', 'HTTP Security Headers', _render_headers(headers))
    ssl_data = results.get('ssl', {})
    if ssl_data:
        html += _section('🔒', 'SSL/TLS Certificate', _render_ssl(ssl_data))
    tech = results.get('tech', {})
    if tech:
        html += _section('⚙️', 'Technologies Detected', _render_tech(tech))
    subs = results.get('subdomains', {})
    if subs:
        html += _section('🌐', 'Subdomains', _render_subdomains(subs))
    emails = results.get('emails', {})
    if emails:
        html += _section('📧', 'Email Addresses', _render_emails(emails))
    wayback = results.get('wayback', {})
    if wayback:
        html += _section('🕰️', 'Wayback Machine', _render_wayback(wayback))
    threat = results.get('threat', {})
    if threat:
        html += _section('🚨', 'Threat Intelligence', _render_threat(threat))
    shodan = results.get('shodan', {})
    if shodan:
        html += _section('🔎', 'Shodan / VirusTotal / AbuseIPDB', _render_shodan(shodan))
    wayback_secrets = results.get('wayback_secrets', {})
    if wayback_secrets:
        html += _section('🗝️', 'Wayback Secrets', _render_wayback_secrets(wayback_secrets))
    dom = results.get('dom_fingerprint', {})
    if dom:
        html += _section('🖥️', 'DOM Fingerprint', _render_dom_fingerprint(dom))
    deps = results.get('dependency_chain', {})
    if deps:
        html += _section('🔗', 'Dependency Chain', _render_dependency_chain(deps))
    ghost = results.get('ghost_assets', {})
    if ghost:
        html += _section('👻', 'Ghost Assets', _render_ghost_assets(ghost))
    html += f'\n        <div class="footer">\n            Generated by <a href="https://github.com/WIzbisy/twilight-orbit">Twilight Orbit</a> v{APP_VERSION}<br>\n            ⚠️ For authorized security testing only\n        </div>\n    </div>\n</body>\n</html>'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return output_path

def _section(icon: str, title: str, content: str) -> str:
    return f'\n        <div class="section">\n            <div class="section-header">\n                <span class="icon">{icon}</span>\n                <h2>{title}</h2>\n            </div>\n            <div class="section-body">\n                {content}\n            </div>\n        </div>\n    '

def _render_errors(data: dict) -> str:
    errors = data.get('errors', [])
    if errors:
        return ''.join((f'<p class="error">⚠ {e}</p>' for e in errors))
    return ''

def _render_dns(data: dict) -> str:
    errors = _render_errors(data)
    records = data.get('records', {})
    if not records:
        return errors + '<p class="no-data">No DNS records found</p>'
    rows = ''
    for rtype, values in records.items():
        for val in values:
            if isinstance(val, dict):
                val_str = ' | '.join((f'{k}={v}' for k, v in val.items()))
            else:
                val_str = str(val)
            rows += f"<tr><td><span class='badge badge-blue'>{rtype}</span></td><td>{val_str}</td></tr>"
    return errors + f'\n        <table>\n            <thead><tr><th>Type</th><th>Value</th></tr></thead>\n            <tbody>{rows}</tbody>\n        </table>\n    '

def _render_whois(data: dict) -> str:
    errors = _render_errors(data)
    info = data.get('data', {})
    if not info:
        return errors + '<p class="no-data">No WHOIS data available</p>'
    rows = ''
    for key, value in info.items():
        display_key = key.replace('_', ' ').title()
        if isinstance(value, list):
            display_val = ', '.join((str(v) for v in value))
        else:
            display_val = str(value)
        rows += f'<tr><td><strong>{display_key}</strong></td><td>{display_val}</td></tr>'
    return errors + f'\n        <table>\n            <thead><tr><th>Field</th><th>Value</th></tr></thead>\n            <tbody>{rows}</tbody>\n        </table>\n    '

def _render_geo(data: dict) -> str:
    errors = _render_errors(data)
    ip = data.get('ip', '')
    loc = data.get('location', {})
    if not loc:
        return errors + '<p class="no-data">No geolocation data</p>'
    rows = ''
    fields = [('Country', 'country'), ('Region', 'region'), ('City', 'city'), ('ZIP', 'zip'), ('Latitude', 'latitude'), ('Longitude', 'longitude'), ('Timezone', 'timezone'), ('ISP', 'isp'), ('Organization', 'organization'), ('AS Number', 'as_number')]
    for label, key in fields:
        val = loc.get(key)
        if val is not None:
            rows += f'<tr><td><strong>{label}</strong></td><td>{val}</td></tr>'
    return errors + f'\n        <p style="color: #6b7280; margin-bottom: 1rem;">IP: {ip}</p>\n        <table>\n            <thead><tr><th>Field</th><th>Value</th></tr></thead>\n            <tbody>{rows}</tbody>\n        </table>\n    '

def _render_ports(data: dict) -> str:
    errors = _render_errors(data)
    open_ports = data.get('open_ports', [])
    if not open_ports:
        return errors + '<p class="no-data">No open ports found</p>'
    rows = ''
    for p in open_ports:
        rows += f"""<tr>\n            <td><strong>{p['port']}</strong></td>\n            <td><span class="badge badge-green">{p['state']}</span></td>\n            <td>{p['service']}</td>\n            <td style="color: #6b7280;">{p.get('banner', '')[:80]}</td>\n        </tr>"""
    return errors + f'\n        <table>\n            <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr></thead>\n            <tbody>{rows}</tbody>\n        </table>\n    '

def _render_headers(data: dict) -> str:
    errors = _render_errors(data)
    score = data.get('score', 0)
    max_score = data.get('max_score', 0)
    analysis = data.get('security_analysis', [])
    ratio = score / max_score if max_score > 0 else 0
    score_class = 'badge-green' if ratio >= 0.75 else 'badge-yellow' if ratio >= 0.5 else 'badge-red'
    rows = ''
    for item in analysis:
        status = '<span class="badge badge-green">✓ Set</span>' if item['present'] else '<span class="badge badge-red">✗ Missing</span>'
        sev_class = {'HIGH': 'badge-red', 'MEDIUM': 'badge-yellow', 'LOW': 'badge-blue'}.get(item['severity'], '')
        rows += f"""<tr>\n            <td><strong>{item['header']}</strong></td>\n            <td>{status}</td>\n            <td><span class="badge {sev_class}">{item['severity']}</span></td>\n            <td style="color: #6b7280;">{item['description']}</td>\n        </tr>"""
    return errors + f'\n        <p style="margin-bottom: 1rem;">Security Score: <span class="badge {score_class}">{score}/{max_score}</span></p>\n        <table>\n            <thead><tr><th>Header</th><th>Status</th><th>Severity</th><th>Description</th></tr></thead>\n            <tbody>{rows}</tbody>\n        </table>\n    '

def _render_ssl(data: dict) -> str:
    errors = _render_errors(data)
    cert = data.get('certificate', {})
    if not cert:
        return errors + '<p class="no-data">No SSL certificate data</p>'
    rows = ''
    subject = cert.get('subject', {})
    issuer = cert.get('issuer', {})
    if subject.get('commonName'):
        rows += f"<tr><td><strong>Common Name</strong></td><td>{subject['commonName']}</td></tr>"
    if issuer.get('organizationName'):
        rows += f"<tr><td><strong>Issuer</strong></td><td>{issuer['organizationName']}</td></tr>"
    if cert.get('not_before'):
        rows += f"<tr><td><strong>Valid From</strong></td><td>{cert['not_before']}</td></tr>"
    if cert.get('not_after'):
        rows += f"<tr><td><strong>Valid Until</strong></td><td>{cert['not_after']}</td></tr>"
    days = cert.get('days_until_expiry')
    if days is not None:
        if days < 0:
            rows += '<tr><td><strong>Status</strong></td><td><span class="badge badge-red">EXPIRED</span></td></tr>'
        elif days < 30:
            rows += f'<tr><td><strong>Status</strong></td><td><span class="badge badge-yellow">Expires in {days} days</span></td></tr>'
        else:
            rows += f'<tr><td><strong>Status</strong></td><td><span class="badge badge-green">Valid ({days} days)</span></td></tr>'
    if cert.get('protocol'):
        rows += f"<tr><td><strong>Protocol</strong></td><td>{cert['protocol']}</td></tr>"
    cipher = cert.get('cipher')
    if isinstance(cipher, dict):
        rows += f"<tr><td><strong>Cipher</strong></td><td>{cipher.get('name', '')} ({cipher.get('bits', '')} bits)</td></tr>"
    san = cert.get('san', [])
    if san:
        tags = ' '.join((f'<span class="tag">{s}</span>' for s in san[:15]))
        rows += f'<tr><td><strong>Alt Names</strong></td><td>{tags}</td></tr>'
    return errors + f'\n        <table>\n            <thead><tr><th>Field</th><th>Value</th></tr></thead>\n            <tbody>{rows}</tbody>\n        </table>\n    '

def _render_tech(data: dict) -> str:
    errors = _render_errors(data)
    techs = data.get('technologies', [])
    if not techs:
        return errors + '<p class="no-data">No technologies detected</p>'
    tags = ' '.join((f'<span class="tag">{t}</span>' for t in techs))
    categories = data.get('categories', {})
    cat_html = ''
    cat_icons = {'server': '🖥️ Server', 'framework': '⚙️ Framework', 'cms': '📝 CMS', 'javascript': '📜 JavaScript', 'cdn': '🌐 CDN', 'analytics': '📊 Analytics', 'other': '📦 Other'}
    rows = ''
    for cat_key, cat_label in cat_icons.items():
        cat_techs = categories.get(cat_key, [])
        if cat_techs:
            cat_tags = ' '.join((f'<span class="tag">{t}</span>' for t in cat_techs))
            rows += f'<tr><td><strong>{cat_label}</strong></td><td>{cat_tags}</td></tr>'
    return errors + f'\n        <table>\n            <thead><tr><th>Category</th><th>Technologies</th></tr></thead>\n            <tbody>{rows}</tbody>\n        </table>\n    '

def _render_subdomains(data: dict) -> str:
    errors = _render_errors(data)
    subs = data.get('subdomains', [])
    total = data.get('total', 0)
    if not subs:
        return errors + '<p class="no-data">No subdomains discovered</p>'
    tags = ' '.join((f'<span class="tag">{s}</span>' for s in subs))
    return errors + f'\n        <p style="margin-bottom: 1rem;">Total: <span class="badge badge-blue">{total}</span></p>\n        <div>{tags}</div>\n    '

def _render_emails(data: dict) -> str:
    errors = _render_errors(data)
    emails = data.get('emails', [])
    if not emails:
        return errors + '<p class="no-data">No email addresses found</p>'
    rows = ''
    for i, email in enumerate(emails, 1):
        rows += f'<tr><td>{i}</td><td>{email}</td></tr>'
    return errors + f'\n        <table>\n            <thead><tr><th>#</th><th>Email Address</th></tr></thead>\n            <tbody>{rows}</tbody>\n        </table>\n    '

def _render_wayback(data: dict) -> str:
    errors = _render_errors(data)
    if not data.get('has_archive'):
        return errors + '<p class="no-data">No archived snapshots found</p>'
    snapshots = data.get('snapshots', [])
    total = data.get('total_snapshots', len(snapshots))
    rows = ''
    for snap in snapshots[:15]:
        rows += f'''<tr>\n            <td>{snap.get('timestamp', 'N/A')}</td>\n            <td><span class="badge badge-blue">{snap.get('status', '')}</span></td>\n            <td><a href="{snap.get('url', '')}" style="color: #60a5fa;" target="_blank">{snap.get('url', '')[:80]}</a></td>\n        </tr>'''
    return errors + f'\n        <p style="margin-bottom: 1rem;">Total snapshots: <span class="badge badge-blue">{total}</span></p>\n        <table>\n            <thead><tr><th>Date</th><th>Status</th><th>Archive URL</th></tr></thead>\n            <tbody>{rows}</tbody>\n        </table>\n    '

def _render_threat(data: dict) -> str:
    errors = _render_errors(data)
    risk = data.get('risk_level', 'UNKNOWN')
    risk_class = {'HIGH': 'badge-red', 'MEDIUM': 'badge-yellow', 'LOW': 'badge-green', 'CLEAN': 'badge-green'}.get(risk, 'badge-blue')
    html = f'<p style="margin-bottom: 1rem;">Risk Level: <span class="badge {risk_class}">{risk}</span></p>'
    otx = data.get('otx', {})
    if otx:
        html += f"<p>AlienVault OTX: <strong>{otx.get('pulses', 0)}</strong> threat pulses</p>"
        tags = otx.get('tags', [])
        if tags:
            tag_html = ' '.join((f'<span class="tag">{t}</span>' for t in tags[:10]))
            html += f'<p style="margin-top: 0.5rem;">Tags: {tag_html}</p>'
    tf = data.get('threatfox', {})
    if tf.get('is_malicious'):
        html += '<p style="margin-top: 1rem;"><span class="badge badge-red">⚠ MALICIOUS IOCs FOUND</span></p>'
    else:
        html += '<p style="margin-top: 0.5rem;"><span class="badge badge-green">✓ No known IOCs (ThreatFox)</span></p>'
    scans = data.get('urlscan', [])
    if scans:
        rows = ''
        for scan in scans:
            rows += f"<tr>\n                <td>{scan.get('url', '')[:50]}</td>\n                <td>{scan.get('ip', '')}</td>\n                <td>{scan.get('server', '')}</td>\n                <td>{scan.get('scan_date', '')[:10]}</td>\n            </tr>"
        html += f'\n            <table style="margin-top: 1rem;">\n                <thead><tr><th>URL</th><th>IP</th><th>Server</th><th>Date</th></tr></thead>\n                <tbody>{rows}</tbody>\n            </table>\n        '
    return errors + html

def _render_shodan(data: dict) -> str:
    errors = _render_errors(data)
    keys = data.get('api_keys_configured', [])
    html = ''
    if keys:
        html += f"""<p><span class="badge badge-green">API keys: {', '.join(keys)}</span></p>"""
    else:
        html += '<p style="color: #6b7280;">No API keys configured. Set env vars for enhanced data:</p>'
        html += '<p class="no-data">SHODAN_API_KEY (free at shodan.io) · VIRUSTOTAL_API_KEY (free at virustotal.com) · ABUSEIPDB_API_KEY (free at abuseipdb.com)</p>'
    vt = data.get('virustotal', {})
    if vt.get('verdict'):
        v_class = {'MALICIOUS': 'badge-red', 'SUSPICIOUS': 'badge-yellow', 'CLEAN': 'badge-green'}.get(vt['verdict'], '')
        html += f"""<p style="margin-top: 1rem;">VirusTotal: <span class="badge {v_class}">{vt['verdict']}</span> : Malicious: {vt.get('malicious', 0)} | Suspicious: {vt.get('suspicious', 0)} | Harmless: {vt.get('harmless', 0)}</p>"""
    abuse = data.get('abuseipdb', {})
    if abuse.get('abuse_confidence_score') is not None:
        score = abuse['abuse_confidence_score']
        s_class = 'badge-red' if score > 50 else 'badge-yellow' if score > 10 else 'badge-green'
        html += f"""<p style="margin-top: 0.5rem;">AbuseIPDB: <span class="badge {s_class}">{score}% abuse score</span> : Reports: {abuse.get('total_reports', 0)}</p>"""
    return errors + html

def _render_wayback_secrets(data: dict) -> str:
    errors = _render_errors(data)
    leaks = data.get('leaks_found', [])
    urls_scanned = data.get('urls_scanned', 0)
    html = f'<p style="margin-bottom: 1rem;">URLs scanned for secrets: {urls_scanned}</p>'
    if not leaks:
        return errors + html + '<p class="no-data">No leaked secrets found in historical archives.</p>'
    rows = ''
    for leak in leaks:
        rows += f"<tr><td><span class='badge badge-red'>{leak['type']}</span></td><td><code>{leak['value']}</code></td><td><a href='{leak['source_url']}' style='color: #60a5fa;' target='_blank'>View Source</a></td></tr>"
    html += f'<table><thead><tr><th>Type</th><th>Secret Value</th><th>Source</th></tr></thead><tbody>{rows}</tbody></table>'
    return errors + html

def _render_dom_fingerprint(data: dict) -> str:
    errors = _render_errors(data)
    frameworks = data.get('frameworks', [])
    if not frameworks:
        return errors + '<p class="no-data">No specific DOM frameworks detected.</p>'
    tags = ' '.join(f'<span class="tag">{f}</span>' for f in frameworks)
    return errors + f'<div>{tags}</div>'

def _render_dependency_chain(data: dict) -> str:
    errors = _render_errors(data)
    deps = data.get('dependencies', [])
    vulns = data.get('vulnerabilities', [])
    html = ""
    if vulns:
        html += '<p style="margin-bottom: 1rem;"><span class="badge badge-red">⚠ VULNERABILITIES DETECTED</span></p><ul>'
        for v in vulns:
            html += f'<li style="color: #f87171; margin-left: 20px;">{v}</li>'
        html += '</ul><br>'
    if not deps:
        return errors + html + '<p class="no-data">No library dependencies detected.</p>'
    tags = ' '.join(f'<span class="tag">{d}</span>' for d in deps)
    return errors + html + f'<div><strong>Libraries Included:</strong><br><br>{tags}</div>'

def _render_ghost_assets(data: dict) -> str:
    errors = _render_errors(data)
    takeovers = data.get('takeovers', [])
    if not takeovers:
        return errors + '<p class="no-data">No vulnerable subdomains (takeovers) detected.</p>'
    html = '<p style="margin-bottom: 1rem;"><span class="badge badge-red">⚠ CRITICAL: SUBDOMAIN TAKEOVERS FOUND</span></p>'
    rows = ''
    for t in takeovers:
        rows += f"<tr><td><span class='badge badge-red'>{t['subdomain']}</span></td><td>{t['service']}</td><td>{t['cname']}</td></tr>"
    html += f'<table><thead><tr><th>Vulnerable Subdomain</th><th>Service</th><th>CNAME Record</th></tr></thead><tbody>{rows}</tbody></table>'
    return errors + html