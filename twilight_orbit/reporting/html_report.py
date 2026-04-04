import json
import html as html_module
from datetime import datetime
from twilight_orbit.config import APP_VERSION

# ── helpers ──────────────────────────────────────────────────────────────────

def _e(s) -> str:
    """HTML-escape a value."""
    return html_module.escape(str(s)) if s is not None else ''


def _badge(text: str, colour: str) -> str:
    colours = {
        'green':    ('#064e3b', '#34d399'),
        'red':      ('#450a0a', '#f87171'),
        'orange':   ('#431407', '#fb923c'),
        'yellow':   ('#422006', '#fbbf24'),
        'blue':     ('#0c2d48', '#60a5fa'),
        'purple':   ('#2e1065', '#a78bfa'),
        'gray':     ('#1e293b', '#94a3b8'),
        'cyan':     ('#083344', '#22d3ee'),
    }
    bg, fg = colours.get(colour, colours['gray'])
    return (f'<span style="display:inline-block;padding:2px 9px;border-radius:5px;'
            f'font-size:0.78rem;font-weight:700;background:{bg};color:{fg};'
            f'letter-spacing:.4px">{_e(text)}</span>')


def _sev_badge(severity: str) -> str:
    mapping = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 'LOW': 'blue', 'INFO': 'gray'}
    return _badge(severity, mapping.get(severity.upper(), 'gray'))


def _section(icon: str, title: str, content: str, count: str = '') -> str:
    count_html = f' <span style="font-size:.8rem;color:#6b7280;font-weight:400">({count})</span>' if count else ''
    return f'''
    <div class="section" id="sec-{title.lower().replace(' ', '-')}">
      <div class="section-header" onclick="toggle(this)">
        <span class="s-icon">{icon}</span>
        <h2>{_e(title)}{count_html}</h2>
        <span class="chevron">▾</span>
      </div>
      <div class="section-body">{content}</div>
    </div>'''


def _render_errors(data: dict) -> str:
    errors = data.get('errors', [])
    return ''.join(
        f'<div class="alert alert-warn">⚠ {_e(e)}</div>'
        for e in errors
    )


def _render_findings(data: dict) -> str:
    findings = data.get('findings', [])
    if not findings:
        return ''
    items = ''.join(f'<li>{_e(f)}</li>' for f in findings)
    return f'<div class="alert alert-find"><strong>🔎 Findings</strong><ul style="margin-top:.5rem;padding-left:1.2rem">{items}</ul></div>'


def _no_data(msg: str = 'No data returned') -> str:
    return f'<p class="no-data">{_e(msg)}</p>'


def _table(headers: list[str], rows: list[list]) -> str:
    ths = ''.join(f'<th>{_e(h)}</th>' for h in headers)
    trs = ''
    for row in rows:
        tds = ''.join(f'<td>{c}</td>' for c in row)
        trs += f'<tr>{tds}</tr>'
    return f'<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>'


# ── module renderers ──────────────────────────────────────────────────────────

def _render_dns(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    records = data.get('records', {})
    if not records:
        return out + _no_data('No DNS records found')
    rows = []
    for rtype, info in records.items():
        values = info.get('values', []) if isinstance(info, dict) else [info]
        ttl = info.get('ttl', '') if isinstance(info, dict) else ''
        for val in values:
            if isinstance(val, dict):
                val_str = ' &nbsp;|&nbsp; '.join(f'<span style="color:#94a3b8">{_e(k)}</span> {_e(v)}' for k, v in val.items())
            else:
                val_str = f'<code>{_e(val)}</code>'
            rows.append([_badge(rtype, 'blue'), val_str, f'<span style="color:#6b7280">{_e(ttl)}s</span>' if ttl else ''])
    out += _table(['Type', 'Value', 'TTL'], rows)
    return out


def _render_whois(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    info = data.get('data', {})
    if not info:
        return out + _no_data('No WHOIS data available')
    rows = []
    for key, value in info.items():
        label = key.replace('_', ' ').title()
        if isinstance(value, list):
            display = ', '.join(_e(v) for v in value)
        else:
            display = _e(value)
        if key == 'days_until_expiry':
            v = int(value) if str(value).lstrip('-').isdigit() else 999
            col = 'red' if v < 0 else 'yellow' if v < 30 else 'green'
            display = _badge(f'{value} days', col)
        rows.append([f'<strong>{_e(label)}</strong>', display])
    out += _table(['Field', 'Value'], rows)
    return out


def _render_geo(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    loc = data.get('location', {})
    ip = data.get('ip', '')
    all_ips = data.get('all_ips', [])
    nc = data.get('network_classification', '')
    if not loc:
        return out + _no_data('No geolocation data')
    ip_list = ', '.join(_e(i) for i in all_ips) if all_ips else _e(ip)
    out += f'<p style="margin-bottom:.8rem;color:#94a3b8">IP(s): <strong style="color:#e2e8f0">{ip_list}</strong>'
    if nc:
        nc_col = {'cloud_provider': 'purple', 'datacenter': 'blue', 'educational': 'cyan', 'government': 'yellow'}.get(nc, 'gray')
        out += f' &nbsp; {_badge(nc.replace("_", " ").upper(), nc_col)}'
    out += '</p>'
    fields = [('Country', 'country'), ('Region', 'region'), ('City', 'city'),
              ('Timezone', 'timezone'), ('ISP', 'isp'), ('Organization', 'organization'),
              ('AS Number', 'as_number')]
    rows = [[f'<strong>{label}</strong>', _e(loc.get(key, ''))] for label, key in fields if loc.get(key)]
    out += _table(['Field', 'Value'], rows)
    return out


def _render_ports(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    open_ports = data.get('open_ports', [])
    scanned = data.get('scanned_count', 0)
    high_risk = data.get('high_risk_count', 0)
    out += f'<p style="margin-bottom:.8rem">Scanned: {_badge(str(scanned), "gray")} &nbsp; Open: {_badge(str(len(open_ports)), "blue")} &nbsp; High-risk: {_badge(str(high_risk), "red")}</p>'
    if not open_ports:
        return out + _no_data('No open ports found')
    rows = []
    for p in open_ports:
        flags = p.get('risk_flags', [])
        flag_html = ' '.join(_badge(f, 'orange') for f in flags) if flags else _badge('clean', 'green')
        banner = f'<code style="font-size:.78rem;color:#94a3b8">{_e(p.get("banner", "")[:100])}</code>' if p.get('banner') else ''
        rows.append([f'<strong>{p["port"]}</strong>', _badge('open', 'green'), _e(p['service']), flag_html, banner])
    out += _table(['Port', 'State', 'Service', 'Risk', 'Banner'], rows)
    return out


def _render_headers(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    score = data.get('score', 0)
    max_score = data.get('max_score', 0)
    grade = data.get('grade', '?')
    url = data.get('url', '')
    grade_col = {'A': 'green', 'B': 'cyan', 'C': 'yellow', 'D': 'orange', 'F': 'red'}.get(grade, 'gray')
    ratio = score / max_score if max_score else 0
    pct = int(ratio * 100)
    out += f'''<div style="display:flex;align-items:center;gap:1.5rem;margin-bottom:1.2rem;flex-wrap:wrap">
      <div style="text-align:center">
        <div style="font-size:2.8rem;font-weight:900;color:{'#34d399' if grade=='A' else '#22d3ee' if grade=='B' else '#fbbf24' if grade=='C' else '#fb923c' if grade=='D' else '#f87171'}">{_e(grade)}</div>
        <div style="font-size:.75rem;color:#6b7280;letter-spacing:.5px">GRADE</div>
      </div>
      <div style="flex:1">
        <div style="font-size:.85rem;color:#94a3b8;margin-bottom:.4rem">{score}/{max_score} security headers present</div>
        <div style="height:8px;background:#1e293b;border-radius:99px;overflow:hidden">
          <div style="height:100%;width:{pct}%;background:{'#34d399' if pct>=75 else '#fbbf24' if pct>=50 else '#f87171'};border-radius:99px;transition:width .5s"></div>
        </div>
      </div>
    </div>'''
    if url:
        out += f'<p style="margin-bottom:1rem;color:#6b7280;font-size:.85rem">Scanned: <a href="{_e(url)}" style="color:#60a5fa" target="_blank">{_e(url)}</a></p>'
    analysis = data.get('security_analysis', [])
    rows = []
    for item in analysis:
        status = _badge('✓ Set', 'green') if item['present'] else _badge('✗ Missing', 'red')
        sev = item.get('severity', '')
        sev_col = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'blue'}.get(sev, 'gray')
        val_display = f'<code style="font-size:.78rem">{_e(item.get("value", ""))}</code>' if item['present'] else '<span style="color:#6b7280">—</span>'
        sub = item.get('sub_findings', [])
        sub_html = ''.join(f'<div style="font-size:.78rem;color:#fbbf24;margin-top:.2rem">⚠ {_e(s)}</div>' for s in sub) if sub else ''
        rows.append([f'<strong style="font-size:.88rem">{_e(item["header"])}</strong>{sub_html}', status, _badge(sev, sev_col), val_display])
    out += _table(['Header', 'Status', 'Severity', 'Value'], rows)
    return out


def _render_ssl(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    cert = data.get('certificate', {})
    if not cert:
        return out + _no_data('No SSL certificate data')
    rows = []
    subject = cert.get('subject', {})
    issuer = cert.get('issuer', {})
    if subject.get('commonName'):
        rows.append(['<strong>Common Name</strong>', _e(subject['commonName'])])
    if issuer.get('organizationName'):
        rows.append(['<strong>Issuer</strong>', _e(issuer['organizationName'])])
    for f, l in [('not_before', 'Valid From'), ('not_after', 'Valid Until')]:
        if cert.get(f):
            rows.append([f'<strong>{l}</strong>', _e(cert[f])])
    days = cert.get('days_until_expiry')
    if days is not None:
        col = 'red' if days < 0 else 'yellow' if days < 30 else 'green'
        rows.append(['<strong>Expiry</strong>', _badge(f'Expired' if days < 0 else f'{days} days remaining', col)])
    if cert.get('protocol'):
        weak = cert['protocol'] in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2')
        rows.append(['<strong>Protocol</strong>', _badge(cert['protocol'], 'red' if weak else 'green')])
    cipher = cert.get('cipher')
    if isinstance(cipher, dict):
        rows.append(['<strong>Cipher</strong>', f'<code>{_e(cipher.get("name",""))}</code> ({_e(cipher.get("bits",""))} bits)'])
    if cert.get('fingerprint_sha256'):
        rows.append(['<strong>SHA-256 Fingerprint</strong>', f'<code style="font-size:.75rem">{_e(cert["fingerprint_sha256"])}</code>'])
    san = cert.get('san', [])
    if san:
        tags = ' '.join(f'<span class="tag">{_e(s)}</span>' for s in san[:20])
        rows.append(['<strong>Alt Names</strong>', tags])
    out += _table(['Field', 'Value'], rows)
    return out


def _render_tech(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    techs = data.get('technologies', [])
    if not techs:
        return out + _no_data('No technologies detected')
    categories = data.get('categories', {})
    cat_icons = {
        'server': '🖥️ Server', 'framework': '⚙️ Framework', 'cms': '📝 CMS',
        'javascript': '📜 JavaScript', 'css_framework': '🎨 CSS', 'cdn': '🌐 CDN',
        'analytics': '📊 Analytics', 'payment': '💳 Payment', 'security': '🔐 Security',
        'other': '📦 Other',
    }
    rows = []
    for cat_key, cat_label in cat_icons.items():
        cat_techs = categories.get(cat_key, [])
        if cat_techs:
            tags = ' '.join(f'<span class="tag">{_e(t)}</span>' for t in cat_techs)
            rows.append([f'<strong>{cat_label}</strong>', tags])
    out += _table(['Category', 'Technologies'], rows)
    return out


def _render_subdomains(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    subs = data.get('subdomains', [])
    total = data.get('total', 0)
    takeovers = data.get('takeover_candidates', [])
    if takeovers:
        items = ''.join(f'<li style="color:#f87171">{_e(t)}</li>' for t in takeovers)
        out += f'<div class="alert alert-crit">🔥 <strong>Subdomain Takeover Candidates</strong><ul style="margin-top:.5rem;padding-left:1.2rem">{items}</ul></div>'
    resolved = data.get('resolved', [])
    sources = data.get('sources', {})
    src_html = ' &nbsp; '.join(
        f'{_badge(k.replace("_"," ").title(), "blue")} <span style="color:#6b7280;font-size:.82rem">{len(v)}</span>'
        for k, v in sources.items() if v
    )
    out += f'<p style="margin-bottom:.8rem">Total: {_badge(str(total), "cyan")} &nbsp; {src_html}</p>'
    if not subs:
        return out + _no_data('No subdomains discovered')
    if resolved:
        rows = []
        for r in resolved[:50]:
            ips = ', '.join(_e(i) for i in r.get('ips', []))
            cname = f'<span style="color:#a78bfa">{_e(r["cname"])}</span>' if r.get('cname') else ''
            rows.append([f'<code>{_e(r["fqdn"])}</code>', ips, cname])
        out += _table(['Subdomain', 'IPs', 'CNAME'], rows)
    else:
        tags = ' '.join(f'<span class="tag">{_e(s)}</span>' for s in subs[:100])
        out += f'<div style="line-height:2">{tags}</div>'
    return out


def _render_emails(data: dict) -> str:
    out = _render_errors(data)
    emails = data.get('emails', [])
    classified = data.get('classified', {})
    total = data.get('total', 0)
    out += f'<p style="margin-bottom:.8rem">Found: {_badge(str(total), "cyan")}</p>'
    if not emails:
        return out + _no_data('No email addresses found')
    if classified:
        rows = []
        for cat, addrs in classified.items():
            tags = ' '.join(f'<span class="tag">{_e(a)}</span>' for a in addrs)
            rows.append([_badge(cat.replace('_', ' ').title(), 'blue'), tags])
        out += _table(['Category', 'Emails'], rows)
    else:
        rows = [[str(i), f'<code>{_e(e)}</code>'] for i, e in enumerate(emails, 1)]
        out += _table(['#', 'Email'], rows)
    return out


def _render_wayback(data: dict) -> str:
    out = _render_errors(data)
    if not data.get('has_archive'):
        return out + _no_data('No archived snapshots found')
    summary = data.get('summary', {})
    total = data.get('total_snapshots', 0)
    truncated = data.get('truncated', False)
    mimes = data.get('unique_mime_types', [])
    out += f'''<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:1.2rem">
      <div class="stat-card"><div class="stat-val">{_e(summary.get("first_seen","N/A"))}</div><div class="stat-lbl">First Seen</div></div>
      <div class="stat-card"><div class="stat-val">{_e(summary.get("last_seen","N/A"))}</div><div class="stat-lbl">Last Seen</div></div>
      <div class="stat-card"><div class="stat-val">{_e(total)}</div><div class="stat-lbl">Snapshots{" (truncated)" if truncated else ""}</div></div>
      <div class="stat-card"><div class="stat-val">{_e(summary.get("archive_age_years","?"))}</div><div class="stat-lbl">Years of History</div></div>
    </div>'''
    if mimes:
        out += '<p style="margin-bottom:.8rem;color:#6b7280;font-size:.85rem">MIME types: ' + ' '.join(f'<span class="tag">{_e(m)}</span>' for m in mimes) + '</p>'
    snapshots = data.get('snapshots', [])
    rows = []
    for snap in snapshots[:20]:
        rows.append([_e(snap.get('timestamp', '')), _badge(snap.get('status', ''), 'gray'),
                     _e(snap.get('mimetype', '')),
                     f'<a href="{_e(snap.get("url",""))}" style="color:#60a5fa" target="_blank">Open ↗</a>'])
    out += _table(['Date', 'Status', 'MIME', 'Link'], rows)
    return out


def _render_threat(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    risk = data.get('risk_level', 'UNKNOWN')
    risk_score = data.get('risk_score', 0)
    risk_col = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'blue', 'CLEAN': 'green'}.get(risk, 'gray')
    out += f'<div style="display:flex;align-items:center;gap:1rem;margin-bottom:1.2rem">'
    out += f'<span style="font-size:1.4rem;font-weight:800;color:{"#f87171" if risk=="HIGH" else "#fbbf24" if risk=="MEDIUM" else "#34d399"}">{_e(risk)}</span>'
    out += f' {_badge(f"Score: {risk_score}", risk_col)}</div>'
    otx = data.get('otx', {})
    if otx:
        pulses = otx.get('pulses', 0)
        tags = otx.get('tags', [])
        malware = otx.get('malware_families', [])
        out += f'<p style="margin-bottom:.5rem">OTX Pulses: {_badge(str(pulses), "red" if pulses > 5 else "yellow" if pulses > 0 else "green")}</p>'
        if malware:
            out += '<p style="margin-bottom:.5rem">Malware: ' + ' '.join(_badge(m, 'red') for m in malware) + '</p>'
        if tags:
            out += '<p style="margin-bottom:.8rem;font-size:.82rem">Tags: ' + ' '.join(f'<span class="tag">{_e(t)}</span>' for t in tags[:15]) + '</p>'
    tf = data.get('threatfox', {})
    if tf.get('is_malicious'):
        iocs = tf.get('iocs', [])
        rows = [[_e(i.get('ioc', '')), _badge(i.get('threat_type', ''), 'red'), _e(i.get('malware', '')),
                 _badge(f'{i.get("confidence", 0)}%', 'orange')] for i in iocs[:5]]
        out += '<p style="margin:.8rem 0 .4rem">' + _badge('⚠ MALICIOUS IOCs FOUND', 'red') + '</p>'
        out += _table(['IOC', 'Threat Type', 'Malware', 'Confidence'], rows)
    else:
        out += '<p>' + _badge('✓ No known IOCs — ThreatFox', 'green') + '</p>'
    scans = data.get('urlscan', [])
    if scans:
        rows = [[f'<a href="{_e(s.get("report_url",""))}" style="color:#60a5fa" target="_blank">{_e(s.get("url","")[:60])}</a>',
                 _e(s.get('ip', '')), _e(s.get('server', '')), _e(s.get('scan_date', '')[:10])] for s in scans]
        out += '<p style="margin:.8rem 0 .4rem;color:#94a3b8;font-size:.85rem">URLScan.io Results</p>'
        out += _table(['URL', 'IP', 'Server', 'Date'], rows)
    return out


def _render_shodan(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    keys = data.get('api_keys_configured', [])
    if not keys:
        return out + '<p class="no-data">No API keys configured. Set <code>SHODAN_API_KEY</code>, <code>VIRUSTOTAL_API_KEY</code>, <code>ABUSEIPDB_API_KEY</code> in your .env file.</p>'
    out += '<p style="margin-bottom:.8rem">Active keys: ' + ' '.join(_badge(k, 'green') for k in keys) + '</p>'
    vt = data.get('virustotal', {})
    if vt.get('verdict'):
        v_col = {'MALICIOUS': 'red', 'SUSPICIOUS': 'orange', 'POSSIBLY_SUSPICIOUS': 'yellow', 'CLEAN': 'green'}.get(vt['verdict'], 'gray')
        out += f'<p style="margin-bottom:.5rem">VirusTotal: {_badge(vt["verdict"], v_col)} &nbsp; Malicious: <strong>{vt.get("malicious",0)}</strong> &nbsp; Suspicious: <strong>{vt.get("suspicious",0)}</strong> &nbsp; Engines: <strong>{vt.get("total_engines",0)}</strong></p>'
    abuse = data.get('abuseipdb', {})
    if abuse.get('abuse_confidence_score') is not None:
        score = abuse['abuse_confidence_score']
        col = 'red' if score >= 75 else 'orange' if score >= 25 else 'green'
        out += f'<p style="margin-bottom:.5rem">AbuseIPDB: {_badge(f"{score}% abuse confidence", col)} &nbsp; Reports: <strong>{abuse.get("total_reports",0)}</strong>'
        if abuse.get('is_tor'):
            out += f' &nbsp; {_badge("TOR EXIT NODE", "red")}'
        out += '</p>'
    shodan = data.get('shodan', {})
    if shodan.get('ports'):
        out += '<p style="margin-bottom:.5rem">Shodan Ports: ' + ' '.join(f'<span class="tag">{p}</span>' for p in shodan['ports'][:30]) + '</p>'
    if shodan.get('vulns'):
        out += '<p style="margin-bottom:.5rem">CVEs: ' + ' '.join(_badge(v, 'red') for v in list(shodan['vulns'])[:10]) + '</p>'
    return out


def _render_wayback_secrets(data: dict) -> str:
    out = _render_errors(data)
    leaks = data.get('leaks_found', [])
    urls_scanned = data.get('urls_scanned', 0)
    sev_summary = data.get('severity_summary', {})
    sev_html = ' &nbsp; '.join(f'{_sev_badge(k)}&thinsp;<span style="color:#6b7280">{v}</span>' for k, v in sev_summary.items()) if sev_summary else ''
    out += f'<p style="margin-bottom:.8rem">URLs scanned: {_badge(str(urls_scanned), "gray")} &nbsp; {sev_html}</p>'
    if not leaks:
        return out + '<p class="no-data">✓ No leaked secrets found in historical archives.</p>'
    out += f'<div class="alert alert-crit">🔑 <strong>{len(leaks)} unique secret(s) detected</strong> in Wayback Machine archives</div>'
    rows = []
    for leak in leaks:
        srcs = leak.get('source_urls', [leak.get('source_url', '')])
        src_links = ' '.join(f'<a href="{_e(u)}" style="color:#60a5fa;font-size:.8rem" target="_blank">↗</a>' for u in srcs[:3])
        rows.append([_sev_badge(leak.get('severity', '')), _badge(leak.get('pattern', ''), 'blue'),
                     f'<code style="font-size:.8rem">{_e(leak.get("value_redacted",""))}</code>',
                     _e(leak.get('archived_date', '')), src_links])
    out += _table(['Severity', 'Pattern', 'Redacted Value', 'Archived', 'Source(s)'], rows)
    return out


def _render_dom_fingerprint(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    frameworks = data.get('frameworks', [])
    versions = data.get('versions', {})
    meta = data.get('meta', {})
    if not frameworks and not meta:
        return out + _no_data('No DOM fingerprint data')
    if frameworks:
        tags = ' '.join(
            f'<span class="tag">{_e(f)}{" <span style=color:#fbbf24>" + _e(versions[f]) + "</span>" if f in versions else ""}</span>'
            for f in frameworks
        )
        out += f'<p style="margin-bottom:.8rem"><strong>Detected Frameworks</strong><br><br>{tags}</p>'
    if meta:
        rows = [[f'<strong>{_e(k.replace("_"," ").title())}</strong>', _e(str(v))] for k, v in meta.items() if v and v is not True]
        if rows:
            out += _table(['Meta Field', 'Value'], rows)
    return out


def _render_dependency_chain(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    deps = data.get('dependencies', [])
    vulns = data.get('vulnerabilities', [])
    vuln_count = data.get('vuln_count', 0)
    out += f'<p style="margin-bottom:.8rem">Libraries detected: {_badge(str(len(deps)), "gray")} &nbsp; Vulnerabilities: {_badge(str(vuln_count), "red" if vuln_count else "green")}</p>'
    if vulns:
        rows = [[ _sev_badge(v.get('severity', '')), _e(v.get('library', '')),
                  _e(v.get('version', '')), _e(v.get('description', '')) ] for v in vulns]
        out += _table(['Severity', 'Library', 'Version', 'Description'], rows)
    if not deps:
        return out + _no_data('No library dependencies detected')
    tags = ' '.join(
        f'<span class="tag" style="{"border:1px solid #f8717180" if any(v.get("library","").lower() in d["name"].lower() for v in vulns) else ""}">{_e(d["name"])} <span style="color:#6b7280">{_e(d["version"])}</span></span>'
        for d in deps
    )
    out += f'<div style="margin-top:.8rem;line-height:2.2">{tags}</div>'
    return out


def _render_ghost_assets(data: dict) -> str:
    out = _render_errors(data) + _render_findings(data)
    takeovers = data.get('takeovers', [])
    unconfirmed = data.get('unconfirmed_candidates', [])
    checked = data.get('subdomains_checked', 0)
    out += f'<p style="margin-bottom:.8rem">Subdomains checked: {_badge(str(checked), "gray")} &nbsp; Confirmed: {_badge(str(len(takeovers)), "red" if takeovers else "green")} &nbsp; Unconfirmed: {_badge(str(len(unconfirmed)), "yellow" if unconfirmed else "gray")}</p>'
    if takeovers:
        out += f'<div class="alert alert-crit">💀 <strong>{len(takeovers)} CONFIRMED subdomain takeover(s)</strong> — immediate remediation required</div>'
        rows = [[_sev_badge(t.get('severity', '')), f'<code>{_e(t["subdomain"])}</code>',
                 _badge(t.get('service', ''), 'blue'), f'<code>{_e(t.get("cname",""))}</code>',
                 f'<span style="color:#94a3b8;font-size:.78rem">{_e(t.get("fingerprint_matched",""))}</span>'] for t in takeovers]
        out += _table(['Severity', 'Subdomain', 'Provider', 'CNAME', 'Fingerprint'], rows)
    if unconfirmed:
        rows = [[_sev_badge(t.get('severity', '')), f'<code>{_e(t["subdomain"])}</code>',
                 _badge(t.get('service', ''), 'blue'), f'<code>{_e(t.get("cname",""))}</code>'] for t in unconfirmed]
        out += '<p style="margin:.8rem 0 .4rem;color:#94a3b8;font-size:.85rem">Unconfirmed candidates (manual verification needed)</p>'
        out += _table(['Severity', 'Subdomain', 'Provider', 'CNAME'], rows)
    if not takeovers and not unconfirmed:
        out += '<p class="no-data">✓ No subdomain takeover candidates found.</p>'
    return out


# ── main export ───────────────────────────────────────────────────────────────

def export(scan_results: dict, output_path: str) -> str:
    target = scan_results.get('target', 'Unknown')
    duration = scan_results.get('duration', 0)
    start_time = scan_results.get('start_time', '')
    successful = scan_results.get('successful_modules', 0)
    failed = scan_results.get('failed_modules', 0)
    results = scan_results.get('results', {})

    # Collect all findings for the top banner
    all_findings: list[tuple[str, str]] = []
    for mod_key, mod_data in results.items():
        if isinstance(mod_data, dict):
            for f in mod_data.get('findings', []):
                all_findings.append((mod_key.replace('_', ' ').title(), f))
            for t in mod_data.get('takeovers', []):
                all_findings.append(('Ghost Assets', f'CONFIRMED TAKEOVER: {t.get("subdomain")} → {t.get("service")}'))
            for leak in mod_data.get('leaks_found', []):
                sev = leak.get('severity', '')
                if sev in ('CRITICAL', 'HIGH'):
                    all_findings.append(('Wayback Secrets', f'[{sev}] {leak.get("pattern")}: {leak.get("value_redacted")}'))

    findings_banner = ''
    if all_findings:
        items = ''.join(f'<li><span style="color:#6b7280;font-size:.78rem">[{_e(src)}]</span> {_e(f)}</li>' for src, f in all_findings[:30])
        findings_banner = f'''<div class="findings-banner">
          <div style="font-weight:700;font-size:1rem;margin-bottom:.6rem">🔎 {len(all_findings)} Finding(s) Across All Modules</div>
          <ul style="padding-left:1.3rem;line-height:1.9">{items}</ul>
        </div>'''

    css = '''
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&family=JetBrains+Mono:wght@400;700&display=swap');
      *{margin:0;padding:0;box-sizing:border-box}
      body{font-family:'Inter',system-ui,sans-serif;background:#060b14;color:#e2e8f0;line-height:1.6;font-size:15px}
      a{color:#60a5fa;text-decoration:none}a:hover{text-decoration:underline}
      code{font-family:'JetBrains Mono',monospace;font-size:.85em;background:#0d1117;padding:1px 5px;border-radius:4px}
      .container{max-width:1150px;margin:0 auto;padding:2rem 1.5rem}

      /* header */
      .header{text-align:center;padding:3.5rem 0 2.5rem;border-bottom:1px solid #1e293b;margin-bottom:2rem}
      .logo{font-size:2.8rem;font-weight:900;background:linear-gradient(135deg,#00d4ff 0%,#7b2ff7 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
      .tagline{color:#475569;margin-top:.3rem;font-size:.95rem}

      /* summary grid */
      .summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}
      .scard{background:#0d1520;border:1px solid #1e293b;border-radius:10px;padding:1.2rem;text-align:center}
      .scard .val{font-size:1.6rem;font-weight:800;color:#00d4ff;letter-spacing:-.5px}
      .scard .lbl{font-size:.72rem;color:#475569;text-transform:uppercase;letter-spacing:.8px;margin-top:.2rem}

      /* findings banner */
      .findings-banner{background:linear-gradient(135deg,#0f172a,#1a0a2e);border:1px solid #4c1d95;border-left:4px solid #7b2ff7;border-radius:10px;padding:1.2rem 1.5rem;margin-bottom:1.8rem;font-size:.88rem}

      /* sections */
      .section{background:#0d1520;border:1px solid #1e293b;border-radius:10px;margin-bottom:1rem;overflow:hidden}
      .section-header{background:linear-gradient(90deg,#111827,#0d1520);padding:1rem 1.4rem;cursor:pointer;display:flex;align-items:center;gap:.8rem;transition:background .15s}
      .section-header:hover{background:linear-gradient(90deg,#1a2235,#111827)}
      .section-header h2{font-size:1rem;font-weight:600;flex:1}
      .s-icon{font-size:1.2rem}
      .chevron{color:#475569;font-size:.9rem;transition:transform .2s}
      .section-body{padding:1.4rem;border-top:1px solid #1e293b}
      .section-body.collapsed{display:none}

      /* tables */
      table{width:100%;border-collapse:collapse;font-size:.875rem}
      th{text-align:left;padding:.65rem 1rem;background:#070c14;color:#00d4ff;font-size:.75rem;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #1e293b}
      td{padding:.6rem 1rem;border-bottom:1px solid #1a2235;vertical-align:top}
      tr:last-child td{border-bottom:none}
      tr:hover td{background:#0a1120}

      /* alerts */
      .alert{padding:.8rem 1rem;border-radius:8px;margin-bottom:.8rem;font-size:.875rem}
      .alert-warn{background:#1c0a00;border-left:3px solid #f88;color:#fca5a5}
      .alert-find{background:#0a1628;border-left:3px solid #60a5fa;color:#bfdbfe}
      .alert-crit{background:#1f0a0a;border-left:3px solid #f87171;color:#fca5a5}

      /* misc */
      .tag{display:inline-block;background:#1e293b;color:#94a3b8;padding:2px 7px;border-radius:4px;font-size:.78rem;margin:2px}
      .no-data{color:#475569;font-style:italic;padding:.5rem 0}
      .stat-card{background:#070c14;border:1px solid #1e293b;border-radius:8px;padding:.8rem;text-align:center}
      .stat-val{font-size:1.1rem;font-weight:700;color:#00d4ff}
      .stat-lbl{font-size:.68rem;color:#475569;text-transform:uppercase;letter-spacing:.5px;margin-top:.1rem}
      .footer{text-align:center;padding:2rem 0;color:#334155;font-size:.8rem;border-top:1px solid #1e293b;margin-top:2rem}
    '''

    js = '''
      function toggle(header) {
        const body = header.nextElementSibling;
        const chev = header.querySelector('.chevron');
        body.classList.toggle('collapsed');
        chev.style.transform = body.classList.contains('collapsed') ? 'rotate(-90deg)' : '';
      }
    '''

    body = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Twilight Orbit — {_e(target)}</title>
  <style>{css}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">🌑 Twilight Orbit</div>
    <div class="tagline">Automated OSINT Recon Report &mdash; {_e(target)}</div>
  </div>

  <div class="summary">
    <div class="scard"><div class="val">{_e(target)}</div><div class="lbl">Target</div></div>
    <div class="scard"><div class="val">{_e(duration)}s</div><div class="lbl">Duration</div></div>
    <div class="scard"><div class="val">{_e(successful)}</div><div class="lbl">Modules Run</div></div>
    <div class="scard"><div class="val" style="color:#f87171">{_e(failed)}</div><div class="lbl">Failed</div></div>
    <div class="scard"><div class="val" style="font-size:1rem">{_e(start_time)}</div><div class="lbl">Scan Date</div></div>
  </div>

  {findings_banner}
'''

    MODULE_RENDERERS = [
        ('dns',             '🔍', 'DNS Records',                    _render_dns),
        ('whois',           '📋', 'WHOIS Information',              _render_whois),
        ('geo',             '🌍', 'IP Geolocation',                 _render_geo),
        ('ports',           '🔓', 'Open Ports',                     _render_ports),
        ('headers',         '🛡️',  'HTTP Security Headers',          _render_headers),
        ('ssl',             '🔒', 'SSL / TLS Certificate',          _render_ssl),
        ('tech',            '⚙️',  'Technologies Detected',          _render_tech),
        ('subdomains',      '🌐', 'Subdomains',                     _render_subdomains),
        ('emails',          '📧', 'Email Addresses',                _render_emails),
        ('wayback',         '🕰️',  'Wayback Machine',                _render_wayback),
        ('wayback_secrets', '🗝️',  'Wayback Secrets Scan',           _render_wayback_secrets),
        ('dom_fingerprint', '🖥️',  'DOM Fingerprint',                _render_dom_fingerprint),
        ('dependency_chain','🔗', 'Dependency Chain',               _render_dependency_chain),
        ('ghost_assets',    '👻', 'Ghost Assets / Subdomain Takeover', _render_ghost_assets),
        ('threat',          '🚨', 'Threat Intelligence',            _render_threat),
        ('shodan',          '🔎', 'Shodan / VirusTotal / AbuseIPDB',_render_shodan),
    ]

    for mod_key, icon, title, renderer in MODULE_RENDERERS:
        mod_data = results.get(mod_key)
        if not mod_data:
            continue
        try:
            content = renderer(mod_data)
        except Exception as ex:
            content = f'<p style="color:#f87171">Render error: {_e(str(ex))}</p>'
        # Count indicator
        count = ''
        if mod_key == 'ports':
            count = f'{len(mod_data.get("open_ports",[]))} open'
        elif mod_key == 'subdomains':
            count = f'{mod_data.get("total",0)} found'
        elif mod_key == 'wayback_secrets':
            n = len(mod_data.get('leaks_found', []))
            count = f'{n} leak(s)' if n else 'clean'
        elif mod_key == 'ghost_assets':
            n = len(mod_data.get('takeovers', []))
            count = f'{n} TAKEOVER(S)' if n else 'clean'
        elif mod_key == 'dependency_chain':
            count = f'{mod_data.get("vuln_count",0)} vuln(s)'
        body += _section(icon, title, content, count)

    body += f'''
  <div class="footer">
    Generated by <a href="https://github.com/WIzbisy/twilight-orbit">Twilight Orbit</a> v{_e(APP_VERSION)} &nbsp;|&nbsp; ⚠ For authorized security testing only
  </div>
</div>
<script>{js}</script>
</body>
</html>'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(body)
    return output_path