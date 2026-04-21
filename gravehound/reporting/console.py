from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich import box
from gravehound.config import BANNER, TAGLINE, APP_VERSION

import sys
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

console = Console()

def print_banner():
    banner_text = Text(BANNER, style='bold cyan')
    console.print(banner_text)
    console.print(f'  [dim]{TAGLINE}[/dim]')
    console.print(f'  [dim]v{APP_VERSION}[/dim]\n')

def print_scan_header(target: str, modules: list[str]):
    console.print(Panel(f"[bold white]Target:[/bold white] [cyan]{target}[/cyan]\n[bold white]Modules:[/bold white] [yellow]{', '.join(modules)}[/yellow]", title='[bold bright_green]🐾 Scan Initiated[/bold bright_green]', border_style='bright_green', padding=(1, 2)))

def print_scan_summary(scan_results: dict):
    console.print()
    console.print(Panel(f"[bold white]Duration:[/bold white] [cyan]{scan_results['duration']}s[/cyan]\n[bold white]Modules Run:[/bold white] [green]{scan_results['successful_modules']}[/green] successful  [red]{scan_results['failed_modules']}[/red] failed\n[bold white]Started:[/bold white] {scan_results['start_time']}\n[bold white]Finished:[/bold white] {scan_results['end_time']}", title='[bold bright_green]✅ Scan Complete[/bold bright_green]', border_style='bright_green', padding=(1, 2)))

def print_dns_results(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
        return
    records = data.get('records', {})
    if not records:
        console.print('  [yellow]No DNS records found[/yellow]')
        return
    table = Table(title='DNS Records', box=box.ROUNDED, border_style='cyan', title_style='bold cyan', show_lines=True)
    table.add_column('Type', style='bold yellow', width=8)
    table.add_column('Value', style='white')
    for record_type, values in records.items():
        for value in values:
            if isinstance(value, dict):
                val_str = '  '.join((f'{k}={v}' for k, v in value.items()))
            else:
                val_str = str(value)
            table.add_row(record_type, val_str)
    console.print(table)

def print_whois_results(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
        return
    info = data.get('data', {})
    if not info:
        console.print('  [yellow]No WHOIS data available[/yellow]')
        return
    table = Table(title='WHOIS Information', box=box.ROUNDED, border_style='magenta', title_style='bold magenta')
    table.add_column('Field', style='bold yellow', width=20)
    table.add_column('Value', style='white')
    for key, value in info.items():
        display_key = key.replace('_', ' ').title()
        if isinstance(value, list):
            display_val = ', '.join((str(v) for v in value))
        else:
            display_val = str(value)
        table.add_row(display_key, display_val)
    console.print(table)

def print_subdomain_results(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    subs = data.get('subdomains', [])
    total = data.get('total', 0)
    if not subs:
        console.print('  [yellow]No subdomains discovered[/yellow]')
        return
    table = Table(title=f'Subdomains Found ({total})', box=box.ROUNDED, border_style='green', title_style='bold green')
    table.add_column('#', style='dim', width=4)
    table.add_column('Subdomain', style='bold cyan')
    table.add_column('Source', style='yellow')
    sources = data.get('sources', {})
    bruteforce = set(sources.get('bruteforce', []))
    crt_sh = set(sources.get('crt_sh', []))
    for i, sub in enumerate(subs, 1):
        source = []
        if sub in bruteforce:
            source.append('DNS')
        if sub in crt_sh:
            source.append('crt.sh')
        table.add_row(str(i), sub, ', '.join(source) if source else ':')
    console.print(table)

def print_port_results(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    ip = data.get('ip', 'Unknown')
    open_ports = data.get('open_ports', [])
    scanned = data.get('scanned_count', 0)
    console.print(f'  [dim]IP: {ip} | Ports scanned: {scanned}[/dim]')
    if not open_ports:
        console.print('  [yellow]No open ports found[/yellow]')
    else:
        table = Table(title=f'Open Ports ({len(open_ports)})', box=box.ROUNDED, border_style='red', title_style='bold red')
        table.add_column('Port', style='bold cyan', width=8)
        table.add_column('State', style='bold green', width=8)
        table.add_column('Service', style='yellow', width=16)
        table.add_column('Detected', style='bold magenta', width=16)
        table.add_column('Banner', style='dim', max_width=45)
        for port_info in open_ports:
            detected = port_info.get('detected_service') or ''
            svc = port_info['service']
            if detected and detected.upper() != svc.upper().split(' ')[0]:
                detected = f'[red]{detected}[/red]'
            table.add_row(str(port_info['port']), port_info['state'], svc, detected, port_info.get('banner', '')[:80])
        console.print(table)
    knock = data.get('port_knocking', {})
    filtered = knock.get('filtered_high_value', [])
    unlocked = knock.get('unlocked', [])
    if filtered:
        console.print(f'\n  [bold yellow]🚪 Port Knocking Analysis[/bold yellow]')
        console.print(f'  [dim]Sequences tested: {knock.get("sequences_tried", 0)}[/dim]')
        ftable = Table(title='Filtered High-Value Ports', box=box.ROUNDED, border_style='yellow', title_style='bold yellow')
        ftable.add_column('Port', style='bold cyan', width=8)
        ftable.add_column('Expected Service', style='yellow', width=16)
        ftable.add_column('State', width=12)
        for fp in filtered:
            ftable.add_row(str(fp['port']), fp['service'], '[yellow]FILTERED[/yellow]')
        console.print(ftable)
        if unlocked:
            console.print(f'\n  [bold red]⚠ PORT KNOCKING CONFIRMED[/bold red]')
            for u in unlocked:
                seq = ' → '.join(str(p) for p in u['sequence'])
                console.print(f'  [red]  🔓 {u["service"]} ({u["port"]}) unlocked with: [{seq}][/red]')
        else:
            console.print(f'  [dim]No default sequences unlocked these ports (custom sequence likely in use)[/dim]')

def print_headers_results(data: dict):
    if data.get('errors') and (not data.get('url')):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
        return
    url = data.get('url', '')
    status = data.get('status_code', '')
    server = data.get('server', '')
    score = data.get('score', 0)
    max_score = data.get('max_score', 0)
    console.print(f'  [dim]URL: {url} | Status: {status} | Server: {server}[/dim]')
    analysis = data.get('security_analysis', [])
    if not analysis:
        return
    ratio = score / max_score if max_score > 0 else 0
    if ratio >= 0.75:
        score_style = 'bold green'
    elif ratio >= 0.5:
        score_style = 'bold yellow'
    else:
        score_style = 'bold red'
    console.print(f'\n  Security Score: [{score_style}]{score}/{max_score}[/{score_style}]')
    table = Table(title='Security Headers', box=box.ROUNDED, border_style='yellow', title_style='bold yellow')
    table.add_column('Header', style='white', width=35)
    table.add_column('Status', width=10)
    table.add_column('Severity', width=10)
    table.add_column('Description', style='dim')
    for item in analysis:
        status_str = '[green]✓ Set[/green]' if item['present'] else '[red]✗ Missing[/red]'
        sev = item['severity']
        sev_style = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'dim'}.get(sev, 'white')
        table.add_row(item['header'], status_str, f'[{sev_style}]{sev}[/{sev_style}]', item['description'])
    console.print(table)

def print_ssl_results(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
        if not data.get('certificate'):
            return
    cert = data.get('certificate', {})
    if not cert:
        console.print('  [yellow]No SSL certificate data[/yellow]')
        return
    table = Table(title='SSL/TLS Certificate', box=box.ROUNDED, border_style='bright_blue', title_style='bold bright_blue')
    table.add_column('Field', style='bold yellow', width=22)
    table.add_column('Value', style='white')
    subject = cert.get('subject', {})
    if subject:
        table.add_row('Common Name', subject.get('commonName', 'N/A'))
        if 'organizationName' in subject:
            table.add_row('Organization', subject['organizationName'])
    issuer = cert.get('issuer', {})
    if issuer:
        table.add_row('Issuer', issuer.get('organizationName', issuer.get('commonName', 'N/A')))
    table.add_row('Valid From', cert.get('not_before', 'N/A'))
    table.add_row('Valid Until', cert.get('not_after', 'N/A'))
    days = cert.get('days_until_expiry')
    if days is not None:
        if days < 0:
            table.add_row('Status', '[bold red]⚠ EXPIRED[/bold red]')
        elif days < 30:
            table.add_row('Status', f'[yellow]⚠ Expires in {days} days[/yellow]')
        else:
            table.add_row('Status', f'[green]✓ Valid ({days} days remaining)[/green]')
    san = cert.get('san', [])
    if san:
        table.add_row('Alt Names', ', '.join(san[:10]))
        if len(san) > 10:
            table.add_row('', f'... and {len(san) - 10} more')
    if cert.get('protocol'):
        table.add_row('Protocol', cert['protocol'])
    cipher = cert.get('cipher')
    if isinstance(cipher, dict):
        table.add_row('Cipher', f"{cipher.get('name', '')} ({cipher.get('bits', '')} bits)")
    elif cipher:
        table.add_row('Cipher', str(cipher))
    console.print(table)

def print_tech_results(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    technologies = data.get('technologies', [])
    if not technologies:
        console.print('  [yellow]No technologies detected[/yellow]')
        return
    categories = data.get('categories', {})
    table = Table(title=f'Technologies Detected ({len(technologies)})', box=box.ROUNDED, border_style='bright_magenta', title_style='bold bright_magenta')
    table.add_column('Category', style='bold yellow', width=15)
    table.add_column('Technologies', style='cyan')
    category_icons = {'server': '🖥️  Server', 'framework': '⚙️  Framework', 'cms': '📝 CMS', 'javascript': '📜 JavaScript', 'cdn': '🌐 CDN', 'analytics': '📊 Analytics', 'other': '📦 Other'}
    for cat_key, cat_label in category_icons.items():
        techs = categories.get(cat_key, [])
        if techs:
            table.add_row(cat_label, ', '.join(techs))
    console.print(table)

def print_geo_results(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
        return
    ip = data.get('ip', 'Unknown')
    loc = data.get('location', {})
    if not loc:
        console.print('  [yellow]No geolocation data[/yellow]')
        return
    table = Table(title=f'IP Geolocation ({ip})', box=box.ROUNDED, border_style='bright_yellow', title_style='bold bright_yellow')
    table.add_column('Field', style='bold cyan', width=15)
    table.add_column('Value', style='white')
    field_map = {'country': '🌍 Country', 'region': '📍 Region', 'city': '🏙️  City', 'zip': '📮 ZIP', 'latitude': '📐 Latitude', 'longitude': '📐 Longitude', 'timezone': '🕐 Timezone', 'isp': '🏢 ISP', 'organization': '🏛️  Organization', 'as_number': '🔢 AS Number'}
    for key, label in field_map.items():
        val = loc.get(key)
        if val is not None and str(val):
            table.add_row(label, str(val))
    console.print(table)

def print_email_results(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    emails = data.get('emails', [])
    total = data.get('total', 0)
    if emails:
        table = Table(title=f'Emails Found ({total})', box=box.ROUNDED, border_style='green', title_style='bold green')
        table.add_column('#', style='dim', width=4)
        table.add_column('Email Address', style='bold cyan')
        for i, email in enumerate(emails, 1):
            table.add_row(str(i), email)
        console.print(table)
    else:
        console.print('  [yellow]No emails found on website[/yellow]')
    patterns = data.get('common_patterns', [])
    if patterns:
        console.print(f'\n  [dim]Common patterns to try:[/dim]')
        for p in patterns:
            console.print(f'  [dim]  • {p}[/dim]')

def _print_cloud_storage(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    total = data.get('total_checked', 0)
    buckets = data.get('buckets_found', [])
    private = data.get('exists_but_private', [])
    self_hosted = data.get('self_hosted', [])
    providers = data.get('providers_checked', [])
    console.print(f'  [dim]Providers: {", ".join(providers)} | Checked: {total}[/dim]')
    if buckets:
        console.print(f'\n  [bold red]⚠ {len(buckets)} OPEN bucket(s) found![/bold red]')
        table = Table(title='Open Buckets', box=box.ROUNDED, border_style='red', title_style='bold red')
        table.add_column('Provider', style='bold yellow', width=20)
        table.add_column('Name', style='bold cyan')
        table.add_column('Status', width=10)
        table.add_column('URL', style='dim', max_width=60)
        for b in buckets:
            status_str = '[red]OPEN[/red]' if b.get('listable') else '[yellow]EXISTS[/yellow]'
            table.add_row(b.get('provider', ''), b.get('name', ''), status_str, b.get('url', ''))
        console.print(table)
    if self_hosted:
        console.print(f'\n  [bold magenta]🖥️  {len(self_hosted)} self-hosted storage instance(s) detected[/bold magenta]')
        table = Table(title='Self-Hosted Storage', box=box.ROUNDED, border_style='magenta', title_style='bold magenta')
        table.add_column('Service', style='bold yellow', width=20)
        table.add_column('Host', style='bold cyan')
        table.add_column('Status', width=14)
        table.add_column('URL', style='dim', max_width=55)
        for sh in self_hosted:
            sev = sh.get('severity', '')
            sev_style = {'CRITICAL': 'red', 'HIGH': 'yellow'}.get(sev, 'white')
            table.add_row(sh.get('provider', sh.get('service', '')), sh.get('name', ''), f'[{sev_style}]{sh.get("status", "")}[/{sev_style}]', sh.get('url', ''))
        console.print(table)
    if not buckets and not self_hosted:
        console.print('  [green]✓ No open buckets or self-hosted storage found[/green]')
    if private:
        console.print(f'\n  [dim]{len(private)} bucket(s) exist but are private (403)[/dim]')

def _print_js_analyzer(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    scanned = data.get('js_files_scanned', 0)
    secrets = data.get('secrets', [])
    endpoints = data.get('endpoints', [])
    internal = data.get('internal_uris', [])
    console.print(f'  [dim]JS files scanned: {scanned}[/dim]')
    if secrets:
        console.print(f'\n  [bold red]🔑 {len(secrets)} hardcoded secret(s) found[/bold red]')
        table = Table(title='Secrets in JavaScript', box=box.ROUNDED, border_style='red', title_style='bold red')
        table.add_column('Severity', width=10)
        table.add_column('Pattern', style='bold yellow')
        table.add_column('Value', style='cyan')
        table.add_column('Source', style='dim', max_width=40)
        for s in secrets[:20]:
            sev = s.get('severity', '')
            sev_style = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'blue'}.get(sev, 'white')
            table.add_row(f'[{sev_style}]{sev}[/{sev_style}]', s.get('pattern', ''), s.get('value_redacted', ''), s.get('source', '')[-40:])
        console.print(table)
    if endpoints:
        console.print(f'\n  [bold cyan]🔗 {len(endpoints)} hidden endpoint(s)[/bold cyan]')
        for ep in endpoints[:15]:
            console.print(f'    • {ep}')
    if internal:
        console.print(f'\n  [bold yellow]🏠 {len(internal)} internal URI(s)[/bold yellow]')
        for uri in internal[:10]:
            console.print(f'    • {uri}')
    if not secrets and not endpoints and not internal:
        console.print('  [green]✓ No secrets or hidden endpoints found[/green]')

def _print_web3_recon(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    rpc = data.get('exposed_rpc', [])
    wallets = data.get('wallet_addresses', {})
    keys = data.get('leaked_keys', [])
    providers = data.get('web3_providers', [])
    if rpc:
        console.print(f'\n  [bold red]⚠ {len(rpc)} exposed RPC endpoint(s)[/bold red]')
        table = Table(title='Exposed JSON-RPC', box=box.ROUNDED, border_style='red', title_style='bold red')
        table.add_column('URL', style='cyan', max_width=50)
        table.add_column('Chain', style='bold yellow')
        table.add_column('Chain ID', style='dim')
        for r in rpc:
            table.add_row(r.get('url', ''), r.get('chain_name', ''), r.get('chain_id', ''))
        console.print(table)
    evm = wallets.get('evm', [])
    btc = wallets.get('bitcoin', [])
    total_wallets = len(evm) + len(btc)
    if total_wallets:
        console.print(f'\n  [bold cyan]💰 {total_wallets} wallet address(es) found[/bold cyan]')
        if evm:
            console.print(f'    EVM: {", ".join(evm[:5])}{" ..." if len(evm) > 5 else ""}')
        if btc:
            console.print(f'    BTC: {", ".join(btc[:3])}')
    if keys:
        console.print(f'\n  [bold yellow]🔑 {len(keys)} Web3 key(s) leaked[/bold yellow]')
        for k in keys:
            console.print(f'    • {k["type"]}: {k["value_redacted"]}')
    if providers:
        console.print(f'\n  [bold green]⛓️  Web3 stack: {", ".join(providers)}[/bold green]')
    if not rpc and not total_wallets and not keys and not providers:
        console.print('  [dim]No Web3 footprint detected[/dim]')

def _print_dotfiles(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    exposed = data.get('exposed', [])
    total = data.get('total_checked', 0)
    hosts = data.get('hosts_scanned', [])
    console.print(f'  [dim]Hosts scanned: {len(hosts)} | Paths checked: {total}[/dim]')
    if exposed:
        table = Table(title=f'Exposed Files ({len(exposed)})', box=box.ROUNDED, border_style='red', title_style='bold red')
        table.add_column('Severity', width=10)
        table.add_column('Path', style='bold cyan')
        table.add_column('Category', style='yellow')
        table.add_column('Evidence', style='dim', max_width=30)
        table.add_column('URL', style='dim', max_width=40)
        for item in exposed[:30]:
            sev = item.get('severity', '')
            sev_style = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'blue', 'LOW': 'dim'}.get(sev, 'white')
            table.add_row(f'[{sev_style}]{sev}[/{sev_style}]', item.get('path', ''), item.get('category', ''), str(item.get('evidence', ''))[:30], item.get('url', '')[-40:])
        console.print(table)
    else:
        console.print('  [green]✓ No exposed configs or dotfiles found[/green]')

def _print_cors(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    vulns = data.get('vulnerabilities', [])
    total = data.get('total_tested', 0)
    endpoints = data.get('endpoints_tested', [])
    console.print(f'  [dim]Endpoints tested: {len(endpoints)} | Total checks: {total}[/dim]')
    if vulns:
        console.print(f'\n  [bold red]⚠ {len(vulns)} CORS misconfiguration(s) found[/bold red]')
        table = Table(title='CORS Vulnerabilities', box=box.ROUNDED, border_style='red', title_style='bold red')
        table.add_column('Severity', width=10)
        table.add_column('Test', style='bold yellow')
        table.add_column('Origin Sent', style='cyan', max_width=30)
        table.add_column('ACAO', style='white', max_width=30)
        table.add_column('Creds', width=6)
        table.add_column('URL', style='dim', max_width=35)
        for v in vulns:
            sev = v.get('severity', '')
            sev_style = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'blue'}.get(sev, 'white')
            creds = '[red]✓[/red]' if v.get('acac') else '[dim]✗[/dim]'
            table.add_row(f'[{sev_style}]{sev}[/{sev_style}]', v.get('test_name', ''), v.get('origin_sent', ''), v.get('acao_received', ''), creds, v.get('url', '')[-35:])
        console.print(table)
    else:
        console.print('  [green]✓ No CORS misconfigurations detected[/green]')

PRINTERS = {'dns': print_dns_results, 'whois': print_whois_results, 'subdomains': print_subdomain_results, 'ports': print_port_results, 'headers': print_headers_results, 'ssl': print_ssl_results, 'tech': print_tech_results, 'geo': print_geo_results, 'emails': print_email_results, 'wayback': lambda data: _print_wayback(data), 'threat': lambda data: _print_threat(data), 'shodan': lambda data: _print_shodan(data), 'cloud_storage': lambda data: _print_cloud_storage(data), 'js_analyzer': lambda data: _print_js_analyzer(data), 'web3_recon': lambda data: _print_web3_recon(data), 'dotfiles': lambda data: _print_dotfiles(data), 'cors_check': lambda data: _print_cors(data)}

def print_results(scan_results: dict):
    results = scan_results.get('results', {})
    module_titles = {'dns': '🔍 DNS Lookup', 'whois': '📋 WHOIS Lookup', 'subdomains': '🌐 Subdomain Discovery', 'ports': '🔓 Port Scanner', 'headers': '🛡️  HTTP Security Headers', 'ssl': '🔒 SSL/TLS Certificate', 'tech': '⚙️  Technology Detection', 'geo': '🌍 IP Geolocation', 'emails': '📧 Email Harvesting', 'wayback': '🕰️  Wayback Machine (archive.org)', 'threat': '🚨 Threat Intelligence (OTX / URLScan / ThreatFox)', 'shodan': '🔎 Shodan / VirusTotal / AbuseIPDB', 'cloud_storage': '☁️  Cloud Storage Buckets', 'js_analyzer': '📜 JavaScript Analysis', 'web3_recon': '⛓️  Web3 / On-Chain Recon', 'dotfiles': '📂 Exposed Configs & Dotfiles', 'cors_check': '🔀 CORS Misconfiguration'}
    for mod_key in scan_results.get('modules_run', []):
        data = results.get(mod_key, {})
        title = module_titles.get(mod_key, mod_key)
        console.print()
        console.rule(f'[bold]{title}[/bold]', style='bright_blue')
        console.print()
        printer = PRINTERS.get(mod_key)
        if printer:
            printer(data)
        else:
            console.print(f'  [dim]No printer for module: {mod_key}[/dim]')

def _print_wayback(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    if not data.get('has_archive'):
        console.print('  [yellow]No archived snapshots found[/yellow]')
        return
    total = data.get('total_snapshots', len(data.get('snapshots', [])))
    console.print(f'  [green]✓ Found {total} archived snapshots[/green]')
    snapshots = data.get('snapshots', [])
    if snapshots:
        table = Table(title=f'Archived Snapshots', box=box.ROUNDED, border_style='bright_cyan', title_style='bold bright_cyan')
        table.add_column('Date', style='bold yellow', width=15)
        table.add_column('Status', width=8)
        table.add_column('Archive URL', style='cyan')
        for snap in snapshots[:15]:
            table.add_row(snap.get('timestamp', 'N/A'), snap.get('status', 'N/A'), snap.get('url', '')[:100])
        console.print(table)

def _print_threat(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    risk = data.get('risk_level', 'UNKNOWN')
    risk_style = {'HIGH': 'bold red', 'MEDIUM': 'bold yellow', 'LOW': 'bold green', 'CLEAN': 'bold bright_green'}.get(risk, 'white')
    console.print(f'\n  Risk Level: [{risk_style}]{risk}[/{risk_style}]')
    otx = data.get('otx', {})
    if otx:
        pulses = otx.get('pulses', 0)
        console.print(f'\n  [bold cyan]AlienVault OTX:[/bold cyan]')
        console.print(f'    Threat Pulses: {pulses}')
        tags = otx.get('tags', [])
        if tags:
            console.print(f"    Tags: {', '.join(tags[:10])}")
    scans = data.get('urlscan', [])
    if scans:
        table = Table(title='URLScan.io Results', box=box.ROUNDED, border_style='blue', title_style='bold blue')
        table.add_column('URL', style='cyan', max_width=40)
        table.add_column('IP', style='yellow', width=16)
        table.add_column('Server', style='white', width=15)
        table.add_column('Date', style='dim', width=12)
        for scan in scans:
            table.add_row(scan.get('url', '')[:40], scan.get('ip', ''), scan.get('server', ''), scan.get('scan_date', '')[:10])
        console.print(table)
    tf = data.get('threatfox', {})
    if tf.get('is_malicious'):
        console.print(f'\n  [bold red]⚠ ThreatFox: MALICIOUS IOCs FOUND[/bold red]')
        for ioc in tf.get('iocs', []):
            console.print(f"    [red]• {ioc.get('threat_type', '')} : {ioc.get('malware', '')}[/red]")
    else:
        console.print(f'\n  [green]✓ ThreatFox: No known IOCs[/green]')
    rdns = data.get('reverse_dns', [])
    if rdns:
        console.print(f'\n  [bold cyan]Reverse DNS ({len(rdns)} domains):[/bold cyan]')
        for d in rdns[:10]:
            console.print(f'    • {d}')

def _print_shodan(data: dict):
    if data.get('errors'):
        for err in data['errors']:
            console.print(f'  [red]✗ {err}[/red]')
    keys = data.get('api_keys_configured', [])
    if keys:
        console.print(f"  [green]API keys configured: {', '.join(keys)}[/green]")
    else:
        console.print(f'  [yellow]No API keys configured[/yellow]')
    shodan = data.get('shodan', {})
    if not shodan.get('available', True):
        console.print(f"  [dim]{shodan.get('note', '')}[/dim]")
    elif shodan.get('ports'):
        console.print(f'\n  [bold cyan]Shodan:[/bold cyan]')
        console.print(f"    Ports: {', '.join((str(p) for p in shodan['ports']))}")
        console.print(f"    OS: {shodan.get('os', 'Unknown')}")
        vulns = shodan.get('vulns', [])
        if vulns:
            console.print(f"    [red]Vulnerabilities: {', '.join(vulns[:10])}[/red]")
    vt = data.get('virustotal', {})
    if not vt.get('available', True):
        console.print(f"  [dim]{vt.get('note', '')}[/dim]")
    elif vt.get('verdict'):
        verdict = vt['verdict']
        v_style = {'MALICIOUS': 'bold red', 'SUSPICIOUS': 'bold yellow', 'CLEAN': 'bold green'}.get(verdict, 'white')
        console.print(f'\n  [bold cyan]VirusTotal:[/bold cyan]')
        console.print(f'    Verdict: [{v_style}]{verdict}[/{v_style}]')
        console.print(f"    Malicious: {vt.get('malicious', 0)} | Suspicious: {vt.get('suspicious', 0)} | Harmless: {vt.get('harmless', 0)}")
    abuse = data.get('abuseipdb', {})
    if not abuse.get('available', True):
        console.print(f"  [dim]{abuse.get('note', '')}[/dim]")
    elif abuse.get('abuse_confidence_score') is not None:
        score = abuse['abuse_confidence_score']
        s_style = 'red' if score > 50 else 'yellow' if score > 10 else 'green'
        console.print(f'\n  [bold cyan]AbuseIPDB:[/bold cyan]')
        console.print(f'    Abuse Score: [{s_style}]{score}%[/{s_style}]')
        console.print(f"    Reports: {abuse.get('total_reports', 0)} | Tor: {abuse.get('is_tor', False)}")
