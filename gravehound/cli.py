import click
from rich.console import Console
from gravehound.config import APP_VERSION
from gravehound.scanner import run_scan, get_module_list, MODULES, DEFAULT_MODULES
from gravehound.reporting.console import print_banner, print_scan_header, print_results, print_scan_summary
from gravehound.reporting.json_report import export as json_export
from gravehound.reporting.html_report import export as html_export
from gravehound import tor

console = Console()
@click.group()
@click.version_option(version=APP_VERSION, prog_name='gravehound')
def cli():
    pass

@cli.command()
@click.argument('target')
@click.option('--modules', '-m', default=None, help='Comma-separated list of modules to run. Available: ' + ', '.join(get_module_list()))
@click.option('--output', '-o', default=None, help='Output file path for HTML report (e.g., report.html)')
@click.option('--json', '-j', 'json_output', is_flag=True, default=False, help='Output results as JSON to stdout')
@click.option('--json-file', default=None, help='Save JSON results to a file')
@click.option('--tor', 'use_tor', is_flag=True, default=False, help='Route all HTTP traffic through Tor (auto-detects 9050/9150)')
@click.option('--tor-proxy', default=None, help='Custom Tor SOCKS5 proxy URL (e.g. socks5://127.0.0.1:9050)')
@click.option('--knock', is_flag=True, default=False, help='Enable active port knocking detection (WARNING: active probing, requires explicit permission)')
def scan(target: str, modules: str | None, output: str | None, json_output: bool, json_file: str | None, use_tor: bool, tor_proxy: str | None, knock: bool):
    print_banner()
    if use_tor or tor_proxy:
        with console.status("[cyan]Configuring Tor proxy...[/cyan]"):
            try:
                tor.configure(tor_proxy)
                info = tor.check_connection()
                if info.get('connected') and info.get('is_tor'):
                    console.print(f"  [bright_green]✓ Tor Active[/bright_green] [dim](IP: {info.get('ip', 'hidden')} via {info.get('proxy')})[/dim]\n")
                else:
                    console.print(f"  [yellow]⚠ Tor connected but API check reported non-Tor IP[/yellow] [dim]({info.get('error', 'check failed')})[/dim]\n")
            except Exception as e:
                console.print(f"  [bold red]✗ Tor connection failed:[/bold red] {str(e)}\n")
                return
    if modules:
        module_list = [m.strip() for m in modules.split(',')]
    else:
        module_list = DEFAULT_MODULES
    print_scan_header(target, module_list)
    scan_options = {'knock': knock}
    scan_results = run_scan(target, module_list, options=scan_options)
    if not json_output:
        print_results(scan_results)
        print_scan_summary(scan_results)
    if json_output:
        json_str = json_export(scan_results)
        click.echo(json_str)
    if json_file:
        json_export(scan_results, json_file)
        console.print(f'\n  [green]✓ JSON report saved to:[/green] [bold]{json_file}[/bold]')
    if output:
        if output.lower().endswith('.json'):
            json_export(scan_results, output)
            console.print(f'\n  [green]✓ JSON report saved to:[/green] [bold]{output}[/bold]')
        else:
            html_export(scan_results, output)
            console.print(f'\n  [green]✓ HTML report saved to:[/green] [bold]{output}[/bold]')
    console.print()

@cli.command(name='modules')

def list_modules():
    print_banner()
    console.print('  [bold bright_green]Available Modules:[/bold bright_green]\n')
    for key, info in MODULES.items():
        console.print(f"  [cyan]{key:<15}[/cyan] {info['description']}")
    console.print(f'\n  [dim]Use --modules flag to select specific modules[/dim]')
    console.print(f'  [dim]Example: gravehound scan example.com --modules dns,whois,ports[/dim]\n')

if __name__ == '__main__':
    cli()
