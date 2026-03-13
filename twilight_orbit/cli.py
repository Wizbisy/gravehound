import click
from rich.console import Console
from twilight_orbit.config import APP_VERSION
from twilight_orbit.scanner import run_scan, get_module_list, MODULES, DEFAULT_MODULES
from twilight_orbit.reporting.console import print_banner, print_scan_header, print_results, print_scan_summary
from twilight_orbit.reporting.json_report import export as json_export
from twilight_orbit.reporting.html_report import export as html_export
console = Console()

@click.group()
@click.version_option(version=APP_VERSION, prog_name='twilight-orbit')
def cli():
    pass

@cli.command()
@click.argument('target')
@click.option('--modules', '-m', default=None, help='Comma-separated list of modules to run. Available: ' + ', '.join(get_module_list()))
@click.option('--output', '-o', default=None, help='Output file path for HTML report (e.g., report.html)')
@click.option('--json', '-j', 'json_output', is_flag=True, default=False, help='Output results as JSON to stdout')
@click.option('--json-file', default=None, help='Save JSON results to a file')
def scan(target: str, modules: str | None, output: str | None, json_output: bool, json_file: str | None):
    print_banner()
    if modules:
        module_list = [m.strip() for m in modules.split(',')]
    else:
        module_list = DEFAULT_MODULES
    print_scan_header(target, module_list)
    scan_results = run_scan(target, module_list)
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
    console.print(f'  [dim]Example: twilight-orbit scan example.com --modules dns,whois,ports[/dim]\n')
if __name__ == '__main__':
    cli()