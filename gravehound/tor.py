import os
import socket
import httpx

_TOR_HOST = os.getenv('TOR_HOST', '127.0.0.1')
_SOCKS_PROXY = f'socks5h://{_TOR_HOST}:9050'
_SOCKS_PROXY_BROWSER = f'socks5h://{_TOR_HOST}:9150'
_active = False
_proxy_url = None
_control_port = None

def configure(proxy_url: str | None = None, control_port: int | None = None) -> str:
    global _active, _proxy_url, _control_port
    if proxy_url:
        _proxy_url = proxy_url
        _control_port = control_port
    else:
        for candidate, c_port in [(_SOCKS_PROXY, 9051), (_SOCKS_PROXY_BROWSER, 9151)]:
            try:
                with httpx.Client(proxy=candidate, timeout=5) as client:
                    resp = client.get('https://check.torproject.org/api/ip')
                    if resp.status_code == 200:
                        _proxy_url = candidate
                        _control_port = c_port
                        break
            except Exception:
                continue
        if not _proxy_url:
            raise ConnectionError(
                'Tor proxy not reachable on 9050 (daemon) or 9150 (browser). '
                'Start Tor or Tor Browser, or pass a custom proxy with --tor-proxy.'
            )

    try:
        import socket
        import socks
    except ImportError:
        from rich.console import Console
        Console().print("\n  [bold red]⚠ PySocks not installed.[/bold red] [yellow]The port scanner will bypass Tor and leak your IP! Please run:[/yellow] pip install PySocks\n")

    _active = True
    return _proxy_url


def check_connection() -> dict:
    if not _proxy_url:
        return {'connected': False, 'error': 'Tor not configured'}
    
    try:
        with httpx.Client(proxy=_proxy_url, timeout=10) as client:
            resp = client.get('https://check.torproject.org/api/ip')
            data = resp.json()
            return {
                'connected': True,
                'is_tor': data.get('IsTor', False),
                'ip': data.get('IP', ''),
                'proxy': _proxy_url,
            }
    except Exception as e:
        return {'connected': False, 'error': str(e)}


def get_proxy() -> str | None:
    return _proxy_url if _active else None

def create_socket(family=None, type=None, proto=-1, fileno=None):
    import socket
    if _active and _proxy_url:
        try:
            import socks
            from urllib.parse import urlparse
            parsed = urlparse(_proxy_url)
            proxy_host = parsed.hostname or '127.0.0.1'
            proxy_port = parsed.port or 9050
            s = socks.socksocket(family or socket.AF_INET, type or socket.SOCK_STREAM, proto)
            s.set_proxy(socks.PROXY_TYPE_SOCKS5, proxy_host, proxy_port, True)
            return s
        except ImportError:
            pass
    return socket.socket(family or socket.AF_INET, type or socket.SOCK_STREAM, proto)


def is_active() -> bool:
    return _active


def resolve(hostname: str) -> str:
    if _active and _proxy_url:
        try:
            with httpx.Client(proxy=_proxy_url, timeout=10) as client:
                resp = client.get(
                    'https://cloudflare-dns.com/dns-query',
                    params={'name': hostname, 'type': 'A'},
                    headers={'Accept': 'application/dns-json'},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for ans in data.get('Answer', []):
                        if ans.get('type') == 1:
                            return ans['data']
            raise socket.gaierror(f'No A record found for {hostname} via Tor DoH')
        except socket.gaierror:
            raise
        except Exception as e:
            raise socket.gaierror(f'Tor DNS resolution failed for {hostname}: {e}')
    return socket.gethostbyname(hostname)


def resolve_all(hostname: str) -> list[str]:
    if _active and _proxy_url:
        try:
            with httpx.Client(proxy=_proxy_url, timeout=10) as client:
                resp = client.get(
                    'https://cloudflare-dns.com/dns-query',
                    params={'name': hostname, 'type': 'A'},
                    headers={'Accept': 'application/dns-json'},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    ips = [ans['data'] for ans in data.get('Answer', []) if ans.get('type') == 1]
                    if ips:
                        return ips
            return []
        except Exception:
            return []
    try:
        return list({str(r[4][0]) for r in socket.getaddrinfo(hostname, None)})
    except Exception:
        return []


def create_connection(address: tuple, timeout: float = 10) -> socket.socket:
    host, port = address
    sock = create_socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def get_new_identity():
    if not _control_port:
        return False
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=_control_port) as ctrl:
            try:
                ctrl.authenticate()
            except Exception as e:
                from rich.console import Console
                Console().print(f"[bold yellow]⚠ Tor Identity Rotation Failed:[/bold yellow] [dim]Control Port authentication error. To enable automated identity rotation, add [bold white]CookieAuthentication 1[/bold white] to your torrc file.[/dim]")
                return False
            ctrl.signal(Signal.NEWNYM)
            return True
    except Exception:
        return False
