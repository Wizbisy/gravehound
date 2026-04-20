import os
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


def is_active() -> bool:
    return _active


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
                # Requires CookieAuthentication 1 or hashed password in torrc
                raise PermissionError(f"Tor Control Port authentication failed (check torrc): {e}")
            ctrl.signal(Signal.NEWNYM)
            return True
    except Exception:
        return False
