import socket
import select
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from gravehound.config import TOP_PORTS, PORT_SERVICES, DEFAULT_PORT_TIMEOUT, DEFAULT_THREADS

_RISKY_PORTS = {21, 23, 69, 135, 139, 445, 512, 513, 514, 3389, 5900, 6379, 9200, 11211, 27017}
_PLAINTEXT_PROTOCOLS = {21: 'FTP', 23: 'Telnet', 69: 'TFTP', 80: 'HTTP',
                        110: 'POP3', 143: 'IMAP', 514: 'Syslog'}
_HTTP_PROBE = b'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
_GENERIC_PROBE = b'\r\n'

def _grab_banner(target_ip: str, port: int, timeout: float, hostname: str = '') -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target_ip, port))
            service = PORT_SERVICES.get(port, '').lower()
            if 'http' in service or port in (80, 8080, 8443, 8888):
                probe = _HTTP_PROBE.replace(b'{host}', (hostname or target_ip).encode())
                sock.sendall(probe)
            else:
                sock.sendall(_GENERIC_PROBE)
            ready = select.select([sock], [], [], timeout)
            if ready[0]:
                raw = sock.recv(512)
                return raw.decode('utf-8', errors='replace').strip()[:300]
    except Exception:
        pass
    return ''

def _scan_port(target_ip: str, port: int, timeout: float, hostname: str) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
        if result == 0:
            service = PORT_SERVICES.get(port, 'Unknown')
            banner = _grab_banner(target_ip, port, timeout, hostname)
            risk = []
            if port in _RISKY_PORTS:
                risk.append('high_risk_port')
            if port in _PLAINTEXT_PROTOCOLS:
                risk.append(f'plaintext_protocol ({_PLAINTEXT_PROTOCOLS[port]})')
            return {
                'port': port,
                'state': 'open',
                'service': service,
                'banner': banner,
                'risk_flags': risk,
            }
    except OSError:
        pass
    return None

def run(target: str, ports: list[int] | None = None, threads: int = DEFAULT_THREADS) -> dict:
    results = {
        'module': 'Port Scanner',
        'target': target,
        'ip': None,
        'open_ports': [],
        'scanned_count': 0,
        'high_risk_count': 0,
        'findings': [],
        'errors': [],
    }
    scan_ports = ports or TOP_PORTS
    results['scanned_count'] = len(scan_ports)
    try:
        target_ip = socket.gethostbyname(target)
        results['ip'] = target_ip
    except socket.gaierror as e:
        results['errors'].append(f'Could not resolve {target}: {str(e)}')
        return results
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(_scan_port, target_ip, port, DEFAULT_PORT_TIMEOUT, target): port
                for port in scan_ports
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results['open_ports'].append(result)
                        if result['risk_flags']:
                            results['high_risk_count'] += 1
                except Exception as e:
                    results['errors'].append(f'Port scan future error: {str(e)}')
    except Exception as e:
        results['errors'].append(f'Thread pool error: {str(e)}')
    results['open_ports'].sort(key=lambda x: x['port'])
    for entry in results['open_ports']:
        for flag in entry.get('risk_flags', []):
            results['findings'].append(f'Port {entry["port"]} ({entry["service"]}): {flag}')
    if 3389 in {p['port'] for p in results['open_ports']}:
        results['findings'].append('RDP (3389) exposed — high risk for brute-force and BlueKeep-class vulns')
    if 6379 in {p['port'] for p in results['open_ports']}:
        results['findings'].append('Redis (6379) exposed — check for unauthenticated access')
    if 9200 in {p['port'] for p in results['open_ports']}:
        results['findings'].append('Elasticsearch (9200) exposed — verify authentication is enabled')
    if 27017 in {p['port'] for p in results['open_ports']}:
        results['findings'].append('MongoDB (27017) exposed — verify authentication is enabled')
    return results
