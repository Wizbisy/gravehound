import re
import socket
import select
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from gravehound.config import TOP_PORTS, PORT_SERVICES, DEFAULT_PORT_TIMEOUT, DEFAULT_THREADS
from gravehound import tor

_RISKY_PORTS = {21, 23, 69, 135, 139, 445, 512, 513, 514, 3389, 5900, 6379, 9200, 11211, 27017}

_PLAINTEXT_PROTOCOLS = {21: 'FTP', 23: 'Telnet', 69: 'TFTP',
                        110: 'POP3', 143: 'IMAP', 514: 'Syslog'}

_PROBES: dict[str, bytes] = {
    'http':    b'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n',
    'redis':   b'*1\r\n$4\r\nPING\r\n',
    'mongodb': b'\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07'
               b'\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00'
               b'\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00',
    'generic': b'\r\n',
}

_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ('SSH',           re.compile(rb'SSH-\d+\.\d+', re.IGNORECASE)),
    ('HTTP',          re.compile(rb'HTTP/\d+\.\d+', re.IGNORECASE)),
    ('FTP',           re.compile(rb'^\d{3}[\s-].*FTP', re.IGNORECASE)),
    ('SMTP',          re.compile(rb'^\d{3}[\s-].*(SMTP|ESMTP|mail)', re.IGNORECASE)),
    ('POP3',          re.compile(rb'^\+OK', re.IGNORECASE)),
    ('IMAP',          re.compile(rb'^\* OK', re.IGNORECASE)),
    ('Redis',         re.compile(rb'^\+PONG|\$\d+\r\n', re.IGNORECASE)),
    ('MongoDB',       re.compile(rb'ismaster|mongodb|topologyVersion', re.IGNORECASE)),
    ('Elasticsearch', re.compile(rb'"cluster_name"|"version".*"number"', re.IGNORECASE)),
    ('MySQL',         re.compile(rb'mysql_native_password|\x05\x00\x00\x00\x0a', re.IGNORECASE)),
    ('Memcached',     re.compile(rb'^(STORED|ERROR|VERSION \d)', re.IGNORECASE)),
    ('RDP',           re.compile(rb'^\x03\x00', re.IGNORECASE)),
    ('SMB',           re.compile(rb'^\x00\x00\x00.{1}\xffSMB', re.IGNORECASE)),
    ('Telnet',        re.compile(rb'^\xff[\xfb-\xfe]', re.IGNORECASE)),
    ('VNC',           re.compile(rb'^RFB \d+\.\d+', re.IGNORECASE)),
]

_EXPECTED_PORTS: dict[str, set[int]] = {
    'SSH':           {22, 2222},
    'HTTP':          {80, 443, 8080, 8000, 8443, 8888, 3000, 5000},
    'FTP':           {21},
    'SMTP':          {25, 465, 587},
    'POP3':          {110, 995},
    'IMAP':          {143, 993},
    'Redis':         {6379},
    'MongoDB':       {27017, 27018, 27019},
    'Elasticsearch': {9200, 9300},
    'MySQL':         {3306, 33060},
    'Memcached':     {11211},
    'RDP':           {3389},
    'SMB':           {139, 445},
    'Telnet':        {23},
    'VNC':           {5900, 5901},
}

_MISMATCH_WHITELIST: dict[int, set[str]] = {
    443:  {'HTTP'},
    8443: {'HTTP'},
    993:  {'HTTP'},
    995:  {'HTTP'},
    465:  {'HTTP'},
    636:  {'HTTP'},
}

_KNOCK_TARGETS = {22, 2222, 3389, 5900, 8080, 8443}

_KNOCK_SEQUENCES = [
    ([7000, 8000, 9000], 0.10),
    ([7000, 8000, 9000], 0.50),
    ([1234, 5678, 9012], 0.10),
    ([7000, 7001, 7002], 0.10),
    ([1111, 2222, 3333], 0.10),
    ([6000, 7000, 8000], 0.10),
    ([9000, 8000, 7000], 0.10),
    ([1337, 2600, 8080], 0.10),
    ([65535, 1, 65535],  0.10),
]


def _fingerprint(raw_bytes: bytes) -> str | None:
    for name, pattern in _SIGNATURES:
        if pattern.search(raw_bytes):
            return name
    return None


def _port_state(target_ip: str, port: int, timeout: float) -> str:
    try:
        with tor.create_socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                return 'open'
            if result in (10061, 111):
                return 'closed'
            if result in (10060, 110):
                return 'filtered'
            return 'closed'
    except socket.timeout:
        return 'filtered'
    except OSError:
        return 'closed'


def _send_knock(target_ip: str, sequence: list[int], delay: float):
    for port in sequence:
        try:
            with tor.create_socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                sock.connect_ex((target_ip, port))
        except Exception:
            pass
        time.sleep(delay)


def _detect_port_knocking(target_ip: str, open_port_nums: set[int], timeout: float) -> dict:
    knock_results = {
        'filtered_high_value': [],
        'knock_detected': False,
        'sequences_tried': 0,
        'unlocked': [],
    }

    candidates = sorted(_KNOCK_TARGETS - open_port_nums)
    if not candidates:
        return knock_results

    for port in candidates:
        state = _port_state(target_ip, port, timeout)
        if state == 'filtered':
            knock_results['filtered_high_value'].append({
                'port': port,
                'service': PORT_SERVICES.get(port, 'Unknown'),
            })

    if not knock_results['filtered_high_value']:
        return knock_results

    filtered_ports = [p['port'] for p in knock_results['filtered_high_value']]
    for seq, delay in _KNOCK_SEQUENCES:
        knock_results['sequences_tried'] += 1
        _send_knock(target_ip, seq, delay)
        time.sleep(0.5)

        for port in filtered_ports:
            new_state = _port_state(target_ip, port, timeout)
            if new_state == 'open':
                knock_results['knock_detected'] = True
                knock_results['unlocked'].append({
                    'port': port,
                    'sequence': list(seq),
                    'delay_ms': int(delay * 1000),
                    'service': PORT_SERVICES.get(port, 'Unknown'),
                })

        if knock_results['knock_detected']:
            break

    return knock_results


def _scan_port(target_ip: str, port: int, timeout: float, hostname: str) -> dict | None:
    try:
        with tor.create_socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result != 0:
                return None

            service_label = PORT_SERVICES.get(port, 'Unknown')
            raw_banner = b''
            try:
                ready = select.select([sock], [], [], min(timeout, 1.0))
                if ready[0]:
                    raw_banner = sock.recv(2048)

                if not raw_banner:
                    service_lower = service_label.lower()
                    if 'redis' in service_lower or port == 6379:
                        sock.sendall(_PROBES['redis'])
                    elif 'mongo' in service_lower or port in (27017, 27018, 27019):
                        sock.sendall(_PROBES['mongodb'])
                    elif 'http' in service_lower or port in (80, 8080, 8443, 8888, 443):
                        probe = _PROBES['http'].replace(b'{host}', (hostname or target_ip).encode())
                        sock.sendall(probe)
                    else:
                        sock.sendall(_PROBES['generic'])

                    ready = select.select([sock], [], [], timeout)
                    if ready[0]:
                        raw_banner = sock.recv(2048)
            except Exception:
                pass

            banner_text = raw_banner.decode('utf-8', errors='replace').strip()[:300]
            detected_service = _fingerprint(raw_banner)

            risk = []
            if port in _RISKY_PORTS:
                risk.append('high_risk_port')
            if port in _PLAINTEXT_PROTOCOLS:
                risk.append(f'plaintext_protocol ({_PLAINTEXT_PROTOCOLS[port]})')

            if detected_service and service_label != 'Unknown':
                expected_for_detected = _EXPECTED_PORTS.get(detected_service, set())
                if expected_for_detected and port not in expected_for_detected:
                    risk.append(f'service_on_nonstandard_port ({detected_service} on {port})')

            whitelisted = _MISMATCH_WHITELIST.get(port, set())
            expected_for_port = {
                name for name, ports in _EXPECTED_PORTS.items() if port in ports
            }
            if (expected_for_port and detected_service
                    and detected_service not in expected_for_port
                    and detected_service not in whitelisted):
                risk.append(f'banner_mismatch (expected {"/".join(expected_for_port)}, got {detected_service})')

            return {
                'port': port,
                'state': 'open',
                'service': service_label,
                'detected_service': detected_service,
                'banner': banner_text,
                'risk_flags': risk,
            }
    except OSError:
        pass
    return None


def run(target: str, ports: list[int] | None = None, threads: int = DEFAULT_THREADS,
        detect_knocking: bool = False) -> dict:
    results = {
        'module': 'Port Scanner',
        'target': target,
        'ip': None,
        'open_ports': [],
        'scanned_count': 0,
        'high_risk_count': 0,
        'port_knocking': {},
        'findings': [],
        'errors': [],
    }
    scan_ports = ports or TOP_PORTS
    results['scanned_count'] = len(scan_ports)
    try:
        target_ip = tor.resolve(target)
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
    open_port_nums = {p['port'] for p in results['open_ports']}

    if detect_knocking:
        try:
            knock = _detect_port_knocking(target_ip, open_port_nums, DEFAULT_PORT_TIMEOUT)
            results['port_knocking'] = knock
        except Exception as e:
            results['errors'].append(f'Port knock detection error: {str(e)}')

    for entry in results['open_ports']:
        for flag in entry.get('risk_flags', []):
            results['findings'].append(f'Port {entry["port"]} ({entry["service"]}): {flag}')

    if 80 in open_port_nums and 443 not in open_port_nums:
        results['findings'].append('HTTP only \u2014 no HTTPS detected')
    if 3389 in open_port_nums:
        results['findings'].append('RDP (3389) exposed \u2014 high risk for brute-force and BlueKeep-class vulns')
    if 6379 in open_port_nums:
        results['findings'].append('Redis (6379) exposed \u2014 check for unauthenticated access')
    if 9200 in open_port_nums:
        results['findings'].append('Elasticsearch (9200) exposed \u2014 verify authentication is enabled')
    if 27017 in open_port_nums:
        results['findings'].append('MongoDB (27017) exposed \u2014 verify authentication is enabled')

    nonstandard = [
        p for p in results['open_ports']
        if any('service_on_nonstandard_port' in f for f in p.get('risk_flags', []))
    ]
    for p in nonstandard:
        ds = p.get('detected_service', '?')
        results['findings'].append(
            f'{ds} detected on non-standard port {p["port"]} \u2014 possible evasion or misconfiguration'
        )

    mismatched = [
        p for p in results['open_ports']
        if any('banner_mismatch' in f for f in p.get('risk_flags', []))
    ]
    for p in mismatched:
        results['findings'].append(
            f'Port {p["port"]}: banner does not match expected service \u2014 possible honeypot or decoy'
        )

    knock = results.get('port_knocking', {})
    if knock.get('filtered_high_value'):
        ports_str = ', '.join(str(p['port']) for p in knock['filtered_high_value'])
        results['findings'].append(
            f'High-value ports filtered (not closed): {ports_str} \u2014 possible port knocking or dynamic firewall'
        )
    if knock.get('knock_detected'):
        for u in knock['unlocked']:
            seq_str = ' \u2192 '.join(str(p) for p in u['sequence'])
            results['findings'].append(
                f'PORT KNOCKING CONFIRMED: {u["service"]} ({u["port"]}) unlocked with sequence [{seq_str}] (delay: {u["delay_ms"]}ms)'
            )

    return results
