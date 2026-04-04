import ssl
import socket
import hashlib
import datetime
from twilight_orbit.config import DEFAULT_TIMEOUT

_WEAK_CIPHERS = ['RC4', 'DES', 'NULL', 'EXPORT', 'MD5', 'ANON']
_WEAK_PROTOCOLS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'}
_DEPRECATED_SIG_ALGS = ['md5WithRSAEncryption', 'sha1WithRSAEncryption']


def _parse_cert(cert: dict, ssock) -> dict:
    out: dict = {}

    subject = {}
    for item in cert.get('subject', ()):
        for k, v in item:
            subject[k] = v
    out['subject'] = subject

    issuer = {}
    for item in cert.get('issuer', ()):
        for k, v in item:
            issuer[k] = v
    out['issuer'] = issuer

    out['serial_number'] = cert.get('serialNumber', '')
    out['version'] = cert.get('version', '')
    out['not_before'] = cert.get('notBefore', '')
    out['not_after'] = cert.get('notAfter', '')

    not_after = out['not_after']
    if not_after:
        try:
            expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(
                tzinfo=datetime.timezone.utc
            )
            now = datetime.datetime.now(datetime.timezone.utc)
            days = (expiry - now).days
            out['days_until_expiry'] = days
            out['expired'] = days < 0
        except ValueError:
            pass

    san = cert.get('subjectAltName', ())
    out['san'] = [name for _, name in san]
    out['san_count'] = len(out['san'])

    out['protocol'] = ssock.version()
    cipher = ssock.cipher()
    if cipher:
        out['cipher'] = {'name': cipher[0], 'protocol': cipher[1], 'bits': cipher[2]}

    sig_alg = cert.get('signatureAlgorithm', '')
    out['signature_algorithm'] = sig_alg

    try:
        der = ssock.getpeercert(binary_form=True)
        if der:
            out['fingerprint_sha256'] = hashlib.sha256(der).hexdigest()
            out['fingerprint_sha1'] = hashlib.sha1(der).hexdigest()
    except Exception:
        pass

    return out


def _flag_issues(cert_data: dict) -> list[str]:
    findings = []

    if cert_data.get('expired'):
        findings.append('Certificate has EXPIRED')
    elif cert_data.get('days_until_expiry', 999) < 30:
        findings.append(f'Certificate expires in {cert_data["days_until_expiry"]} days — renewal critical')
    elif cert_data.get('days_until_expiry', 999) < 90:
        findings.append(f'Certificate expires in {cert_data["days_until_expiry"]} days — renewal recommended')

    proto = cert_data.get('protocol', '')
    if proto in _WEAK_PROTOCOLS:
        findings.append(f'Weak TLS/SSL protocol in use: {proto} — upgrade required')

    cipher_name = cert_data.get('cipher', {}).get('name', '')
    for weak in _WEAK_CIPHERS:
        if weak in cipher_name.upper():
            findings.append(f'Weak cipher suite: {cipher_name}')
            break

    sig_alg = cert_data.get('signature_algorithm', '')
    if sig_alg in _DEPRECATED_SIG_ALGS:
        findings.append(f'Deprecated signature algorithm: {sig_alg} — SHA-256 or better recommended')

    issuer = cert_data.get('issuer', {})
    subject = cert_data.get('subject', {})
    if issuer.get('organizationName') == subject.get('organizationName') and issuer.get('commonName') == subject.get('commonName'):
        findings.append('Self-signed certificate detected — not trusted by browsers')

    bits = cert_data.get('cipher', {}).get('bits', 256)
    if isinstance(bits, int) and bits < 128:
        findings.append(f'Cipher key length {bits} bits — critically weak')

    return findings


def run(target: str, port: int = 443) -> dict:
    results = {
        'module': 'SSL/TLS Info',
        'target': target,
        'port': port,
        'certificate': {},
        'findings': [],
        'errors': [],
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, port), timeout=DEFAULT_TIMEOUT) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    results['certificate'] = _parse_cert(cert, ssock)
                else:
                    results['certificate']['protocol'] = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        results['certificate']['cipher'] = {'name': cipher[0], 'protocol': cipher[1], 'bits': cipher[2]}
                    results['errors'].append('Certificate returned no structured data (may be self-signed or malformed)')

    except ssl.SSLError as e:
        results['errors'].append(f'SSL error: {str(e)}')
    except socket.timeout:
        results['errors'].append(f'Connection to {target}:{port} timed out')
    except ConnectionRefusedError:
        results['errors'].append(f'Connection to {target}:{port} refused — SSL/TLS not available on this port')
    except socket.gaierror as e:
        results['errors'].append(f'DNS resolution failed for {target}: {str(e)}')
    except OSError as e:
        results['errors'].append(f'Network error: {str(e)}')

    if results['certificate']:
        results['findings'] = _flag_issues(results['certificate'])

    return results