import re
import httpx
from gravehound import http
from concurrent.futures import ThreadPoolExecutor, as_completed

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'

PROVIDERS = {
    'AWS S3': {
        'url': 'https://{name}.s3.amazonaws.com',
        'open_signals': ['ListBucketResult', '<Contents>'],
        'severity': 'CRITICAL',
    },
    'Azure Blob': {
        'url': 'https://{name}.blob.core.windows.net/{name}?restype=container&comp=list',
        'open_signals': ['EnumerationResults', '<Blobs>'],
        'severity': 'CRITICAL',
    },
    'GCP Storage': {
        'url': 'https://storage.googleapis.com/{name}',
        'open_signals': ['ListBucketResult', '<Contents>'],
        'severity': 'CRITICAL',
    },
    'DigitalOcean Spaces': {
        'url': 'https://{name}.nyc3.digitaloceanspaces.com',
        'open_signals': ['ListBucketResult', '<Contents>'],
        'severity': 'HIGH',
    },
    'Wasabi': {
        'url': 'https://{name}.s3.wasabisys.com',
        'open_signals': ['ListBucketResult', '<Contents>'],
        'severity': 'HIGH',
    },
    'Alibaba OSS': {
        'url': 'https://{name}.oss-us-west-1.aliyuncs.com',
        'open_signals': ['ListBucketResult', '<Contents>'],
        'severity': 'HIGH',
    },
}

SELF_HOSTED_PORTS = [9000, 9001, 8080, 8333, 7480]

SELF_HOSTED_PROBES = [
    {
        'path': '/minio/health/live',
        'fingerprints': [],
        'expect_status': 200,
        'service': 'MinIO',
        'severity': 'CRITICAL',
        'description': 'MinIO health endpoint — confirmed instance',
    },
    {
        'path': '/minio/health/cluster',
        'fingerprints': [],
        'expect_status': 200,
        'service': 'MinIO',
        'severity': 'CRITICAL',
        'description': 'MinIO cluster health — multi-node deployment',
    },
    {
        'path': '/minio',
        'fingerprints': ['MinIO', 'minio', 'Console', 'login'],
        'expect_status': None,
        'service': 'MinIO Console',
        'severity': 'HIGH',
        'description': 'MinIO web console exposed',
    },
    {
        'path': '/?list-type=2',
        'fingerprints': ['ListBucketResult', 'CommonPrefixes', '<Contents>'],
        'expect_status': 200,
        'service': 'S3-Compatible',
        'severity': 'CRITICAL',
        'description': 'S3-compatible API responding to bucket listing',
    },
    {
        'path': '/',
        'fingerprints': ['ListAllMyBucketsResult', '<Buckets>'],
        'expect_status': 200,
        'service': 'S3-Compatible',
        'severity': 'CRITICAL',
        'description': 'S3-compatible API — full bucket listing',
    },
    {
        'path': '/v1/auth',
        'fingerprints': ['X-Storage-Url', 'X-Auth-Token', 'x-storage-url'],
        'expect_status': None,
        'service': 'OpenStack Swift',
        'severity': 'HIGH',
        'description': 'Swift authentication endpoint exposed',
    },
    {
        'path': '/swift/v1',
        'fingerprints': ['application/json', 'text/plain'],
        'expect_status': None,
        'service': 'OpenStack Swift',
        'severity': 'HIGH',
        'description': 'Swift object storage API exposed',
    },
    {
        'path': '/api/v1/buckets',
        'fingerprints': ['"buckets"', '"name"', '"creation_date"'],
        'expect_status': 200,
        'service': 'MinIO Console API',
        'severity': 'CRITICAL',
        'description': 'MinIO console API — bucket listing without auth',
    },
]

PORT_PROBE_MAP = {
    9000: ['/minio/health/live', '/minio/health/cluster', '/?list-type=2', '/', '/api/v1/buckets'],
    9001: ['/minio', '/minio/health/live'],
    8080: ['/v1/auth', '/swift/v1', '/?list-type=2', '/'],
    8333: ['/?list-type=2', '/', '/minio/health/live'],
    7480: ['/', '/?list-type=2'],
}

_PROBE_BY_PATH = {p['path']: p for p in SELF_HOSTED_PROBES}

_HEADER_FINGERPRINTS = {
    'minio': 'MinIO',
    'ceph': 'Ceph RGW',
    'swift': 'OpenStack Swift',
    'riak': 'Riak CS',
    'cloudian': 'Cloudian HyperStore',
    'scality': 'Scality RING',
    'seaweedfs': 'SeaweedFS',
    'garage': 'Garage S3',
}

SUFFIXES = [
    '', '-dev', '-development', '-staging', '-stg', '-prod', '-production',
    '-backup', '-backups', '-bak', '-assets', '-static', '-media', '-data',
    '-logs', '-log', '-uploads', '-upload', '-internal', '-private', '-public',
    '-test', '-testing', '-qa', '-uat', '-cdn', '-files', '-docs', '-documents',
    '-images', '-img', '-archive', '-old', '-temp', '-tmp', '-db', '-database',
    '-config', '-configs', '-secrets', '-keys', '-api', '-web', '-app', '-site',
    '-infra', '-ops', '-devops', '-ci', '-deploy', '-releases', '-artifacts',
]

_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def _extract_base(target: str) -> list[str]:
    try:
        import tldextract
        ext = tldextract.extract(target)
        domain = ext.domain.lower()
    except ImportError:
        parts = target.lower().strip().split('.')
        domain = parts[-2] if len(parts) >= 2 else parts[0]
    bases = {domain}
    stripped = re.sub(r'[\-_]', '', domain)
    if stripped != domain:
        bases.add(stripped)
    no_numbers = re.sub(r'[0-9]+', '', domain)
    if no_numbers and no_numbers != domain:
        bases.add(no_numbers)
    return sorted(bases)


def _detect_header_fingerprint(resp: httpx.Response) -> str | None:
    server = resp.headers.get('server', '').lower()
    x_amz = resp.headers.get('x-amz-request-id', '')
    x_minio = resp.headers.get('x-minio-deployment-id', '')
    if x_minio:
        return 'MinIO'
    garage_headers = [k for k in resp.headers.keys() if k.lower().startswith('x-garage')]
    if garage_headers:
        return 'Garage S3'
    for sig, name in _HEADER_FINGERPRINTS.items():
        if sig in server:
            return name
    if x_amz and 'amazonaws' not in resp.url.host:
        return 'S3-Compatible (self-hosted)'
    return None


def _check_bucket(name: str, provider_name: str, provider: dict) -> dict | None:
    url = provider['url'].replace('{name}', name)
    try:
        with http.Client(timeout=8, verify=False, headers={'User-Agent': _UA}, follow_redirects=False) as client:
            resp = client.get(url)
            body = resp.text[:2000]
            header_fp = _detect_header_fingerprint(resp)
            if header_fp:
                return {
                    'name': name,
                    'provider': f'{provider_name} ({header_fp})',
                    'url': url,
                    'status': 'FINGERPRINTED',
                    'listable': False,
                    'status_code': resp.status_code,
                    'severity': 'HIGH',
                    'header_fingerprint': header_fp,
                }
            if resp.status_code == 200:
                is_listable = any(sig in body for sig in provider['open_signals'])
                return {
                    'name': name,
                    'provider': provider_name,
                    'url': url,
                    'status': 'OPEN' if is_listable else 'EXISTS',
                    'listable': is_listable,
                    'status_code': resp.status_code,
                    'severity': provider['severity'] if is_listable else 'MEDIUM',
                }
            elif resp.status_code == 403:
                return {
                    'name': name,
                    'provider': provider_name,
                    'url': url,
                    'status': 'EXISTS',
                    'listable': False,
                    'status_code': 403,
                    'severity': 'LOW',
                }
    except Exception:
        pass
    return None


def _probe_self_hosted(host: str, port: int, probe: dict) -> dict | None:
    for proto in ('https', 'http'):
        url = f'{proto}://{host}:{port}{probe["path"]}'
        try:
            with http.Client(timeout=5, verify=False, headers={'User-Agent': _UA}, follow_redirects=True) as client:
                resp = client.get(url)
                header_fp = _detect_header_fingerprint(resp)
                if header_fp:
                    return {
                        'name': f'{host}:{port}',
                        'provider': header_fp,
                        'url': url,
                        'status': 'SELF-HOSTED',
                        'listable': False,
                        'status_code': resp.status_code,
                        'severity': 'HIGH',
                        'service': header_fp,
                        'path': probe['path'],
                        'description': f'Server header fingerprint: {header_fp}',
                    }
                status_ok = (probe['expect_status'] is None) or (resp.status_code == probe['expect_status'])
                if probe['fingerprints']:
                    body = resp.text[:3000]
                    headers_str = str(resp.headers)
                    combined = body + headers_str
                    body_ok = any(fp.lower() in combined.lower() for fp in probe['fingerprints'])
                else:
                    body_ok = True
                if not (status_ok and body_ok):
                    continue
                return {
                    'name': f'{host}:{port}',
                    'provider': probe['service'],
                    'url': url,
                    'status': 'SELF-HOSTED',
                    'listable': probe['severity'] == 'CRITICAL',
                    'status_code': resp.status_code,
                    'severity': probe['severity'],
                    'service': probe['service'],
                    'path': probe['path'],
                    'description': probe['description'],
                }
        except Exception:
            continue
    return None


def run(target: str, context: dict | None = None) -> dict:
    results = {
        'module': 'Cloud Storage',
        'target': target,
        'buckets_found': [],
        'exists_but_private': [],
        'self_hosted': [],
        'total_checked': 0,
        'providers_checked': list(PROVIDERS.keys()) + ['MinIO', 'Ceph', 'Swift', 'S3-Compatible'],
        'findings': [],
        'errors': [],
    }
    bases = _extract_base(target)
    names = list(dict.fromkeys([f'{base}{suffix}' for base in bases for suffix in SUFFIXES]))
    cloud_tasks = []
    for name in names:
        for prov_name, prov_info in PROVIDERS.items():
            cloud_tasks.append((name, prov_name, prov_info))
    self_hosted_hosts = [target]
    if context and isinstance(context, dict):
        ctx_results = context.get('results', {})
        sub_data = ctx_results.get('subdomains', {})
        if isinstance(sub_data, dict):
            discovered_subs = sub_data.get('subdomains', [])
            storage_keywords = ('s3', 'minio', 'storage', 'object', 'swift', 'ceph', 'blob', 'cdn', 'assets', 'files', 'backup', 'data')
            for sub in discovered_subs:
                if any(kw in sub.lower() for kw in storage_keywords):
                    self_hosted_hosts.append(sub)
            self_hosted_hosts = list(dict.fromkeys(self_hosted_hosts))[:10]
    self_hosted_tasks = []
    for host in self_hosted_hosts:
        for port in SELF_HOSTED_PORTS:
            allowed_paths = PORT_PROBE_MAP.get(port, [])
            for path in allowed_paths:
                probe = _PROBE_BY_PATH.get(path)
                if probe:
                    self_hosted_tasks.append((host, port, probe))
    results['total_checked'] = len(cloud_tasks) + len(self_hosted_tasks)
    seen_sh = set()
    with ThreadPoolExecutor(max_workers=20) as executor:
        cloud_futures = {
            executor.submit(_check_bucket, name, prov_name, prov_info): ('cloud', name, prov_name)
            for name, prov_name, prov_info in cloud_tasks
        }
        sh_futures = {
            executor.submit(_probe_self_hosted, host, port, probe): ('sh', host, port)
            for host, port, probe in self_hosted_tasks
        }
        all_futures = {**cloud_futures, **sh_futures}
        for future in as_completed(all_futures):
            origin = all_futures[future]
            try:
                result = future.result()
                if not result:
                    continue
                if origin[0] == 'cloud':
                    if result['status'] == 'OPEN':
                        results['buckets_found'].append(result)
                        results['findings'].append(
                            f'[{result["severity"]}] OPEN BUCKET: {result["provider"]} — {result["url"]}'
                        )
                    elif result['status'] == 'FINGERPRINTED':
                        dedup_key = (result['url'].split('://')[1].split('/')[0], result.get('header_fingerprint', ''))
                        if dedup_key not in seen_sh:
                            seen_sh.add(dedup_key)
                            results['self_hosted'].append(result)
                            results['findings'].append(
                                f'[{result["severity"]}] HEADER FINGERPRINT: {result.get("header_fingerprint", "")} at {result["url"]}'
                            )
                    elif result['status'] == 'EXISTS':
                        results['exists_but_private'].append(result)
                else:
                    dedup_key = (result['name'], result.get('service', ''))
                    if dedup_key not in seen_sh:
                        seen_sh.add(dedup_key)
                        results['self_hosted'].append(result)
                        results['findings'].append(
                            f'[{result["severity"]}] SELF-HOSTED: {result.get("service", "")} at {result["url"]} — {result.get("description", "")}'
                        )
            except Exception as e:
                results['errors'].append(f'Check failed: {str(e)}')
    results['buckets_found'].sort(key=lambda x: _SEVERITY_ORDER.get(x.get('severity', 'LOW'), 99))
    results['self_hosted'].sort(key=lambda x: _SEVERITY_ORDER.get(x.get('severity', 'LOW'), 99))
    private_total = len(results['exists_but_private'])
    results['exists_but_private'] = results['exists_but_private'][:50]
    if private_total > 50:
        results['exists_but_private_truncated'] = private_total
    total_open = len(results['buckets_found'])
    total_sh = len(results['self_hosted'])
    if total_open:
        results['findings'].insert(
            0,
            f'{total_open} OPEN cloud storage bucket(s) — immediate remediation required'
        )
    if total_sh:
        results['findings'].insert(
            0 if not total_open else 1,
            f'{total_sh} self-hosted storage instance(s) detected'
        )
    return results
