import httpx
from gravehound import http
from concurrent.futures import ThreadPoolExecutor, as_completed

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'

PROBE_PATHS = [
    {'path': '/.git/HEAD',                    'fingerprints': ['ref: refs/heads/', 'ref: refs/'],                                'severity': 'CRITICAL', 'category': 'Version Control'},
    {'path': '/.git/config',                  'fingerprints': ['[core]', '[remote', 'repositoryformatversion'],                  'severity': 'CRITICAL', 'category': 'Version Control'},
    {'path': '/.gitignore',                   'fingerprints': ['node_modules', '.env', '__pycache__', '*.pyc', '.DS_Store'],     'severity': 'MEDIUM',   'category': 'Version Control'},
    {'path': '/.svn/entries',                 'fingerprints': ['dir', 'svn:'],                                                   'severity': 'HIGH',     'category': 'Version Control'},
    {'path': '/.hg/hgrc',                     'fingerprints': ['[paths]', '[ui]'],                                               'severity': 'HIGH',     'category': 'Version Control'},
    {'path': '/.env',                         'fingerprints': ['APP_KEY=', 'DB_PASSWORD=', 'SECRET_KEY=', 'API_KEY=', 'DATABASE_URL=', 'AWS_', 'REDIS_URL='], 'severity': 'CRITICAL', 'category': 'Environment'},
    {'path': '/.env.bak',                     'fingerprints': ['APP_KEY=', 'DB_PASSWORD=', 'SECRET_KEY=', 'DATABASE_URL='],      'severity': 'CRITICAL', 'category': 'Environment'},
    {'path': '/.env.local',                   'fingerprints': ['APP_KEY=', 'DB_PASSWORD=', 'SECRET_KEY='],                       'severity': 'CRITICAL', 'category': 'Environment'},
    {'path': '/.env.production',              'fingerprints': ['APP_KEY=', 'DB_PASSWORD=', 'SECRET_KEY='],                       'severity': 'CRITICAL', 'category': 'Environment'},
    {'path': '/.env.staging',                 'fingerprints': ['APP_KEY=', 'DB_PASSWORD=', 'SECRET_KEY='],                       'severity': 'CRITICAL', 'category': 'Environment'},
    {'path': '/.env.development',             'fingerprints': ['APP_KEY=', 'DB_PASSWORD=', 'SECRET_KEY='],                       'severity': 'HIGH',     'category': 'Environment'},
    {'path': '/.env.example',                 'fingerprints': ['APP_KEY=', 'DB_PASSWORD=', 'SECRET_KEY=', 'API_KEY=', 'DATABASE_URL='], 'severity': 'HIGH', 'category': 'Environment'},
    {'path': '/docker-compose.yml',           'fingerprints': ['version:', 'services:', 'image:', 'container_name:'],            'severity': 'HIGH',     'category': 'Container'},
    {'path': '/docker-compose.yaml',          'fingerprints': ['version:', 'services:', 'image:'],                               'severity': 'HIGH',     'category': 'Container'},
    {'path': '/Dockerfile',                   'fingerprints': ['FROM ', 'RUN ', 'CMD ', 'EXPOSE ', 'ENTRYPOINT'],               'severity': 'MEDIUM',   'category': 'Container'},
    {'path': '/.dockerenv',                   'fingerprints': [],                                                                'severity': 'LOW',      'category': 'Container'},
    {'path': '/phpinfo.php',                  'fingerprints': ['phpinfo()', 'PHP Version', 'Configuration', 'php.ini'],          'severity': 'HIGH',     'category': 'Server Config'},
    {'path': '/info.php',                     'fingerprints': ['phpinfo()', 'PHP Version', 'Configuration'],                     'severity': 'HIGH',     'category': 'Server Config'},
    {'path': '/.htaccess',                    'fingerprints': ['RewriteEngine', 'RewriteRule', 'Deny from', 'AuthType'],         'severity': 'MEDIUM',   'category': 'Server Config'},
    {'path': '/.htpasswd',                    'fingerprints': [':$apr1$', ':$2y$', ':{SHA}'],                                    'severity': 'CRITICAL', 'category': 'Server Config'},
    {'path': '/web.config',                   'fingerprints': ['<configuration>', '<system.web>', 'connectionString'],            'severity': 'HIGH',     'category': 'Server Config'},
    {'path': '/server-status',                'fingerprints': ['Apache Server Status', 'Total accesses', 'Server uptime'],       'severity': 'MEDIUM',   'category': 'Server Config'},
    {'path': '/server-info',                  'fingerprints': ['Apache Server Information', 'Module Name'],                       'severity': 'MEDIUM',   'category': 'Server Config'},
    {'path': '/wp-config.php.bak',            'fingerprints': ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'table_prefix'],             'severity': 'CRITICAL', 'category': 'CMS'},
    {'path': '/wp-config.php~',               'fingerprints': ['DB_NAME', 'DB_USER', 'DB_PASSWORD'],                             'severity': 'CRITICAL', 'category': 'CMS'},
    {'path': '/wp-config.php.old',            'fingerprints': ['DB_NAME', 'DB_USER', 'DB_PASSWORD'],                             'severity': 'CRITICAL', 'category': 'CMS'},
    {'path': '/robots.txt',                   'fingerprints': ['Disallow:', 'Allow:', 'User-agent:'],                            'severity': 'INFO',     'category': 'Intelligence'},
    {'path': '/sitemap.xml',                  'fingerprints': ['<urlset', '<sitemapindex', '<url>'],                              'severity': 'INFO',     'category': 'Intelligence'},
    {'path': '/crossdomain.xml',              'fingerprints': ['<cross-domain-policy', 'allow-access-from'],                     'severity': 'MEDIUM',   'category': 'Policy'},
    {'path': '/.well-known/security.txt',     'fingerprints': ['Contact:', 'Expires:', 'Policy:'],                               'severity': 'INFO',     'category': 'Intelligence'},
    {'path': '/composer.json',                'fingerprints': ['"require"', '"name"', '"autoload"'],                              'severity': 'MEDIUM',   'category': 'Dependencies'},
    {'path': '/package.json',                 'fingerprints': ['"name"', '"version"', '"dependencies"', '"scripts"'],             'severity': 'MEDIUM',   'category': 'Dependencies'},
    {'path': '/Gemfile',                      'fingerprints': ['source', 'gem '],                                                'severity': 'MEDIUM',   'category': 'Dependencies'},
    {'path': '/Makefile',                     'fingerprints': ['all:', 'build:', 'install:', '.PHONY'],                           'severity': 'MEDIUM',   'category': 'Build'},
    {'path': '/.npmrc',                       'fingerprints': ['//registry', '_authToken=', 'registry='],                         'severity': 'HIGH',     'category': 'Dependencies'},
    {'path': '/.pypirc',                      'fingerprints': ['[pypi]', 'username', 'password'],                                'severity': 'HIGH',     'category': 'Dependencies'},
    {'path': '/dump.sql',                     'fingerprints': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE', 'mysqldump'],        'severity': 'CRITICAL', 'category': 'Database'},
    {'path': '/backup.sql',                   'fingerprints': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE'],                     'severity': 'CRITICAL', 'category': 'Database'},
    {'path': '/database.sql',                 'fingerprints': ['CREATE TABLE', 'INSERT INTO'],                                   'severity': 'CRITICAL', 'category': 'Database'},
    {'path': '/.aws/credentials',             'fingerprints': ['aws_access_key_id', 'aws_secret_access_key'],                    'severity': 'CRITICAL', 'category': 'Cloud'},
    {'path': '/.DS_Store',                    'fingerprints': [],                                                                'severity': 'LOW',      'category': 'Metadata'},
    {'path': '/config.yml',                   'fingerprints': ['database:', 'host:', 'password:', 'secret:'],                    'severity': 'HIGH',     'category': 'Config'},
    {'path': '/config.yaml',                  'fingerprints': ['database:', 'host:', 'password:'],                               'severity': 'HIGH',     'category': 'Config'},
    {'path': '/config.json',                  'fingerprints': ['"database"', '"password"', '"secret"', '"apiKey"'],               'severity': 'HIGH',     'category': 'Config'},
    {'path': '/application.yml',              'fingerprints': ['spring:', 'datasource:', 'server:'],                             'severity': 'HIGH',     'category': 'Config'},
    {'path': '/application.properties',       'fingerprints': ['spring.datasource', 'server.port', 'spring.jpa'],                'severity': 'HIGH',     'category': 'Config'},
    {'path': '/.vscode/settings.json',        'fingerprints': ['"editor.', '"files.'],                                           'severity': 'LOW',      'category': 'IDE'},
    {'path': '/.idea/workspace.xml',          'fingerprints': ['<?xml', '<project'],                                             'severity': 'LOW',      'category': 'IDE'},
    {'path': '/debug/vars',                   'fingerprints': ['cmdline', 'memstats'],                                           'severity': 'HIGH',     'category': 'Debug'},
    {'path': '/debug/pprof/',                 'fingerprints': ['Types of profiles', 'goroutine', 'heap'],                        'severity': 'HIGH',     'category': 'Debug'},
    {'path': '/actuator',                     'fingerprints': ['"_links"', '"self"', '"health"'],                                'severity': 'HIGH',     'category': 'Debug'},
    {'path': '/actuator/env',                 'fingerprints': ['"propertySources"', '"activeProfiles"'],                          'severity': 'CRITICAL', 'category': 'Debug'},
    {'path': '/.travis.yml',                  'fingerprints': ['language:', 'script:', 'install:'],                               'severity': 'MEDIUM',   'category': 'CI/CD'},
    {'path': '/.github/workflows',            'fingerprints': [],                                                                'severity': 'LOW',      'category': 'CI/CD'},
    {'path': '/Jenkinsfile',                  'fingerprints': ['pipeline', 'agent', 'stages', 'steps'],                          'severity': 'MEDIUM',   'category': 'CI/CD'},
]

_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

_FALSE_POSITIVE_SIGNALS = [
    '<html', '<!DOCTYPE', '<head>', '404', 'not found', 'page not found',
    'forbidden', 'access denied',
]

_EMPTY_FP_EXTRA_SIGNALS = ['login', 'sign in', 'redirect', 'sign up', 'register']


def _check_path(base_url: str, probe: dict) -> dict | None:
    url = f'{base_url}{probe["path"]}'
    try:
        with http.Client(timeout=8,
            verify=False,
            follow_redirects=False,
            headers={'User-Agent': _UA},
        ) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                body = resp.text[:4000]
                if probe['fingerprints']:
                    matched = [fp for fp in probe['fingerprints'] if fp.lower() in body.lower()]
                    if not matched:
                        return None
                    evidence = matched[0]
                else:
                    if len(resp.content) < 5:
                        return None
                    lower_body = body.lower()
                    if any(sig in lower_body for sig in _FALSE_POSITIVE_SIGNALS):
                        return None
                    if any(sig in lower_body for sig in _EMPTY_FP_EXTRA_SIGNALS):
                        return None
                    evidence = f'{len(resp.content)} bytes'
                return {
                    'path': probe['path'],
                    'url': url,
                    'severity': probe['severity'],
                    'category': probe['category'],
                    'status_code': resp.status_code,
                    'evidence': evidence if isinstance(evidence, str) else str(evidence),
                    'content_length': len(resp.content),
                }
    except Exception:
        pass
    return None


def run(target: str, context: dict | None = None) -> dict:
    results = {
        'module': 'Exposed Configs & Dotfiles',
        'target': target,
        'exposed': [],
        'total_checked': 0,
        'hosts_scanned': [],
        'category_summary': {},
        'findings': [],
        'errors': [],
    }
    hosts = [target]
    if context and isinstance(context, dict):
        ctx_results = context.get('results', {})
        sub_data = ctx_results.get('subdomains', {})
        if isinstance(sub_data, dict):
            discovered_subs = sub_data.get('subdomains', [])
            interesting_prefixes = (
                'api', 'app', 'admin', 'dev', 'staging', 'beta', 'test',
                'internal', 'portal', 'dashboard', 'panel', 'manage', 'cms',
                'blog', 'docs', 'jenkins', 'gitlab', 'jira', 'confluence',
                'grafana', 'kibana', 'sonar', 'vault', 'old', 'legacy',
            )
            for sub in discovered_subs:
                sub_lower = sub.lower()
                if any(sub_lower.startswith(f'{p}.') for p in interesting_prefixes):
                    hosts.append(sub)
            hosts = list(dict.fromkeys(hosts))[:15]
    results['hosts_scanned'] = hosts
    all_tasks = []
    for host in hosts:
        for proto in ('https', 'http'):
            base = f'{proto}://{host}'
            for probe in PROBE_PATHS:
                all_tasks.append((base, probe))
    results['total_checked'] = len(all_tasks)
    seen = set()
    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {
            executor.submit(_check_path, base, probe): (base, probe['path'])
            for base, probe in all_tasks
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    host = result['url'].split('://')[1].split('/')[0]
                    dedup_key = (host, result['path'])
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        results['exposed'].append(result)
            except Exception as e:
                results['errors'].append(f'Check failed: {str(e)}')
    results['exposed'].sort(key=lambda x: _SEVERITY_ORDER.get(x.get('severity', 'INFO'), 99))
    cat_summary = {}
    for item in results['exposed']:
        cat = item['category']
        cat_summary[cat] = cat_summary.get(cat, 0) + 1
    results['category_summary'] = cat_summary
    critical_count = sum(1 for e in results['exposed'] if e['severity'] == 'CRITICAL')
    high_count = sum(1 for e in results['exposed'] if e['severity'] == 'HIGH')
    if critical_count:
        results['findings'].insert(0, f'{critical_count} CRITICAL exposed config(s) — immediate remediation required')
    if high_count:
        results['findings'].append(f'{high_count} HIGH severity exposed file(s) found')
    for item in results['exposed']:
        if item['severity'] in ('CRITICAL', 'HIGH'):
            results['findings'].append(f'[{item["severity"]}] {item["path"]} exposed on {item["url"].split("://")[1].split("/")[0]}')
    return results
