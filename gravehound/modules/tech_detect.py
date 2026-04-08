import re
import httpx
from gravehound.config import DEFAULT_TIMEOUT

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'
TECH_SIGNATURES = {
    'headers': {
        'server': {
            'Apache': r'Apache',
            'Nginx': r'nginx',
            'IIS': r'Microsoft-IIS',
            'LiteSpeed': r'LiteSpeed',
            'Cloudflare': r'cloudflare',
            'Caddy': r'Caddy',
            'Gunicorn': r'gunicorn',
            'Cowboy': r'Cowboy',
            'Openresty': r'openresty',
            'Tomcat': r'Apache-Coyote|Tomcat',
            'Jetty': r'Jetty',
            'Kestrel': r'Kestrel',
        },
        'x-powered-by': {
            'PHP': r'PHP',
            'ASP.NET': r'ASP\.NET',
            'Express.js': r'Express',
            'Next.js': r'Next\.js',
            'Nuxt.js': r'Nuxt',
            'Flask': r'Flask',
            'Django': r'Django',
            'Ruby on Rails': r'Phusion Passenger',
        },
        'x-generator': {
            'WordPress': r'WordPress',
            'Drupal': r'Drupal',
        },
        'cf-ray': {'Cloudflare': r'.+'},
        'x-amz-cf-id': {'AWS CloudFront': r'.+'},
        'x-azure-ref': {'Azure CDN': r'.+'},
        'x-vercel-id': {'Vercel': r'.+'},
        'x-fastly-request-id': {'Fastly': r'.+'},
    },
    'html': {
        'WordPress': [r'wp-content', r'wp-includes', r'<meta name=["\']generator["\'] content=["\']WordPress'],
        'Drupal': [r'\bDrupal\b', r'drupal\.js', r'/sites/default/files'],
        'Joomla': [r'/media/jui/', r'<meta name=["\']generator["\'] content=["\']Joomla'],
        'Shopify': [r'cdn\.shopify\.com', r'Shopify\.theme'],
        'Wix': [r'wix\.com', r'X-Wix-'],
        'Squarespace': [r'squarespace', r'static\.squarespace'],
        'React': [r'react(?:\.min)?\.js', r'__NEXT_DATA__', r'_react'],
        'Vue.js': [r'vue(?:\.min)?\.js', r'__vue__', r'v-app'],
        'Angular': [r'ng-version', r'\bangular\b', r'ng-app'],
        'Svelte': [r'svelte', r'__SVELTE__'],
        'Next.js': [r'__NEXT_DATA__', r'/_next/static'],
        'Nuxt.js': [r'__NUXT__', r'/_nuxt/'],
        'Gatsby': [r'___gatsby', r'/static/gatsby'],
        'jQuery': [r'jquery(?:\.min)?\.js'],
        'Bootstrap': [r'bootstrap(?:\.min)?\.css', r'bootstrap(?:\.min)?\.js'],
        'Tailwind CSS': [r'tailwindcss', r'tailwind\.css'],
        'Bulma': [r'bulma(?:\.min)?\.css'],
        'Google Analytics': [r'google-analytics\.com', r'gtag\(', r'GoogleAnalyticsObject'],
        'Google Tag Manager': [r'googletagmanager\.com', r'gtm\.js'],
        'HubSpot': [r'js\.hubspot\.net', r'hs-scripts\.com'],
        'Intercom': [r'intercom\.io', r'intercomcdn'],
        'Cloudflare': [r'cloudflare', r'cf-ray', r'__cf_bm'],
        'reCAPTCHA': [r'recaptcha', r'google\.com/recaptcha'],
        'Font Awesome': [r'font-awesome', r'fontawesome'],
        'Google Fonts': [r'fonts\.googleapis\.com', r'fonts\.gstatic\.com'],
        'Stripe': [r'js\.stripe\.com', r'Stripe\('],
        'Sentry': [r'browser\.sentry-cdn\.com', r'Sentry\.init'],
        'Datadog': [r'datadoghq\.com', r'datadog-rum'],
    },
    'cookies': {
        'PHP': r'PHPSESSID',
        'ASP.NET': r'ASP\.NET_SessionId',
        'Java': r'JSESSIONID',
        'Laravel': r'laravel_session',
        'Django': r'csrftoken',
        'Rails': r'_rails_session',
        'WordPress': r'wordpress_',
        'Shopify': r'_shopify_',
        'Ghost': r'ghost-admin-api-session',
    },

}
_CATEGORY_MAP = {
    'server': ['Apache', 'Nginx', 'IIS', 'LiteSpeed', 'Caddy', 'Gunicorn', 'Cowboy', 'Openresty', 'Tomcat', 'Jetty', 'Kestrel'],
    'framework': ['PHP', 'ASP.NET', 'Express.js', 'Next.js', 'Nuxt.js', 'Flask', 'Django', 'Ruby on Rails', 'Laravel', 'Rails'],
    'cms': ['WordPress', 'Drupal', 'Joomla', 'Shopify', 'Wix', 'Squarespace', 'Ghost'],
    'javascript': ['React', 'Vue.js', 'Angular', 'jQuery', 'Svelte', 'Gatsby'],
    'css_framework': ['Bootstrap', 'Tailwind CSS', 'Bulma'],
    'cdn': ['Cloudflare', 'AWS CloudFront', 'Azure CDN', 'Vercel', 'Fastly'],
    'analytics': ['Google Analytics', 'Google Tag Manager', 'HubSpot', 'Intercom', 'Datadog', 'Sentry'],
    'payment': ['Stripe'],
    'security': ['reCAPTCHA'],

}
_RISKY_TECH = {
    'jQuery': 'jQuery versions < 3.x have known XSS vulnerabilities — verify version is patched',
    'PHP': 'PHP exposed via headers — remove x-powered-by to avoid fingerprinting',
    'ASP.NET': 'ASP.NET version disclosed — remove x-powered-by header',
    'WordPress': 'WordPress detected — ensure wp-login.php is protected and plugins are updated',
    'Drupal': 'Drupal detected — ensure core and modules are patched (Drupalgeddon risk)',

}

def run(target: str) -> dict:
    results = {
        'module': 'Technology Detection',
        'target': target,
        'technologies': [],
        'categories': {k: [] for k in _CATEGORY_MAP},
        'categories': {**{k: [] for k in _CATEGORY_MAP}, 'other': []},
        'findings': [],
        'errors': [],
    }
    detected: set[str] = set()
    for url in [f'https://{target}', f'http://{target}']:
        try:
            with httpx.Client(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=True,
                verify=False,
                headers={'User-Agent': _UA},
            ) as client:
                response = client.get(url)
                headers = response.headers
                body = response.text[:80000]
                cookies_str = str(response.cookies)
                for header_name, patterns in TECH_SIGNATURES['headers'].items():
                    header_value = headers.get(header_name, '')
                    if not header_value:
                        continue
                    for tech_name, pattern in patterns.items():
                        if re.search(pattern, header_value, re.IGNORECASE):
                            detected.add(tech_name)
                for tech_name, patterns in TECH_SIGNATURES['html'].items():
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            detected.add(tech_name)
                            break
                for tech_name, pattern in TECH_SIGNATURES['cookies'].items():
                    if re.search(pattern, cookies_str, re.IGNORECASE):
                        detected.add(tech_name)
                break
        except httpx.ConnectError:
            continue
        except httpx.TimeoutException:
            results['errors'].append(f'Timeout connecting to {url}')
            continue
        except Exception as e:
            results['errors'].append(f'Error detecting tech at {url}: {type(e).__name__}: {str(e)}')
            continue
    for tech in sorted(detected):
        results['technologies'].append(tech)
        placed = False
        for category, techs in _CATEGORY_MAP.items():
            if tech in techs:
                results['categories'][category].append(tech)
                placed = True
                break
        if not placed:
            results['categories']['other'].append(tech)
        if tech in _RISKY_TECH:
            results['findings'].append(_RISKY_TECH[tech])
    results['categories'] = {k: v for k, v in results['categories'].items() if v}
    return results
