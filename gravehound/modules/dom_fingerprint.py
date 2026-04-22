def run(target: str) -> dict:
    results = {
        'module': 'DOM Fingerprint',
        'target': target,
        'frameworks': [],
        'versions': {},
        'meta': {},
        'findings': [],
        'errors': [],
    }
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        results['errors'].append(
            "Playwright not installed — run: pip install playwright && playwright install chromium"
        )
        return results
    JS_PROBES = [
        ('React', "() => { try { return !!(window.React || document.querySelector('[data-reactroot],[data-reactid]')); } catch(e){return false;} }"),
        ('Angular', "() => { try { return !!(window.angular || document.querySelector('.ng-binding,[ng-app],[data-ng-app],[ng-controller],[ng-version]')); } catch(e){return false;} }"),
        ('Vue.js', "() => { try { return !!(window.Vue || window.__vue_app__ || document.querySelector('[data-v-app],[data-server-rendered]')); } catch(e){return false;} }"),
        ('Next.js', "() => { try { return !!(window.__NEXT_DATA__ || document.querySelector('#__next')); } catch(e){return false;} }"),
        ('Nuxt.js', "() => { try { return !!(window.__NUXT__ || document.querySelector('#__nuxt')); } catch(e){return false;} }"),
        ('Svelte', "() => { try { return !!(window.__svelte || document.querySelector('[class*=\"svelte-\"]')); } catch(e){return false;} }"),
        ('jQuery', "() => { try { return !!(window.jQuery || window.$?.fn?.jquery); } catch(e){return false;} }"),
        ('Gatsby', "() => { try { return !!(window.___gatsby || document.querySelector('#gatsby-focus-wrapper')); } catch(e){return false;} }"),
        ('Ember.js', "() => { try { return !!(window.Ember || window.Em); } catch(e){return false;} }"),
        ('Backbone.js', "() => { try { return !!window.Backbone; } catch(e){return false;} }"),
        ('Alpine.js', "() => { try { return !!(window.Alpine || document.querySelector('[x-data]')); } catch(e){return false;} }"),
        ('HTMX', "() => { try { return !!(window.htmx || document.querySelector('[hx-get],[hx-post]')); } catch(e){return false;} }"),
    ]
    JS_VERSIONS = {
        'React': "() => { try { return window.React?.version || null; } catch(e){return null;} }",
        'Vue.js': "() => { try { return window.Vue?.version || window.__vue_app__?.version || null; } catch(e){return null;} }",
        'jQuery': "() => { try { return window.jQuery?.fn?.jquery || null; } catch(e){return null;} }",
        'Angular': "() => { try { return window.angular?.version?.full || null; } catch(e){return null;} }",
    }
    JS_META = {
        'title': "() => document.title || ''",
        'description': "() => document.querySelector('meta[name=\"description\"]')?.content || ''",
        'generator': "() => document.querySelector('meta[name=\"generator\"]')?.content || ''",
        'viewport': "() => document.querySelector('meta[name=\"viewport\"]')?.content || ''",
        'og_title': "() => document.querySelector('meta[property=\"og:title\"]')?.content || ''",
        'canonical': "() => document.querySelector('link[rel=\"canonical\"]')?.href || ''",
        'csrf_meta': "() => !!(document.querySelector('meta[name=\"csrf-token\"],meta[name=\"_token\"]'))",
    }
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-gpu', '--log-level=3', '--mute-audio'],
            )
            from gravehound import tor
            proxy_url = tor.get_proxy()
            proxy_cfg = None
            if proxy_url:
                proxy_cfg = {'server': proxy_url.replace('socks5h://', 'socks5://')}
            
            ctx = browser.new_context(
                user_agent='Mozilla/5.0 (compatible; Gravehound/1.0)',
                ignore_https_errors=True,
                proxy=proxy_cfg,
            )
            page = ctx.new_page()
            page.set_default_timeout(15000)
            loaded = False
            for proto in ('https', 'http'):
                try:
                    page.goto(f'{proto}://{target}', wait_until='networkidle', timeout=15000)
                    loaded = True
                    break
                except PWTimeout:
                    try:
                        page.goto(f'{proto}://{target}', wait_until='domcontentloaded', timeout=10000)
                        loaded = True
                        break
                    except Exception:
                        continue
                except Exception:
                    continue
            if not loaded:
                results['errors'].append('Failed to load page in headless browser — target may be blocking bots')
                browser.close()
                return results
            for tech_name, js in JS_PROBES:
                try:
                    if page.evaluate(js):
                        results['frameworks'].append(tech_name)
                except Exception:
                    pass
            for tech_name, js in JS_VERSIONS.items():
                if tech_name in results['frameworks']:
                    try:
                        ver = page.evaluate(js)
                        if ver:
                            results['versions'][tech_name] = str(ver)
                    except Exception:
                        pass
            for key, js in JS_META.items():
                try:
                    val = page.evaluate(js)
                    if val:
                        results['meta'][key] = val
                except Exception:
                    pass
            if results['meta'].get('generator'):
                results['findings'].append(f'Generator meta tag: {results["meta"]["generator"]} — reveals CMS/platform')
            if not results['meta'].get('csrf_meta'):
                if any(f in results['frameworks'] for f in ('React', 'Vue.js', 'Angular', 'jQuery')):
                    results['findings'].append('No CSRF meta token found in DOM — verify CSRF protection on forms')
            browser.close()
    except Exception as e:
        results['errors'].append(f'Playwright error: {type(e).__name__}: {str(e)}')
    return results
