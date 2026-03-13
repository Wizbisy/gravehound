def run(target: str) -> dict:
    results = {
        'module': 'DOM Fingerprint',
        'target': target,
        'frameworks': [],
        'errors': []
    }
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        results['errors'].append("Playwright is not installed. Run 'pip install playwright' and 'playwright install chromium'")
        return results

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=['--log-level=3', '--silent', '--mute-audio'])
            page = browser.new_page()
            page.set_default_timeout(10000)
            
            success = False
            for proto in ['http', 'https']:
                try:
                    page.goto(f"{proto}://{target}")
                    success = True
                    break
                except Exception:
                    continue
                    
            if not success:
                results['errors'].append("Failed to load page in headless browser.")
                browser.close()
                return results

            if page.evaluate("() => !!window.React || !!document.querySelector('[data-reactroot], [data-reactid]')"):
                results['frameworks'].append('React')
            
            if page.evaluate("() => !!window.angular || !!document.querySelector('.ng-binding, [ng-app], [data-ng-app], [ng-controller], [ng-version]')"):
                results['frameworks'].append('Angular')
            
            if page.evaluate("() => !!window.Vue || !!document.querySelector('[data-v-app], [data-server-rendered]')"):
                results['frameworks'].append('Vue.js')
            
            if page.evaluate("() => !!window.__NEXT_DATA__ || !!document.querySelector('#__next')"):
                results['frameworks'].append('Next.js')
            
            if page.evaluate("() => !!window.__NUXT__ || !!document.querySelector('#__nuxt')"):
                results['frameworks'].append('Nuxt.js')
            
            if page.evaluate("() => !!window.__svelte || !!document.querySelector('.svelte-')"):
                results['frameworks'].append('Svelte')
                
            if page.evaluate("() => !!window.jQuery || !!window.$"):
                results['frameworks'].append('jQuery')

            browser.close()
    except Exception as e:
        results['errors'].append(f"Playwright error: {str(e)}")
        
    return results
