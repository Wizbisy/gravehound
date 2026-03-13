import httpx
import re

def run(target: str) -> dict:
    results = {
        'module': 'Dependency Chain',
        'target': target,
        'dependencies': [],
        'vulnerabilities': [],
        'errors': []
    }
    
    success = False
    html = ""
    for proto in ['https', 'http']:
        try:
            with httpx.Client(timeout=10, verify=False) as client:
                resp = client.get(f"{proto}://{target}")
                if resp.status_code == 200:
                    html = resp.text
                    success = True
                    break
        except httpx.RequestError as e:
            results['errors'].append(f"Connection failed: {str(e)}")
            continue
        except Exception:
            continue
            
    if not success:
        return results
        
    try:
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for src in scripts:
            version_match = re.search(r'([a-zA-Z0-9_-]+)[-@/]([0-9]+\.[0-9]+(?:\.[0-9]+)?)', src)
            if version_match:
                lib_name = version_match.group(1).lower().replace('.min', '').replace('min', '').strip('-')
                version = version_match.group(2)
                if not lib_name or len(lib_name) < 2:
                    continue
                    
                dep = f"{lib_name} v{version}"
                if dep not in results['dependencies']:
                    results['dependencies'].append(dep)
                    
                    if 'jquery' in lib_name and version.startswith('1.'):
                        results['vulnerabilities'].append(f"Vulnerable Library Detected: {dep} (Known XSS CVEs in 1.x)")
                    elif 'react' in lib_name and version.startswith('15.'):
                        results['vulnerabilities'].append(f"Outdated React detected: {dep} (Cross-Site Scripting risks)")
                    elif 'angular' in lib_name and version.startswith('1.'):
                        results['vulnerabilities'].append(f"Vulnerable AngularJS: {dep} (EOL and known CVEs)")
                    elif 'vue' in lib_name and version.startswith('1.'):
                        results['vulnerabilities'].append(f"Outdated Vue.js detected: {dep} (CVE-2021-X)")
    except Exception as e:
        results['errors'].append(f"Dependency scan error: {str(e)}")
        
    return results
