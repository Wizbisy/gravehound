# Contributing to Gravehound 🐾

First off, thank you for considering contributing to Gravehound! Every contribution helps make this tool better for the security community.

## 🚀 How to Contribute

### Reporting Bugs

1. Open an issue on GitHub
2. Include your Python version, OS, and the full error traceback
3. Describe what you expected vs. what happened

### Suggesting Features

1. Open an issue with the `[Feature Request]` tag
2. Describe the feature and why it would be useful
3. If possible, include examples of expected output

### Submitting Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-new-module`
3. Write your code and tests
4. Ensure your code follows the existing style
5. Submit a Pull Request

## 📦 Adding a New Module

Gravehound is designed to be modular. To add a new recon module:

### ⚠️ Important: Network Requests
All new modules **must** perform HTTP requests using the custom `gravehound.http` library wrapper. 
```python
from gravehound import http

with http.Client(timeout=10) as client:
    # Your request logic here
```
This wrapper automatically injects the `--tor` proxy if configured and provides automatic exponential backoff retries for fragile Tor operations (catching `ConnectTimeout`, `ReadTimeout`, etc.). Do not use raw `httpx`, `requests`, or `urllib` for HTTP traffic. Modules using raw sockets directly (e.g. `port_scanner.py`, `ssl_info.py`) are out-of-scope for the HTTP proxy.

1. Create a new file in `gravehound/modules/your_module.py`
2. Implement a `run()` function with one of these signatures:

   **Standard module** (no cross-module data needed):
   ```python
   def run(target: str) -> dict:
       return {
           "module": "Your Module Name",
           "target": target,
           "findings": [],
           "errors": [],
       }
   ```

   **Context-aware module** (consumes data from earlier modules, e.g. discovered subdomains):
   ```python
   def run(target: str, context: dict | None = None) -> dict:
       results = {
           "module": "Your Module Name",
           "target": target,
           "findings": [],
           "errors": [],
       }
       if context and isinstance(context, dict):
           ctx_results = context.get('results', {})
           sub_data = ctx_results.get('subdomains', {})
           # use discovered subdomains to expand your scan surface
       return results
   ```

   The scanner uses `inspect.signature` to auto-detect the `context` parameter — no registration needed.

3. Register it in `gravehound/scanner.py` in the `MODULES` dict
4. Add a printer function in `gravehound/reporting/console.py` and register in `PRINTERS`
5. Add a renderer in `gravehound/reporting/html_report.py` and register in `MODULE_RENDERERS`

### Module Return Schema

All modules must return a dict with at least these keys. Add your own data keys as needed:

```python
return {
    "module": "Your Module Name",   
    "target": target,               # the target passed into run()
    "your_data_key": [],            # your main results list or dict
    "findings": [],                 
    "errors": [],                 
}
```

**Guidelines:**
- `findings` should be concise, human-readable strings — these appear in the terminal output and HTML report summary. Example: `"3 CRITICAL exposed config(s) found"`
- `errors` should never crash the module — catch exceptions and append to `errors` instead
- Severity levels across all modules follow: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

### False Positive Prevention

Always validate findings against known response fingerprints. A `200` status code alone is not sufficient — check the response body for content that confirms the finding is genuine.

```python
# Bad — flags any 200 response
if resp.status_code == 200:
    findings.append("Found something!")

# Good — confirms content before flagging
FINGERPRINTS = ['ref: refs/heads/', 'repositoryformatversion']
if resp.status_code == 200:
    body = resp.text[:4000]
    matched = [fp for fp in FINGERPRINTS if fp.lower() in body.lower()]
    if matched:
        findings.append(f"Confirmed: {matched[0]}")
```

This is especially important for paths that commonly return custom 200 error pages (login redirects, CDN catch-alls, marketing pages, etc.).

## Testing Your Module

```bash
# Run a targeted scan with only your module
python -m gravehound scan example.com -m your_module

# Generate an HTML report to verify rendering
python -m gravehound scan example.com -m your_module --output test_report.html
```

## ⚖️ Code of Conduct

- Be respectful and constructive
- This tool is for **authorized security testing only**
- Never use Gravehound against targets without permission
- Follow responsible disclosure practices

## 📝 License

By contributing, you agree that your contributions will be licensed under the MIT License.