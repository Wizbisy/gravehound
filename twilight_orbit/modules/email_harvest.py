"""Email Harvesting Module: Discover email addresses associated with a domain."""

import re
import os
import httpx

from twilight_orbit.config import DEFAULT_TIMEOUT, HUNTER_API_URL


def _extract_emails(text: str, domain: str) -> set:
    """Extract email addresses from text, filtering by domain."""
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    all_emails = set(re.findall(pattern, text.lower()))
    domain_emails = {email for email in all_emails if domain.lower() in email}
    return domain_emails


def _search_website(target: str) -> set:
    """Scrape the target website for email addresses."""
    emails = set()
    pages = [
        f"https://{target}",
        f"https://{target}/contact",
        f"https://{target}/about",
        f"https://{target}/about-us",
        f"https://{target}/contact-us",
        f"https://{target}/team",
        f"https://{target}/privacy",
        f"https://{target}/privacy-policy",
        f"http://{target}",
    ]

    with httpx.Client(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; TwilightOrbit/1.0)"},
    ) as client:
        for url in pages:
            try:
                response = client.get(url)
                if response.status_code == 200:
                    found = _extract_emails(response.text, target)
                    emails.update(found)
            except Exception:
                continue

    return emails


def run(target: str) -> dict:
    """
    Discover email addresses associated with the target domain.
    
    Returns:
        dict with discovered email addresses and their sources
    """
    results = {
        "module": "Email Harvesting",
        "target": target,
        "emails": [],
        "total": 0,
        "errors": [],
    }

    discovered = set()

    try:
        web_emails = _search_website(target)
        discovered.update(web_emails)
    except Exception as e:
        results["errors"].append(f"Website scraping error: {str(e)}")

    common_patterns = [
        f"info@{target}",
        f"admin@{target}",
        f"contact@{target}",
        f"support@{target}",
        f"hello@{target}",
        f"sales@{target}",
        f"webmaster@{target}",
    ]

    hunter_key = os.getenv("HUNTER_API_KEY")
    if hunter_key:
        try:
            url = HUNTER_API_URL.replace("{target}", target).replace("{api_key}", hunter_key)
            with httpx.Client(timeout=10, verify=False) as client:
                res = client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    emails = data.get("data", {}).get("emails", [])
                    for e in emails:
                        discovered.add(e.get("value"))
                elif res.status_code == 401:
                    results["errors"].append("Hunter.io API Key is invalid")
        except Exception as e:
            results["errors"].append(f"Hunter.io API error: {str(e)}")

    results["common_patterns"] = common_patterns
    results["emails"] = sorted(list(discovered))
    results["total"] = len(discovered)

    return results
