import time
import httpx
from gravehound import http
from gravehound.config import WAYBACK_API_URL, DEFAULT_TIMEOUT

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0; +https://github.com/WIzbisy/gravehound)'
MAX_SNAPSHOTS = 50
_MAX_RETRIES = 2

def _format_ts(ts: str) -> str:
    if len(ts) >= 8:
        return f'{ts[:4]}-{ts[4:6]}-{ts[6:8]}'
    return ts

def _safe_get(client: httpx.Client, url: str) -> httpx.Response | None:
    for attempt in range(_MAX_RETRIES + 1):
        try:
            return client.get(url)
        except httpx.TimeoutException:
            if attempt == _MAX_RETRIES:
                raise
            time.sleep(0.5 * (2 ** attempt))
        except httpx.HTTPStatusError:
            raise
    return None

def run(target: str) -> dict:
    results = {
        'module': 'Wayback Machine',
        'target': target,
        'has_archive': False,
        'snapshots': [],
        'total_snapshots': 0,
        'truncated': False,
        'unique_mime_types': [],
        'summary': {
            'first_seen': None,
            'last_seen': None,
            'snapshot_count': 0,
            'archive_age_years': None,
        },
        'errors': [],
    }
    headers = {'User-Agent': _UA}
    with http.Client(timeout=DEFAULT_TIMEOUT, headers=headers) as client:
        try:
            url = WAYBACK_API_URL.replace('{target}', target)
            resp = _safe_get(client, url)
            if resp and resp.status_code == 200:
                data = resp.json()
                closest = data.get('archived_snapshots', {}).get('closest')
                if closest:
                    results['has_archive'] = True
                    results['snapshots'].append({
                        'url': closest.get('url', ''),
                        'timestamp': closest.get('timestamp', ''),
                        'status': closest.get('status', ''),
                        'available': closest.get('available', False),
                        'source': 'availability_api',
                    })
        except httpx.TimeoutException:
            results['errors'].append({'source': 'availability_api', 'reason': 'timeout'})
        except Exception as e:
            results['errors'].append({'source': 'availability_api', 'reason': str(e)})
        try:
            cdx_url = (
                f'https://web.archive.org/cdx/search/cdx'
                f'?url={target}'
                f'&output=json'
                f'&limit={MAX_SNAPSHOTS}'
                f'&fl=timestamp,statuscode,original,mimetype'
                f'&collapse=timestamp:6'
                f'&filter=statuscode:200'
            )
            resp = _safe_get(client, cdx_url)
            if resp and resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    headers_row = data[0]
                    rows = data[1:]
                    mime_types: set[str] = set()
                    timestamps: list[str] = []
                    for row in rows:
                        entry = dict(zip(headers_row, row))
                        ts = entry.get('timestamp', '')
                        formatted_date = _format_ts(ts)
                        mime = entry.get('mimetype', '')
                        if mime:
                            mime_types.add(mime)
                        if ts:
                            timestamps.append(ts)
                        results['snapshots'].append({
                            'url': f"https://web.archive.org/web/{ts}/{entry.get('original', '')}",
                            'timestamp': formatted_date,
                            'status': entry.get('statuscode', ''),
                            'mimetype': mime,
                            'source': 'cdx_api',
                        })
                    results['has_archive'] = True
                    results['total_snapshots'] = len(rows)
                    results['truncated'] = len(rows) >= MAX_SNAPSHOTS
                    results['unique_mime_types'] = sorted(mime_types)
                    if timestamps:
                        timestamps_sorted = sorted(timestamps)
                        first_ts = timestamps_sorted[0]
                        last_ts = timestamps_sorted[-1]
                        results['summary']['first_seen'] = _format_ts(first_ts)
                        results['summary']['last_seen'] = _format_ts(last_ts)
                        results['summary']['snapshot_count'] = len(timestamps)
                        try:
                            first_year = int(first_ts[:4])
                            import datetime
                            current_year = datetime.datetime.utcnow().year
                            results['summary']['archive_age_years'] = current_year - first_year
                        except (ValueError, IndexError):
                            pass
        except httpx.TimeoutException:
            results['errors'].append({'source': 'cdx_api', 'reason': 'timeout'})
        except Exception as e:
            results['errors'].append({'source': 'cdx_api', 'reason': str(e)})
    return results
