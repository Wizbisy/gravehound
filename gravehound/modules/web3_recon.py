import re
import math
import httpx
from gravehound import http
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

_UA = 'Mozilla/5.0 (compatible; Gravehound/1.0)'

RPC_PATHS = [
    '/', '/rpc', '/jsonrpc', '/api/rpc', '/eth', '/solana', '/json-rpc',
    '/api/eth', '/api/v1/jsonrpc', '/web3', '/node', '/chain',
]

RPC_PAYLOAD = {
    'jsonrpc': '2.0',
    'method': 'eth_chainId',
    'params': [],
    'id': 1,
}

CHAIN_IDS = {
    '0x1': 'Ethereum Mainnet', '0x5': 'Goerli', '0xaa36a7': 'Sepolia',
    '0x89': 'Polygon', '0xa': 'Optimism', '0xa4b1': 'Arbitrum One',
    '0x38': 'BNB Chain', '0xa86a': 'Avalanche C-Chain', '0xfa': 'Fantom',
    '0x2105': 'Base', '0x144': 'zkSync Era', '0x82750': 'Scroll',
    '0x13881': 'Polygon Mumbai', '0x5a2': 'Stacks Testnet',
}

EVM_ADDR = re.compile(r'0x[a-fA-F0-9]{40}')
BITCOIN_ADDR = re.compile(r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b')

WEB3_PROVIDER_SIGS = [
    ('ethers.js', re.compile(r'ethers\.(?:providers|Contract|Wallet|utils)', re.IGNORECASE)),
    ('web3.js', re.compile(r'new\s+Web3\(|web3\.eth\.|web3\.utils\.', re.IGNORECASE)),
    ('wagmi', re.compile(r'(?:useAccount|useConnect|useContractRead|wagmi)', re.IGNORECASE)),
    ('viem', re.compile(r'(?:createPublicClient|createWalletClient|parseAbi)\b', re.IGNORECASE)),
    ('@solana/web3.js', re.compile(r'(?:Connection|PublicKey|Transaction|Keypair).*(?:solana|clusterApiUrl)', re.IGNORECASE)),
    ('@stacks/transactions', re.compile(r'(?:makeContractCall|makeSTXTokenTransfer|StacksTestnet|StacksMainnet)', re.IGNORECASE)),
    ('Moralis', re.compile(r'Moralis\.(?:start|Web3API|executeFunction)', re.IGNORECASE)),
    ('Alchemy SDK', re.compile(r'(?:Alchemy|AlchemyProvider|alchemy\.core)', re.IGNORECASE)),
    ('Infura', re.compile(r'infura\.io/v3/[a-f0-9]{32}', re.IGNORECASE)),
    ('ThirdWeb', re.compile(r'thirdweb|useContract|ThirdwebProvider', re.IGNORECASE)),
]

INFURA_KEY = re.compile(r'(?:infura\.io/v3/|INFURA[_A-Z]*[=:]\s*["\']?)([a-f0-9]{32})', re.IGNORECASE)
ALCHEMY_KEY = re.compile(r'(?:alchemy\.com/v2/|ALCHEMY[_A-Z]*[=:]\s*["\']?)([A-Za-z0-9_\-]{32,})', re.IGNORECASE)
MORALIS_KEY = re.compile(r'(?:MORALIS[_A-Z]*[=:]\s*["\']?)([A-Za-z0-9]{32,})', re.IGNORECASE)


def _probe_rpc(url: str) -> dict | None:
    try:
        with http.Client(timeout=6, verify=False, headers={'User-Agent': _UA, 'Content-Type': 'application/json'}) as client:
            resp = client.post(url, json=RPC_PAYLOAD)
            if resp.status_code == 200:
                data = resp.json()
                if 'result' in data:
                    chain_id = data['result']
                    chain_name = CHAIN_IDS.get(chain_id, f'Unknown ({chain_id})')
                    return {
                        'url': url,
                        'chain_id': chain_id,
                        'chain_name': chain_name,
                        'severity': 'HIGH',
                    }
    except Exception:
        pass
    return None


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _extract_wallets(text: str) -> dict:
    evm = set()
    solana = set()
    bitcoin = set()
    for m in EVM_ADDR.finditer(text):
        addr = m.group(0)
        if addr != '0x' + '0' * 40 and addr != '0x' + 'f' * 40 and len(set(addr[2:])) > 4:
            evm.add(addr)
    for m in BITCOIN_ADDR.finditer(text):
        bitcoin.add(m.group(0))
    return {
        'evm': sorted(evm)[:50],
        'bitcoin': sorted(bitcoin)[:20],
    }


def _extract_web3_keys(text: str) -> list[dict]:
    keys = []
    for m in INFURA_KEY.finditer(text):
        keys.append({'type': 'Infura Project ID', 'value_redacted': m.group(1), 'severity': 'HIGH'})
    for m in ALCHEMY_KEY.finditer(text):
        keys.append({'type': 'Alchemy API Key', 'value_redacted': m.group(1), 'severity': 'HIGH'})
    for m in MORALIS_KEY.finditer(text):
        keys.append({'type': 'Moralis API Key', 'value_redacted': m.group(1), 'severity': 'MEDIUM'})
    seen = set()
    deduped = []
    for k in keys:
        key = (k['type'], k['value_redacted'])
        if key not in seen:
            seen.add(key)
            deduped.append(k)
    return deduped


def _detect_providers(text: str) -> list[str]:
    found = []
    for name, pattern in WEB3_PROVIDER_SIGS:
        if pattern.search(text):
            found.append(name)
    return found


def run(target: str, context: dict | None = None) -> dict:
    results = {
        'module': 'Web3 Recon',
        'target': target,
        'exposed_rpc': [],
        'wallet_addresses': {'evm': [], 'bitcoin': []},
        'leaked_keys': [],
        'web3_providers': [],
        'findings': [],
        'errors': [],
    }
    rpc_targets = []
    for proto in ('https', 'http'):
        for path in RPC_PATHS:
            rpc_targets.append(f'{proto}://{target}{path}')
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_probe_rpc, url): url for url in rpc_targets}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results['exposed_rpc'].append(result)
            except Exception:
                pass
    full_text = ''
    for proto in ('https', 'http'):
        try:
            with http.Client(timeout=10, verify=False, follow_redirects=True, headers={'User-Agent': _UA}) as client:
                resp = client.get(f'{proto}://{target}')
                if resp.status_code == 200:
                    full_text = resp.text
                    js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', full_text, re.IGNORECASE)
                    for js_url in js_urls[:20]:
                        if js_url.startswith('//'):
                            js_url = f'{proto}:{js_url}'
                        elif js_url.startswith('/'):
                            js_url = urljoin(f'{proto}://{target}', js_url)
                        elif not js_url.startswith('http'):
                            js_url = urljoin(f'{proto}://{target}', js_url)
                        try:
                            js_resp = client.get(js_url)
                            if js_resp.status_code == 200:
                                full_text += '\n' + js_resp.text
                        except Exception:
                            pass
                    break
        except Exception:
            continue
    if not full_text:
        results['errors'].append(f'Could not fetch content from {target}')
        return results
    wallets = _extract_wallets(full_text)
    results['wallet_addresses'] = wallets
    results['leaked_keys'] = _extract_web3_keys(full_text)
    results['web3_providers'] = _detect_providers(full_text)
    if results['exposed_rpc']:
        results['findings'].append(
            f'{len(results["exposed_rpc"])} exposed JSON-RPC endpoint(s) — allows direct blockchain interaction'
        )
    total_wallets = len(wallets['evm']) + len(wallets['bitcoin'])
    if total_wallets:
        results['findings'].append(f'{total_wallets} wallet address(es) found in frontend code')
    if results['leaked_keys']:
        results['findings'].append(f'{len(results["leaked_keys"])} Web3 provider key(s) leaked in JavaScript')
    if results['web3_providers']:
        results['findings'].append(f'Web3 stack detected: {", ".join(results["web3_providers"])}')
    return results
