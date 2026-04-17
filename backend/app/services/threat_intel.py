import os
import logging
import requests

logger = logging.getLogger(__name__)

MB_API_URL = 'https://mb-api.abuse.ch/api/v1/'
TIMEOUT_S  = 10


def lookup_hash(sha256: str) -> dict:
    # api key is optional — malwarebazaar allows unauthenticated queries at a lower rate limit
    api_key = os.getenv('MB_API_KEY', '').strip()

    headers = {}
    if api_key:
        headers['Auth-Key'] = api_key

    try:
        resp = requests.post(
            MB_API_URL,
            data={'query': 'get_info', 'hash': sha256},
            headers=headers,
            timeout=TIMEOUT_S,
        )
        resp.raise_for_status()
        data = resp.json()

        # query_status == 'ok' means the hash was found in the database
        if data.get('query_status') == 'ok' and data.get('data'):
            info = data['data'][0]
            return {
                'found':      True,
                'source':     'malwarebazaar',
                'tags':       info.get('tags') or [],
                'signature':  info.get('signature'),
                'file_type':  info.get('file_type'),
                'first_seen': info.get('first_seen'),
                'reporter':   info.get('reporter'),
                'mb_url':     f"https://bazaar.abuse.ch/sample/{sha256}/",
            }

        return {'found': False, 'source': 'malwarebazaar'}

    except Exception as exc:
        logger.warning('[threat_intel] MalwareBazaar lookup failed: %s', exc)
        return {'found': False, 'source': 'malwarebazaar', 'error': str(exc)}
