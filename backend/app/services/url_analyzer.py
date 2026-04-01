import os
import re
import ssl
import socket
import hashlib
import requests
import datetime
from urllib.parse import urlparse

# Optional API keys from environment 
ABUSEIPDB_KEY        = os.getenv('ABUSEIPDB_KEY', '') or os.getenv('ABUSEIPDB_API_KEY', '')
SAFE_BROWSING_KEY    = os.getenv('SAFE_BROWSING_KEY', '') or os.getenv('SAFE_BROWSING_API_KEY', '')

# Heuristic constants 
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', 
    '.xyz', '.top', '.club', '.work',
    '.link', '.click', '.download',
}

KNOWN_BRAND_KEYWORDS = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
    'facebook', 'instagram', 'linkedin', 'twitter', 'dropbox',
    'onedrive', 'icloud', 'outlook', 'gmail', 'yahoo',
    'bankofamerica', 'barclays', 'hsbc', 'lloyds', 'natwest',
]

SUSPICIOUS_PATTERNS = [
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # raw IP as host
    r'login|verify|secure|update|confirm|account|signin|password',
    r'\.php\?',
    r'redirect=',
    r'url=',
    r'@',   # URL with @ in it
    r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}',  # excessive URL encoding
]

# Known IP grabber / IP logger domains 
IP_GRABBER_DOMAINS = {
    # Grabify ecosystem
    'grabify.link',
    'grabify.ru',
    'grabify.io',

    # IPLogger family 
    'iplogger.ru',
    'iplogger.co',
    'iplogger.com',
    '2ip.ru',
    '02ip.ru',
    'yip.su',
    'iplis.ru',
    'ipgrab.net',
    'ip-logger.org',

    # Blasze / blasze.tk
    'blasze.tk',
    'blasze.com',

    # PS3CFW / shorteners known for IP logging 
    'lovebird.guru',
    'trker.eu',
    'maper.info',
    'datawallet.io',

    # Canarytokens 
    'canarytokens.com',
    'canarytokens.org',

    # GetNotify / email open trackers that also log link clicks
    'getnotify.com',

    # Misc known IP grabbers
    'ipgrabber.ru',
    'ipgrabb.er',
    'api.grabify.link',
    'ezstats.xyz',
    'linkz.io',
    'spyip.net',
    'whatismyipaddress.com',   
    'ip-api.com',              
    'track.rs',
    'clicktracking.net',
    'ipspy.net',
    'freegeoip.app',         
    'checkip.dyndns.org',
    'iphunter.info',
    'trackurl.it',
    'shortlogger.com',
    'piratewings.com',
    'nicelink.ru',
    'lnkshortner.xyz',
    'datadome.co',           
}

# Substrings that appear in IP grabber URL paths / query strings
IP_GRABBER_PATH_PATTERNS = [
    r'/profile\.php\?id=',           
    r'/image\.php\?id=',
    r'/api/track',
    r'/log\.php',
    r'/logger',
    r'/grab\.php',
    r'/ip\.php',
    r'/track/',
    r'/click\?.*token=',
    r'/redirect\?.*log=',
    r'\?ref=grab',
    r'\?src=log',
]

SHORTLINK_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'ow.ly', 'rb.gy', 't.co',
    'shorturl.at', 'is.gd', 'cutt.ly', 'v.gd', 'clck.ru',
    'tiny.cc', 'lnkd.in', 'buff.ly', 'adf.ly', 'bc.vc',
}

# Helpers
def _resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def _check_ssl(hostname: str) -> dict:
    result = {'valid': False, 'expiry': None, 'days_remaining': None, 'error': None}
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname)
        cert = conn.getpeercert()
        conn.close()

        expiry_str = cert.get('notAfter', '')
        expiry = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
        days   = (expiry - datetime.datetime.utcnow()).days

        result['valid']          = True
        result['expiry']         = expiry.strftime('%Y-%m-%d')
        result['days_remaining'] = days
    except ssl.SSLCertVerificationError as e:
        result['error'] = f'SSL verification failed: {str(e)}'
    except Exception as e:
        result['error'] = str(e)
    return result


def _follow_redirects(url: str) -> dict:
    result = {'chain': [], 'final_url': url, 'redirects': 0}
    try:
        resp = requests.get(
            url, allow_redirects=True, timeout=8,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; SandBug/1.0)'},
            verify=False,
        )
        result['chain']       = [r.url for r in resp.history] + [resp.url]
        result['final_url']   = resp.url
        result['redirects']   = len(resp.history)
        result['status_code'] = resp.status_code
    except requests.exceptions.ConnectionError:
        result['error'] = 'Could not connect to host'
    except requests.exceptions.Timeout:
        result['error'] = 'Connection timed out'
    except Exception as e:
        result['error'] = str(e)
    return result


def _ip_grabber_check(parsed_url, redirect_chain: list[str]) -> dict:
    """
    Dedicated IP grabber detection.

    Returns:
      {
        'detected':   bool,
        'confidence': 'confirmed' | 'likely' | 'possible' | 'clean',
        'reasons':    [str, ...],
        'matched_domain': str | None,
      }
    """
    reasons        = []
    score          = 0
    matched_domain = None

    hostname  = (parsed_url.hostname or '').lower().lstrip('www.')
    full_path = (parsed_url.path + '?' + parsed_url.query).lower() if parsed_url.query else parsed_url.path.lower()
    full_url  = parsed_url.geturl()

    # Direct domain match
    if hostname in IP_GRABBER_DOMAINS:
        score          += 100
        matched_domain  = hostname
        reasons.append(f'Domain "{hostname}" is a known IP grabber / logger service')

    # Check all domains in the redirect chain too
    if not matched_domain:
        for hop in redirect_chain:
            try:
                hop_host = urlparse(hop).hostname or ''
                hop_host = hop_host.lower().lstrip('www.')
                if hop_host in IP_GRABBER_DOMAINS:
                    score         += 90
                    matched_domain = hop_host
                    reasons.append(f'Redirect chain passes through known IP grabber: "{hop_host}"')
                    break
            except Exception:
                pass

    # Subdomain of known grabber
    if not matched_domain:
        for grabber in IP_GRABBER_DOMAINS:
            if hostname.endswith('.' + grabber):
                score         += 95
                matched_domain = grabber
                reasons.append(f'Subdomain of known IP grabber: "{hostname}"')
                break

    # Path pattern heuristics 
    for pattern in IP_GRABBER_PATH_PATTERNS:
        if re.search(pattern, full_url, re.IGNORECASE):
            score += 30
            reasons.append(f'URL path matches IP grabber pattern: {pattern}')

    # Disguised as image / media
    image_in_path  = bool(re.search(r'\.(jpg|jpeg|png|gif|bmp|webp|svg)$', parsed_url.path, re.IGNORECASE))
    image_in_query = bool(re.search(r'\.(jpg|jpeg|png|gif|bmp|webp|svg)(\b|$)', parsed_url.query or '', re.IGNORECASE))

    if (image_in_path or image_in_query) and parsed_url.query:
        score += 30
        location = 'path' if image_in_path else 'query parameter'
        reasons.append(f'URL disguised as image file ({location}) with query parameters — common IP grabber technique')

    # Short link used as relay
    is_shortlink = hostname in SHORTLINK_DOMAINS
    if is_shortlink and not matched_domain:
        score += 10
        reasons.append(f'URL shortener "{hostname}" — destination could not be verified without following link')

    # Tracking pixel / 1x1 image patterns
    if re.search(r'(1x1|pixel|track|beacon|open\?|read\?)', full_path):
        score += 20
        reasons.append('URL contains tracking pixel / beacon pattern')

    # Parameter names typical of grabbers
    grabber_params = re.findall(
        r'(id=|uid=|user=|token=|ref=|src=|from=|visit=)',
        (parsed_url.query or '').lower()
    )
    if len(grabber_params) >= 2:
        score += 15
        reasons.append(f'Multiple tracking parameters in query string: {", ".join(set(grabber_params))}')

    #Confidence level
    score = min(score, 100)
    if score >= 90:
        confidence = 'confirmed'
    elif score >= 50:
        confidence = 'likely'
    elif score >= 20:
        confidence = 'possible'
    else:
        confidence = 'clean'

    return {
        'detected':       score >= 20,
        'confidence':     confidence,
        'score':          score,
        'reasons':        reasons,
        'matched_domain': matched_domain,
    }


def _heuristic_score(parsed_url) -> tuple[int, list[str]]:
    """Returns (score 0-100, list of triggered indicators)."""
    score      = 0
    indicators = []
    full_url   = parsed_url.geturl()
    hostname   = parsed_url.hostname or ''
    path       = parsed_url.path or ''
    query      = parsed_url.query or ''

    # Raw IP address as hostname
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        score += 25
        indicators.append('Raw IP address used instead of domain name')

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 15
            indicators.append(f'Suspicious TLD: {tld}')
            break

    # Brand impersonation in subdomain/path
    for brand in KNOWN_BRAND_KEYWORDS:
        if brand in hostname and not hostname.endswith(f'{brand}.com'):
            score += 30
            indicators.append(f'Possible brand impersonation: "{brand}" in domain')
            break

    # @ symbol in URL
    if '@' in full_url:
        score += 20
        indicators.append('@ symbol in URL (potential credential hijack)')

    # Excessive subdomains
    subdomain_count = hostname.count('.')
    if subdomain_count >= 4:
        score += 10
        indicators.append(f'Excessive subdomains ({subdomain_count} dots in hostname)')

    # Very long URL
    if len(full_url) > 150:
        score += 10
        indicators.append(f'Unusually long URL ({len(full_url)} characters)')

    # Suspicious keywords in path/query
    suspicious_kw = re.findall(
        r'login|verify|secure|update|confirm|signin|password|credential|reset|banking',
        (path + query).lower()
    )
    if suspicious_kw:
        score += 15
        indicators.append(f'Suspicious keywords in URL: {", ".join(set(suspicious_kw))}')

    # Multiple redirects encoded in query string
    if re.search(r'redirect=|url=|goto=|return=', query.lower()):
        score += 10
        indicators.append('Open redirect parameter detected in query string')

    # Excessive URL encoding
    encoded = re.findall(r'%[0-9a-fA-F]{2}', full_url)
    if len(encoded) > 5:
        score += 10
        indicators.append(f'Excessive URL encoding ({len(encoded)} encoded characters)')

    return min(score, 100), indicators


def _safe_browsing_check(url: str) -> dict:
    if not SAFE_BROWSING_KEY:
        return {'checked': False, 'reason': 'No API key configured'}
    try:
        resp = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}',
            json={
                'client': {'clientId': 'sandbug', 'clientVersion': '1.0'},
                'threatInfo': {
                    'threatTypes':      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    'platformTypes':    ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries':    [{'url': url}],
                },
            },
            timeout=5,
        )
        data    = resp.json()
        matches = data.get('matches', [])
        return {
            'checked': True,
            'flagged': len(matches) > 0,
            'threats': [m.get('threatType') for m in matches],
        }
    except Exception as e:
        return {'checked': False, 'error': str(e)}


def _abuseipdb_check(ip: str) -> dict:
    if not ABUSEIPDB_KEY or not ip:
        return {'checked': False, 'reason': 'No API key or IP not resolved'}
    try:
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=5,
        )
        data = resp.json().get('data', {})
        return {
            'checked':       True,
            'abuse_score':   data.get('abuseConfidenceScore', 0),
            'total_reports': data.get('totalReports', 0),
            'country':       data.get('countryCode', ''),
            'isp':           data.get('isp', ''),
            'is_tor':        data.get('isTor', False),
        }
    except Exception as e:
        return {'checked': False, 'error': str(e)}



# Public entry point
def analyse_url(url: str) -> dict:
    """
    Run all checks on `url` and return a structured result dict.
    This is called by the Flask route in analysis.py.
    """
    parsed   = urlparse(url)
    hostname = parsed.hostname or ''

    ip = _resolve_ip(hostname)

    # Run checks
    ssl_result                            = _check_ssl(hostname) if parsed.scheme == 'https' else {'valid': False, 'error': 'Not HTTPS'}
    redirect_result                       = _follow_redirects(url)
    heuristic_score, heuristic_indicators = _heuristic_score(parsed)
    sb_result                             = _safe_browsing_check(url)
    abuse_result                          = _abuseipdb_check(ip or '')
    grabber_result                        = _ip_grabber_check(parsed, redirect_result.get('chain', []))

    # Combine into overall risk score 
    risk_score = heuristic_score

    # IP grabber is a severe finding — drive score up hard
    if grabber_result['confidence'] == 'confirmed':
        risk_score = max(risk_score, 90)
    elif grabber_result['confidence'] == 'likely':
        risk_score = min(risk_score + 50, 100)
    elif grabber_result['confidence'] == 'possible':
        risk_score = min(risk_score + 25, 100)

    # Reputation APIs
    if sb_result.get('flagged'):
        risk_score = min(risk_score + 50, 100)
    if abuse_result.get('checked') and abuse_result.get('abuse_score', 0) > 50:
        risk_score = min(risk_score + 30, 100)
    if not ssl_result.get('valid'):
        risk_score = min(risk_score + 10, 100)
    if redirect_result.get('redirects', 0) > 3:
        risk_score = min(risk_score + 10, 100)

    #Risk level
    if risk_score >= 75:
        risk_level = 'critical'
    elif risk_score >= 50:
        risk_level = 'high'
    elif risk_score >= 25:
        risk_level = 'medium'
    else:
        risk_level = 'low'

    return {
        'url':          url,
        'hostname':     hostname,
        'ip':           ip,
        'risk_score':   risk_score,
        'risk_level':   risk_level,
        'ssl':          ssl_result,
        'redirects':    redirect_result,
        'heuristics': {
            'score':      heuristic_score,
            'indicators': heuristic_indicators,
        },
        'ip_grabber':     grabber_result,
        'safe_browsing':  sb_result,
        'ip_reputation':  abuse_result,
    }
