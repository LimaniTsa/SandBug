import os
import json
import logging
import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)
CLAUDE_MODEL = 'claude-haiku-4-5-20251001'
API_URL      = 'https://api.anthropic.com/v1/messages'


def _get_api_key() -> str:
    """Read the key fresh each call so .env changes take effect without restart."""
    return os.getenv('ANTHROPIC_API_KEY', '')

def _call_claude(system_prompt: str, user_content: str, max_tokens: int = 600) -> str:
    api_key = _get_api_key()
    if not api_key:
        return ''

    try:
        resp = requests.post(
            API_URL,
            headers={
                'x-api-key':         api_key,
                'anthropic-version': '2023-06-01',
                'content-type':      'application/json',
            },
            json={
                'model':      CLAUDE_MODEL,
                'max_tokens': max_tokens,
                'system':     system_prompt,
                'messages':   [{'role': 'user', 'content': user_content}],
            },
            timeout=30,
        )
        print(f"[ai_summarizer] status={resp.status_code}")
        if resp.status_code != 200:
            print(f"[ai_summarizer] error body: {resp.text[:500]}")
            return ''
        data = resp.json()
        return data['content'][0]['text'].strip()
    except Exception as exc:
        print(f"[ai_summarizer] exception: {exc}")
        return ''


def _truncate(obj, max_chars: int = 8000) -> str:
    """Serialize obj to JSON and truncate if too long to fit in context."""
    s = json.dumps(obj, default=str)
    if len(s) > max_chars:
        s = s[:max_chars] + '... [truncated]'
    return s

FILE_SYSTEM_PROMPT = """You are a malware analyst assistant for SandBug, a sandbox analysis platform.
Your job is to write clear, concise summaries of file analysis results.

Write TWO short paragraphs:
1. A plain-English summary of what the file appears to be and what threat it poses (2-3 sentences).
   Use concrete details from the data — don't be vague.
2. Key findings: the most important indicators, behaviours, or red flags found (2-3 sentences).
   Mention specific YARA rules, suspicious imports, network activity, or dropped files if present.

Rules:
- Be direct and factual. No filler phrases like "it is important to note".
- If the file looks benign, say so clearly.
- Use plain English, not jargon. Non-technical users should understand.
- Maximum 120 words total.
- Do NOT use bullet points, headers, or markdown formatting.
"""


def summarise_file(
    filename: str,
    file_type: str,
    risk_level: str,
    risk_score: int,
    static_analysis: dict,
    dynamic_analysis: dict | None,
) -> str:
    """Generate a summary for a file malware analysis. Returns empty string if no API key."""
    if not _get_api_key():
        return ''

    try:
        static_summary = {
            'risk_score':            static_analysis.get('risk_score'),
            'entropy':               static_analysis.get('entropy', {}).get('overall'),
            'yara_matches':          [r.get('rule') for r in (static_analysis.get('yara') or {}).get('rules', [])],
            'suspicious_indicators': static_analysis.get('suspicious_indicators', [])[:10],
            'import_dlls':           [i.get('dll') for i in (static_analysis.get('imports') or [])[:8]],
            'sections':              [(s.get('name'), round(s.get('entropy', 0), 2))
                                      for s in (static_analysis.get('sections') or [])[:6]],
        }

        dynamic_summary = None
        if dynamic_analysis and not dynamic_analysis.get('error'):
            dynamic_summary = {
                'triage_score': dynamic_analysis.get('triage_score'),
                'tags':         dynamic_analysis.get('tags', [])[:8],
                'signatures':   [(s.get('name'), s.get('score'))
                                 for s in (dynamic_analysis.get('signatures') or [])[:8]],
                'domains':      [d.get('domain') for d in
                                 (dynamic_analysis.get('network') or {}).get('domains', [])[:5]],
                'dropped':      len(dynamic_analysis.get('dropped_files') or []),
                'injected':     sum(1 for p in (dynamic_analysis.get('processes') or []) if p.get('injected')),
            }

        user_content = f"""Analyse this file and summarise it.

File: {filename}
Type: {file_type}
Risk: {risk_level.upper()} ({risk_score}/100)

Static analysis:
{json.dumps(static_summary, indent=2)}

Dynamic analysis:
{json.dumps(dynamic_summary, indent=2) if dynamic_summary else 'Not available'}"""

        return _call_claude(FILE_SYSTEM_PROMPT, user_content, max_tokens=250)

    except Exception as exc:
        logger.warning('[ai_summarizer] File summary failed: %s', exc)
        return ''


URL_SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for SandBug, a URL threat analysis platform.
Your job is to write clear, concise summaries of URL threat scan results.

Write TWO short paragraphs:
1. What this URL is and what threat (if any) it poses — be direct (2-3 sentences).
   If it's an IP grabber, phishing page, or malware distributor, say exactly that.
2. The specific evidence — SSL status, redirect chains, heuristic triggers,
   IP grabber detection, reputation findings (2-3 sentences).

Rules:
- Be direct. If it's dangerous say so and why.
- If it's clean, confirm that clearly.
- Plain English, no jargon, maximum 120 words.
- Do NOT use bullet points, headers, or markdown formatting.
"""


def summarise_url(url_analysis: dict) -> str:
    """Generate a summary for a URL threat analysis. Returns empty string if no API key."""
    if not _get_api_key():
        return ''

    try:
        grabber   = url_analysis.get('ip_grabber', {})
        heuristic = url_analysis.get('heuristics', {})
        ssl       = url_analysis.get('ssl', {})
        redirects = url_analysis.get('redirects', {})
        sb        = url_analysis.get('safe_browsing', {})
        ipr       = url_analysis.get('ip_reputation', {})

        summary_data = {
            'url':          url_analysis.get('url'),
            'hostname':     url_analysis.get('hostname'),
            'ip':           url_analysis.get('ip'),
            'risk_score':   url_analysis.get('risk_score'),
            'risk_level':   url_analysis.get('risk_level'),
            'ssl_valid':    ssl.get('valid'),
            'ssl_expiry':   ssl.get('expiry'),
            'redirects':    redirects.get('redirects', 0),
            'final_url':    redirects.get('final_url'),
            'ip_grabber': {
                'detected':       grabber.get('detected'),
                'confidence':     grabber.get('confidence'),
                'matched_domain': grabber.get('matched_domain'),
                'reasons':        grabber.get('reasons', [])[:4],
            },
            'heuristic_score':      heuristic.get('score'),
            'heuristic_indicators': heuristic.get('indicators', [])[:5],
            'safe_browsing_flagged': sb.get('flagged'),
            'safe_browsing_threats': sb.get('threats', []),
            'ip_abuse_score':       ipr.get('abuse_score') if ipr.get('checked') else None,
        }

        user_content = f"""Analyse this URL scan and summarise it.

{json.dumps(summary_data, indent=2)}"""

        return _call_claude(URL_SYSTEM_PROMPT, user_content, max_tokens=250)

    except Exception as exc:
        logger.warning('[ai_summarizer] URL summary failed: %s', exc)
        return ''