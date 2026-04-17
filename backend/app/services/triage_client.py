import time
import logging
from typing import Optional
import requests

logger = logging.getLogger(__name__)

TRIAGE_BASE_URL = "https://tria.ge/api/v0"
POLL_INTERVAL_S  = 10    # seconds between status checks
ANALYSIS_TIMEOUT_S = 300  # 5 minutes max wait


class TriageError(Exception):
    """Raised when the Triage API returns an error response."""


class TriageTimeoutError(TriageError):
    """Raised when a sample does not complete within ANALYSIS_TIMEOUT_S."""


class TriageClient:
    """
    Thin wrapper around the Hatching Triage v0 REST API.

    Usage:
        client = TriageClient(api_key="...")
        result = client.analyse(file_bytes, "sample.exe")
        # result is ready to store in Analysis.dynamic_analysis
    """

    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        })

    def analyse(self, file_bytes: bytes, filename: str, on_status=None) -> dict:

        sample_id = self._submit(file_bytes, filename)
        logger.info("[triage] submitted sample_id=%s filename=%s", sample_id, filename)

        if on_status:
            try:
                on_status('dynamic_queued')
            except Exception:
                pass

        self._poll_until_reported(sample_id, on_status=on_status)
        logger.info("[triage] analysis complete sample_id=%s", sample_id)

        return self._build_result(sample_id)

    def _submit(self, file_bytes: bytes, filename: str) -> str:
        resp = self.session.post(
            f"{TRIAGE_BASE_URL}/samples",
            files={"file": (filename, file_bytes, "application/octet-stream")},
            data={"kind": "file"},
            timeout=60,
        )
        self._raise_for_status(resp)
        return resp.json()["id"]

    def _poll_until_reported(self, sample_id: str, on_status=None) -> None:
        attempts = ANALYSIS_TIMEOUT_S // POLL_INTERVAL_S
        last_notified = None

        for i in range(attempts):
            resp = self.session.get(
                f"{TRIAGE_BASE_URL}/samples/{sample_id}",
                timeout=30,
            )
            self._raise_for_status(resp)
            triage_status = resp.json().get("status", "unknown")

            # Forward Triage status transitions to the caller so the UI can
            # show meaningful progress rather than appearing frozen.
            if on_status:
                if triage_status in ("pending", "static") and last_notified != "dynamic_queued":
                    last_notified = "dynamic_queued"
                    try:
                        on_status("dynamic_queued")
                    except Exception:
                        pass
                elif triage_status in ("running", "processing") and last_notified != "sandbox_running":
                    last_notified = "sandbox_running"
                    try:
                        on_status("sandbox_running")
                    except Exception:
                        pass

            if triage_status == "reported":
                return
            if triage_status in ("failed", "error"):
                raise TriageError(f"Triage reported failure for sample {sample_id}")

            logger.debug("[triage] %s status=%s (%d/%d)", sample_id, triage_status, i + 1, attempts)
            time.sleep(POLL_INTERVAL_S)

        raise TriageTimeoutError(
            f"Triage analysis for {sample_id} did not finish within {ANALYSIS_TIMEOUT_S}s"
        )

    def _build_result(self, sample_id: str) -> dict:
        # fetch the overview report and reshape it into the format the app expects
        resp = self.session.get(
            f"{TRIAGE_BASE_URL}/samples/{sample_id}/overview.json",
            timeout=30,
        )
        self._raise_for_status(resp)
        overview = resp.json() 

        analysis_block = overview.get("analysis", {})

        return {
            "sandbox":       "hatching_triage",
            "sample_id":     sample_id,
            "report_url":    f"https://tria.ge/{sample_id}",
            "triage_score":  analysis_block.get("score", 0),
            "signatures":    _parse_signatures(overview),
            "network":       _parse_network(overview),
            "processes":     _parse_processes(overview),
            "dropped_files": _parse_dropped(overview),
            "registry":      _parse_registry(overview),
            "mutexes":       analysis_block.get("mutexes", []),
            "tags":          analysis_block.get("tags", []),
            "errors":        analysis_block.get("errors", []),
        }

    @staticmethod
    def _raise_for_status(resp: requests.Response) -> None:
        if not resp.ok:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise TriageError(f"Triage API {resp.status_code}: {detail}")



def _parse_signatures(overview: dict) -> list:
    return [
        {
            "name":        s.get("name", ""),
            "score":       s.get("score", 0),
            "tags":        s.get("tags", []),
            "description": s.get("desc", ""),
        }
        for s in overview.get("signatures", [])
    ]


def _parse_network(overview: dict) -> dict:
    net = overview.get("network", {})
    return {
        "domains": [
            {"domain": d.get("domain", ""), "ip": d.get("ip", "")}
            for d in net.get("domains", [])
        ],
        "hosts": net.get("hosts", []),
        "http_requests": [
            {
                "method": r.get("method", ""),
                "url":    r.get("url", ""),
                "status": r.get("status", 0),
            }
            for r in net.get("requests", [])
        ],
        "dns_requests": [
            {"query": q.get("domain", ""), "type": q.get("type", "")}
            for q in net.get("dns", [])
        ],
    }


def _parse_processes(overview: dict) -> list:
    return [
        {
            "name":       p.get("name", ""),
            "pid":        p.get("pid", 0),
            "cmd":        p.get("cmd", ""),
            "injected":   p.get("injected", False),
            "signatures": p.get("signatures", []),
        }
        for p in overview.get("processes", [])
    ]


def _parse_dropped(overview: dict) -> list:
    return [
        {
            "name":   f.get("filename", ""),
            "md5":    f.get("md5", ""),
            "sha256": f.get("sha256", ""),
            "type":   f.get("type", ""),
            "size":   f.get("size", 0),
        }
        for f in overview.get("dropped", [])
    ]


def _parse_registry(overview: dict) -> list:
    return [
        {
            "key":   e.get("key", ""),
            "op":    e.get("op", ""),
            "value": e.get("value", ""),
        }
        for e in overview.get("registry", [])
    ]
