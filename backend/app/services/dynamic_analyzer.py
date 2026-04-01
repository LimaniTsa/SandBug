import os
import logging

from app.services.triage_client import TriageClient, TriageError, TriageTimeoutError

logger = logging.getLogger(__name__)

# Triage score to risk score mapping (0-10 → 0-100)
_TRIAGE_SCORE_MAP = {
    0:  0,
    1:  4,
    2:  8,
    3:  14,
    4:  20,
    5:  25,
    6:  38,
    7:  55,
    8:  78,
    9:  90,
    10: 100,
}


def analyse_file(file_path: str, filename: str, on_status=None) -> dict:
    """
    Run dynamic analysis via Hatching Triage.

    on_status: optional callable(status_str) forwarded to the Triage client
               so callers can receive live status transitions.

    Returns:
        {
            "results": {
                "triage":           {...} | None,
                "hybrid_analysis":  None,   # always None — HA removed
            },
            "dynamic_risk_score": int,   # 0-100
            "triage_risk_score":  int,
            "ha_risk_score":      0,
            "error":              str    # only present when Triage fails
        }
    """
    try:
        with open(file_path, "rb") as fh:
            file_bytes = fh.read()
    except OSError as exc:
        msg = f"Could not read file for dynamic analysis: {exc}"
        logger.error("[dynamic] %s", msg)
        return _failure(msg)

    triage_result = None
    triage_risk   = 0
    triage_error  = None

    triage_key = os.environ.get("TRIAGE_API_KEY")
    if not triage_key:
        triage_error = "TRIAGE_API_KEY environment variable is not set"
        logger.warning("[dynamic] %s", triage_error)
    else:
        try:
            client        = TriageClient(api_key=triage_key)
            triage_result = client.analyse(file_bytes, filename, on_status=on_status)
            triage_risk   = _triage_score_to_risk_score(triage_result.get("triage_score", 0))
        except TriageTimeoutError as exc:
            triage_error = f"Triage timed out: {exc}"
            logger.warning("[dynamic] %s", triage_error)
        except TriageError as exc:
            triage_error = f"Triage API error: {exc}"
            logger.error("[dynamic] %s", triage_error)
        except Exception as exc:  # noqa: BLE001
            triage_error = f"Triage unexpected error: {exc}"
            logger.exception("[dynamic] Unexpected error during Triage analysis")

    result: dict = {
        "results": {
            "triage":          triage_result,
            "hybrid_analysis": None,
        },
        "dynamic_risk_score": triage_risk,
        "triage_risk_score":  triage_risk,
        "ha_risk_score":      0,
    }

    if triage_result is None:
        result["error"] = triage_error or "Triage sandbox failed"

    return result


def merge_risk_score(
    static_score: int,
    dynamic_score: int,
    dynamic_available: bool = True,
    is_signed: bool = False,
) -> int:
    """
    Combine static (0-100) and dynamic (0-100) scores.

    Weights — 50 % static / 50 % dynamic with a single sandbox.
    Trusting static and dynamic equally is appropriate when there is only
    one sandbox result rather than a two-sandbox consensus.

    is_signed — True when the file carries a valid Authenticode certificate.
    A valid signature from a trusted CA is the strongest available clean-file
    signal (virtually no malware is signed by a trusted CA), so the merged
    score is halved.  This alone is enough to keep a legitimately-signed
    installer with a mid-range Triage score in the LOW band.

    If dynamic analysis failed, the static score is used unchanged so that
    a broken sandbox run never suppresses valid static findings.
    """
    static_score = max(0, min(100, static_score or 0))

    if not dynamic_available:
        merged = static_score
    else:
        dynamic_score = max(0, min(100, dynamic_score or 0))
        merged = round(static_score * 0.5 + dynamic_score * 0.5)

    if is_signed:
        merged = round(merged * 0.5)

    return max(0, min(100, merged))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _triage_score_to_risk_score(triage_score: int) -> int:
    """Convert Triage 0-10 integer score to SandBug's 0-100 risk_score."""
    clamped = max(0, min(10, int(triage_score or 0)))
    return _TRIAGE_SCORE_MAP[clamped]


def _failure(message: str) -> dict:
    return {
        "results": {
            "triage":          None,
            "hybrid_analysis": None,
        },
        "dynamic_risk_score": 0,
        "triage_risk_score":  0,
        "ha_risk_score":      0,
        "error":              message,
    }
