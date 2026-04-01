import os
import logging

from app.services.triage_client import TriageClient, TriageError, TriageTimeoutError

logger = logging.getLogger(__name__)

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
    Combines static and dynamic scores (50/50 weight).
    A valid Authenticode signature halves the merged score — signed malware is extremely rare.
    Falls back to static score alone if dynamic analysis failed.
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


def _triage_score_to_risk_score(triage_score: int) -> int:
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
