import time

import requests

from hybridanalysis.key import ha_api_key

API_KEY = ha_api_key
BASE = "https://hybrid-analysis.com/api/v2"
DEFAULT_ENVIRONMENT_ID = "140"  # Default on Windows 11
                                # Set to 130 for Windows 10, 120 for Windows 7,
                                # 300 for Ubuntu 16 or 310 for Ubuntu 21

MAX_FILE_SIZE = 250 * 1024 * 1024  # 250 MB
POLL_INTERVAL_SECONDS = 10
POLL_TIMEOUT_SECONDS = 300  # 5 minutes is my limit.


def _headers() -> dict[str, str]:
    return {
        "api-key": API_KEY,
        "accept": "application/json",
        "User-Agent": "Falcon Sandbox",
    }


def _submit_file(file_bytes: bytes, environment_id: str) -> dict:
    url = f"{BASE}/submit/file"
    form = {"environment_id": environment_id}
    files = {"file": ("sample.bin", file_bytes)}
    response = requests.post(url, headers=_headers(), data=form, files=files, timeout=60)
    response.raise_for_status()
    return response.json()


def _get_json(path: str) -> dict:
    url = f"{BASE}/{path}"
    response = requests.get(url, headers=_headers(), timeout=30)
    response.raise_for_status()
    return response.json()


def _wait_for_report(job_id: str) -> None:
    """Poll /report/{job_id}/state until the analysis finishes."""
    deadline = time.time() + POLL_TIMEOUT_SECONDS
    # Deadlines, ahh yes, darkness.

    while time.time() < deadline:
        # We are happy being single... threaded.
        payload = _get_json(f"report/{job_id}/state")
        state = str(payload.get("state") or payload.get("status") or "").lower()
        if state in {"success", "finished", "done", "completed"}:
            return
        if state in {"error", "failed", "failure"}:
            raise RuntimeError(f"\t[*] Hybrid Analysis submission failed: {payload}")
        time.sleep(POLL_INTERVAL_SECONDS)
    raise TimeoutError(f"\t[*] Hybrid Analysis report was not ready before timeout for job {job_id}")


# Fetch the full HA summary. IOCs (IPs, domains, URLs, hashes) are present inside the summary payload
def run(environment_id: str | None, file_bytes: bytes) -> dict:

    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError(f"\t[*] File exceeds upload limit ({len(file_bytes) / 1024 / 1024:.1f} MB > 250 MB)")

    environment_id = environment_id or DEFAULT_ENVIRONMENT_ID
    submission = _submit_file(file_bytes, environment_id=environment_id)

    job_id = submission.get("job_id")
    if not job_id:
        raise RuntimeError(f"\t[*] Could not extract job_id from Hybrid Analysis submission: {submission}")
    job_id = str(job_id)

    _wait_for_report(job_id)
    print(f"\t[*] Analytics via Hybrid Analysis Received")
    return _get_json(f"report/{job_id}/summary")
