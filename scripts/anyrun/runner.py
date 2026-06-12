import requests
from anyrun.key import ar_api_key

API_KEY = ar_api_key
BASE = "https://api.any.run"
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB is the free tier limit

# Fetch IOCs (IPs, domains, URLs, hashes)
def _get_ioc_report(task_uuid: str) -> dict:
    url = f"{BASE}/report/{task_uuid}/ioc/json"
    headers = {"Authorization": f"API-Key {API_KEY}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

# full analysis summary
def _get_summary_report(task_uuid: str) -> dict:
    url = f"{BASE}/v1/analysis/{task_uuid}"
    headers = {"Authorization": f"API-Key {API_KEY}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


def run(task_uuid: str, file_bytes: bytes) -> tuple[dict, dict]:
    print("[zense] Running basic ANY.RUN analysis (free tier)")

    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError(f"[zense] File exceeds free tier limit ({len(file_bytes) / 1024 / 1024:.1f} MB > 16 MB)")

    ioc = _get_ioc_report(task_uuid)
    summary = _get_summary_report(task_uuid)
    return ioc, summary