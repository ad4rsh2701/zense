from time import sleep
import hashlib
import requests
from virustotal.key import vt_api_key

API_KEY = vt_api_key
LARGE_FILE_THRESHOLD = 32 * 1024 * 1024  # 32 MB

# REST API FLEX (from what I remember)

# Return existing VT report if already known.
def _check_existing(file_bytes: bytes) -> dict | None:
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": API_KEY} # thanks LLMs
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        # Return the full file-report attributes block (names, type, signatures,
        # sandbox verdicts, popular_threat_classification, behavior metadata,
        # last_analysis_stats/results, etc.)
        attrs = response.json()["data"]["attributes"]
        print(f"\t[*] Already known to VT (sha256: {sha256}), skipping upload.")
        print(f"\t[*] Existing Analytics via VirtusTotal received.")
        return {
            "analysis_id": sha256,
            "source": "file_report",
            "attributes": attrs,
        }

    return None


# Upload file bytes to VT, switching to large-file (dynamically generated) URL if malware too fat
def _upload_file(file_bytes: bytes, filename: str = "sample.bin") -> dict:

    # damn, LLMs are so good at Python code (or I just forgot enough of Python to tell the difference)
    if len(file_bytes) > LARGE_FILE_THRESHOLD:
        # the math by LLMs
        print(f"\t[*] Large file ({len(file_bytes) / 1024 / 1024:.1f} MB), fetching upload URL...")
        r = requests.get("https://www.virustotal.com/api/v3/files/upload_url", headers={"x-apikey": API_KEY})
        r.raise_for_status()
        url = r.json()["data"]
        print(f"\t[*] Large file upload URL: {url}")
    else:
        url = "https://www.virustotal.com/api/v3/files"

    # I did THIS, AHA, learnt.
    headers = {"x-apikey": API_KEY}
    files = {"file": (filename, file_bytes, "application/octet-stream")}
    response = requests.post(url, headers=headers, files=files)
    response.raise_for_status()
    return response.json()


def _get_analysis(analysis_id: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


def run(file_bytes: bytes, filename: str = "sample.bin") -> dict:
    # Check if VT already has a report (saves my API quota)
    cached = _check_existing(file_bytes)
    if cached:
        return cached

    result = _upload_file(file_bytes, filename)
    analysis_id = result["data"]["id"]
    print(f"\t[*] File uploaded. Analysis ID: {analysis_id}")

    i = 0   # polling counter rahhh
    while True:
        analysis = _get_analysis(analysis_id)
        attrs = analysis["data"]["attributes"]
        status = attrs["status"]
        print(f"\t[*] Polling VT: Attempt #{i}, status: {status}")
        i += 1

        if status == "completed":
            # Once the analysis is done, fetch the full file report so we get all attributes
            sha256 = hashlib.sha256(file_bytes).hexdigest()
            file_report = None
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers={"x-apikey": API_KEY},
                )
                if r.status_code == 200:
                    file_report = r.json()["data"]["attributes"]
            except requests.RequestException:
                file_report = None

            output = {
                "analysis_id": analysis_id,
                "source": "analysis" if file_report is None else "file_report", # only in python
                "analysis_attributes": attrs,
                "attributes": file_report if file_report is not None else attrs,
            }
            print(f"\t[*] Analytics via VirtusTotal received.")
            return output

        sleep(120)  # Poll every 120 seconds (FREE TIER RAH, 1 REQUEST PER MINUTE)
        # why 120? Cuz I know it takes at least more than 120 seconds for VT to finish analyzing a file.