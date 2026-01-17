import requests
import os
import time

API_KEY = "779370a75f399c6da524155f74ed2241a13dcc6f9d86656b65f3b97533f0583b"
UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"

HEADERS = {
    "x-apikey": API_KEY
}

def upload_file(file_path):
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(UPLOAD_URL, headers=HEADERS, files=files)

    if response.status_code != 200:
        raise Exception(f"Upload failed: {response.text}")

    return response.json()["data"]["id"]

def get_analysis_result(analysis_id, max_attempts=10):
    for attempt in range(max_attempts):
        response = requests.get(
            ANALYSIS_URL.format(analysis_id),
            headers=HEADERS
        )

        if response.status_code != 200:
            raise Exception("Failed to fetch analysis")

        data = response.json()
        status = data["data"]["attributes"]["status"]

        print(f"Analysis status: {status}")

        if status == "completed":
            return data["data"]["attributes"]["stats"]

        time.sleep(5)

    raise Exception("Analysis did not complete in time")


def scan_file(file_path):
    print(f"Uploading: {file_path}")
    analysis_id = upload_file(file_path)

    print("Waiting for VirusTotal analysis...")
    return get_analysis_result(analysis_id)

def scan_directory(directory):
    if not os.path.isdir(directory):
        print("ERROR: Directory does not exist")
        return

    print("Scanning directory:", directory)

    for root, _, files in os.walk(directory):
        for name in files:
            file_path = os.path.join(root, name)

            if os.path.getsize(file_path) > 32 * 1024 * 1024:
                print(f"Skipped (too large): {file_path}")
                continue

            try:
                result = scan_file(file_path)
                print("Scan result:")
                print(f"Malicious: {result.get('malicious', 0)}")
                print(f"Suspicious: {result.get('suspicious', 0)}")
                print(f"Undetected: {result.get('undetected', 0)}")
                print("-" * 50)

            except Exception as e:
                print(f"Error scanning {file_path}: {e}")

if __name__ == "__main__":
    scan_directory(r"C:\Users\mor20\Desktop\check")
