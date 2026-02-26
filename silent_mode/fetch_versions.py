import requests
from pathlib import Path
import zipfile
import hashlib
import time

def fetch_timestamps():
    base_url = "https://download.sysinternals.com/files/Sysmon.zip"
    endpoint = "https://web.archive.org/cdx/search/cdx"

    params = {
        "url": f"{base_url}/*",
        "output": "json",
        "filter": "statuscode:200",
        "fl": "timestamp" # Only fetch the timestamp field
    }

    response = requests.get(endpoint, params=params, timeout=60)
    data = response.json()
    timestamps = [timestamp[0] for timestamp in data[1:]]
    timestamps.sort()
    return timestamps

def download_files(timestamps):
    dir_path = "sysmon_versions"
    Path(dir_path).mkdir(exist_ok=True)
    last_hash = None

    for timestamp in timestamps:
        # download the zip file from Wayback Machine
        zip_url = f"https://web.archive.org/web/{timestamp}/https://download.sysinternals.com/files/Sysmon.zip"
        zip_filename = f"{dir_path}/Sysmon_{timestamp}.zip"
        exe_filename = f"{dir_path}/Sysmon_{timestamp}.exe"
        
        if Path(exe_filename).exists(): continue
        
        try:
            response = requests.get(zip_url, stream=True, timeout=60)
        
            if response.status_code == 200:
                with open(zip_filename, "wb") as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            file.write(chunk)
                print(f"Downloaded: {zip_filename}")

                # Extract the exe directly to the target name & delete the zip file
                try:
                    with zipfile.ZipFile(zip_filename, "r") as zip_ref:
                        with zip_ref.open("Sysmon.exe") as src, open(exe_filename, "wb") as dst:
                            for chunk in iter(lambda: src.read(8192), b""):
                                dst.write(chunk)
                    print(f"Extracted: {zip_filename}")
                    Path(zip_filename).unlink()
                except Exception as e:
                    print(f"Failed to extract: {zip_filename} (Error: {e})")

                # Store the unique executable files based on their hash
                with open(exe_filename, "rb") as exe_file:
                    hash = hashlib.sha256()
                    for chunk in iter(lambda: exe_file.read(4096), b""):
                        hash.update(chunk)
                    exe_hash = hash.hexdigest()
                    if exe_hash != last_hash:
                        last_hash = exe_hash
                    else:
                        print(f"Duplicate file detected: {exe_filename} (Hash: {exe_hash})")
                        try:
                            Path(exe_filename).unlink()
                        except PermissionError:
                            for _ in range(6):
                                time.sleep(0.5)
                                try:
                                    Path(exe_filename).unlink()
                                    break
                                except PermissionError:
                                    continue
            else:
                print(f"Failed to download: {zip_filename} (Status code: {response.status_code})")
        
        except requests.RequestException as e:
            print(f"Failed to fetch: {zip_url} (Error: {e})")
        



if __name__ == "__main__":
    timestamps = fetch_timestamps()
    print(f"Found {len(timestamps)} timestamps for Sysmon.exe: {', '.join(timestamps)}")
    download_files(timestamps)