import time
import subprocess
from datetime import datetime

SCAN_TARGET = "scanme.nmap.org"  # Change as needed
SCAN_INTERVAL = 24 * 60 * 60  # 24 hours in seconds
RESULTS_FILE = "/app/logs/daily_scan.log"

while True:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        # Run nmap and extract scanned IPs with awk, saving to nmap_scanned_ips.txt
        cmd = f"nmap -sn {SCAN_TARGET} | awk '/Nmap scan/{{gsub(/[()]/,\"\",$NF); print $NF}}' > /app/logs/nmap_scanned_ips.txt"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        with open(RESULTS_FILE, "a") as f:
            f.write(f"\n--- Scan at {now} ---\n")
            f.write(result.stdout)
            if result.stderr:
                f.write(f"\n[stderr]\n{result.stderr}")
    except Exception as e:
        with open(RESULTS_FILE, "a") as f:
            f.write(f"\n--- Scan at {now} FAILED ---\n{str(e)}\n")
    print(f"Scan completed at {now}, next scan in {SCAN_INTERVAL} seconds.")
    time.sleep(SCAN_INTERVAL)
