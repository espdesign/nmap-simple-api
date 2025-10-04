import time
import subprocess
from datetime import datetime
import os
import sys

# --- Configuration ---
# Get scan target from environment variable, default to 'scanme.nmap.org' for a safe example
SCAN_TARGET = os.environ.get("SCAN_TARGET", "scanme.nmap.org")
# Get scan interval from environment variable, default to 24 hours
SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", 24))
SCAN_INTERVAL = SCAN_INTERVAL_HOURS * 60 * 60  # Convert hours to seconds

# Use absolute paths for clarity inside a container
LOG_DIR = "/code/app/logs"
RESULTS_FILE = os.path.join(LOG_DIR, "daily_scan.log")
IPS_FILE = os.path.join(LOG_DIR, "nmap_scanned_ips.txt")


def ensure_log_dir_exists():
    """Creates the log directory if it doesn't exist to prevent FileNotFoundError."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError as e:
        # Cannot create directory, a critical failure. Print to stderr and exit.
        print(f"FATAL: Could not create log directory {LOG_DIR}: {e}", file=sys.stderr)
        sys.exit(1)  # Exit the script if we can't create the log dir


def log_message(message):
    """Appends a message to the main log file."""
    ensure_log_dir_exists()
    with open(RESULTS_FILE, "a") as f:
        f.write(message)


def parse_nmap_output(nmap_stdout):
    """Parses the output of 'nmap -sn' to find IP addresses."""
    scanned_ips = []
    for line in nmap_stdout.splitlines():
        # Look for the line that reports the target
        if "Nmap scan report for" in line:
            # Extract the last word, which is the IP or hostname
            ip_address = line.split()[-1].strip("()")
            scanned_ips.append(ip_address)
    return scanned_ips


# --- Main Loop ---
print("Starting daily nmap scanner...")
while True:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        # 1. Ensure log directory exists before we do anything else
        ensure_log_dir_exists()

        print(f"[{now}] Running nmap scan on {SCAN_TARGET}...")

        # 2. Run nmap command safely without shell=True
        # We capture the output here instead of redirecting it in the shell
        cmd = ["nmap", "-sn", SCAN_TARGET]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, check=True
        )

        # 3. Log the raw output
        log_message(f"\n--- Scan at {now} ---\n")
        log_message(result.stdout)
        if result.stderr:
            log_message(f"\n[stderr]\n{result.stderr}")

        # 4. Parse the output and save the extracted IPs
        found_ips = parse_nmap_output(result.stdout)

        # Overwrite the IP list file with the latest results
        with open(IPS_FILE, "w") as f:
            if found_ips:
                f.write("\n".join(found_ips) + "\n")
            else:
                f.write("# No hosts found in the latest scan.\n")

        print(f"Scan completed successfully. Found {len(found_ips)} host(s).")

    except subprocess.CalledProcessError as e:
        # This error is raised when nmap returns a non-zero exit code
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_message = (
            f"\n--- Scan at {now_str} FAILED (nmap error) ---\n"
            f"Command failed with exit code {e.returncode}\n"
            f"[stdout]:\n{e.stdout}\n"
            f"[stderr]:\n{e.stderr}\n"
        )
        log_message(error_message)
        print(
            f"ERROR: nmap command failed. \n {error_message} \n See {RESULTS_FILE} for details.",
            file=sys.stderr,
        )

    except Exception as e:
        # Catch any other exceptions (e.g., timeout, permissions)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_message = f"\n--- Scan at {now_str} FAILED (script error) ---\n{str(e)}\n"
        log_message(error_message)
        print(f"ERROR: An unexpected error occurred: {e}", file=sys.stderr)

    print(f"Next scan in {SCAN_INTERVAL_HOURS} hours.")
    time.sleep(SCAN_INTERVAL)
