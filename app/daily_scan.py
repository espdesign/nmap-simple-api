import time
import subprocess
from datetime import datetime
import os
import sys
import json
import xmltodict  # This script also requires: pip install xmltodict

# --- Configuration ---
# Get scan target from environment variable, default to 'scanme.nmap.org' for a safe example
SCAN_TARGET = os.environ.get("SCAN_TARGET", "scanme.nmap.org")
# Get scan interval from environment variable, default to 24 hours
SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", 24))
SCAN_INTERVAL = SCAN_INTERVAL_HOURS * 60 * 60  # Convert hours to seconds

# Use an absolute path for the output directory
OUTPUT_DIR = "/code/app/scan_results"


def ensure_output_dir_exists():
    """Creates the output directory if it doesn't exist."""
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    except OSError as e:
        # A critical failure if we can't create the directory.
        print(
            f"FATAL: Could not create output directory {OUTPUT_DIR}: {e}",
            file=sys.stderr,
        )
        sys.exit(1)


def write_json_file(data, filename):
    """Writes a Python dictionary to a JSON file."""
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Scan results saved to {filepath}")


# --- Main Loop ---
print("Starting periodic nmap scanner...")
while True:
    ensure_output_dir_exists()

    # Generate a timestamp for the filename (e.g., 2025-10-03_21-35-31)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    now_iso = datetime.utcnow().isoformat() + "Z"  # Use UTC for logs

    try:
        print(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running nmap scan on {SCAN_TARGET}..."
        )

        # Run nmap with XML output to stdout ('-oX -')
        # This is more reliable than parsing plain text.
        cmd = ["nmap", "-oX", "-", SCAN_TARGET]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, check=True
        )

        # Convert Nmap's XML output to a Python dictionary
        scan_data_dict = xmltodict.parse(result.stdout)

        # Structure the final JSON output for successful scans
        output_data = {
            "scan_timestamp_utc": now_iso,
            "scan_target": SCAN_TARGET,
            "scan_successful": True,
            "nmap_data": scan_data_dict.get("nmaprun", {}),  # Get the root element
        }

        # Write the successful scan data to a timestamped JSON file
        filename = f"scan_{timestamp}.json"
        write_json_file(output_data, filename)

    except subprocess.CalledProcessError as e:
        # This error occurs when nmap returns a non-zero exit code.
        print(
            f"ERROR: nmap command failed with exit code {e.returncode}.",
            file=sys.stderr,
        )

        # --- IMPROVED LOGGING ---
        # Log the detailed error to the server console for easier debugging
        error_message = e.stderr.strip() if e.stderr else "No stderr output from Nmap."
        print(f"  Target: {SCAN_TARGET}", file=sys.stderr)
        print(f"  Nmap Stderr: {error_message}", file=sys.stderr)
        # --- END IMPROVED LOGGING ---

        error_details = {
            "error_type": "NmapExecutionError",
            "return_code": e.returncode,
            "stdout": e.stdout,
            "stderr": e.stderr,
        }

        output_data = {
            "scan_timestamp_utc": now_iso,
            "scan_target": SCAN_TARGET,
            "scan_successful": False,
            "error": error_details,
        }

        # Write the error data to a timestamped JSON file
        filename = f"scan_{timestamp}_error.json"
        write_json_file(output_data, filename)

    except Exception as e:
        # Catch any other exceptions (e.g., timeout, parsing errors).
        print(f"ERROR: An unexpected error occurred: {e}", file=sys.stderr)

        error_details = {"error_type": "ScriptError", "message": str(e)}

        output_data = {
            "scan_timestamp_utc": now_iso,
            "scan_target": SCAN_TARGET,
            "scan_successful": False,
            "error": error_details,
        }

        # Write the error data to a timestamped JSON file
        filename = f"scan_{timestamp}_error.json"
        write_json_file(output_data, filename)

    print(f"Next scan in {SCAN_INTERVAL_HOURS} hours.")
    time.sleep(SCAN_INTERVAL)
