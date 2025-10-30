from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
import subprocess
import os
import json
from typing import List

# This library is now a dependency for the API as well
# You can install it with: pip install xmltodict
import xmltodict

app = FastAPI(
    title="Nmap Results API",
    description="An API to run on-demand Nmap scans and retrieve results from a periodic background scanner.",
    version="2.0.0",
)

# --- Configuration ---
# This must match the OUTPUT_DIR in your background scanner script
RESULTS_DIR = "/code/app/scan_results"


# Pydantic model for the request body of the on-demand scan
class ScanRequest(BaseModel):
    target: str
    # Example: "scanme.nmap.org" or "192.168.1.0/24"
    arguments: str = "-F"  # Default to a fast scan, but allow overrides


@app.get("/", summary="API Status", tags=["General"])
def index():
    """Returns a simple message to confirm the API is running."""
    return {"message": "Nmap Results API is running."}


@app.post("/scan", summary="Run an On-Demand Scan", tags=["Scanning"])
def scan(request: ScanRequest):
    """
    Triggers a new Nmap scan immediately.
    This scan is synchronous and returns structured JSON output upon completion.
    """
    # Basic input validation to prevent command injection
    # Splitting arguments helps ensure they are treated as separate flags
    args = request.arguments.split()
    if not request.target:
        raise HTTPException(status_code=400, detail="Scan target cannot be empty.")

    try:
        # Use nmap's XML output ('-oX -') which is reliable to parse
        cmd = ["nmap", "-oX", "-"] + args + [request.target]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, check=True
        )

        # Convert the XML output to a dictionary
        scan_data_dict = xmltodict.parse(result.stdout)
        return scan_data_dict

    except subprocess.CalledProcessError as e:
        # This error is raised when nmap returns a non-zero exit code (e.g., target down)
        raise HTTPException(
            status_code=500,
            detail={
                "error_type": "NmapExecutionError",
                "message": "Nmap command failed.",
                "return_code": e.returncode,
                "stdout": e.stdout,
                "stderr": e.stderr,
            },
        )
    except Exception as e:
        # Catch any other exception (e.g., timeout)
        raise HTTPException(
            status_code=500, detail={"error_type": "ScriptError", "message": str(e)}
        )


@app.get(
    "/results",
    summary="List All Scan Results",
    response_model=List[str],
    tags=["Results"],
)
def get_all_results():
    """
    Returns a list of all available scan result filenames, sorted newest to oldest.
    """
    if not os.path.isdir(RESULTS_DIR):
        # If the directory doesn't exist yet, return an empty list.
        return []
    try:
        # Filter for .json files, sort descending to show newest first
        files = sorted(
            [f for f in os.listdir(RESULTS_DIR) if f.endswith(".json")],
            reverse=True,
        )
        return files
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/results/latest", summary="Get Latest Scan Result", tags=["Results"])
def get_latest_result():
    """
    Retrieves the full JSON content of the most recent scan.
    """
    files = get_all_results()  # Reuse the logic from the other endpoint
    if not files:
        raise HTTPException(status_code=404, detail="No scan results found.")

    latest_file_path = os.path.join(RESULTS_DIR, files[0])

    try:
        with open(latest_file_path, "r") as f:
            content = json.load(f)
        return content
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Could not read or parse file: {str(e)}"
        )


@app.get("/results/{filename}", summary="Get a Specific Scan Result", tags=["Results"])
def get_specific_result(filename: str):
    """
    Retrieves the full JSON content of a specific scan by its filename.
    The filename must end in '.json'.
    """
    # Security: Prevent directory traversal attacks
    if ".." in filename or "/" in filename or not filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Invalid or malicious filename.")

    file_path = os.path.join(RESULTS_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found.")

    try:
        # Use Response to serve the file directly with the correct media type
        with open(file_path, "r") as f:
            return Response(content=f.read(), media_type="application/json")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not read file: {str(e)}")

@app.get("/hosts/active", summary="Get Active Hosts on Network", tags=["Hosts"])
def get_active_hosts():
    """
    Returns a list of hosts currently active on the network.
    """
    latest_result = get_latest_result()  # Reuse the logic from the other endpoint

    try:
        hosts = latest_result["nmap_data"]["hosthint"]
        output = []
        for host in hosts:
            host_info = {}
            if "address" in host:
                host_info["ip"] = host["address"]["@addr"]
            if "hostnames" in host and "hostname" in host["hostnames"]:
                host_info["hostname"] = host["hostnames"]["hostname"]["@name"]
            output.append(host_info)

        
            return {"active_hosts": output}

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error processing scan data: {str(e)}"
        )
