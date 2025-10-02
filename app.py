
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import os

app = FastAPI()

class ScanRequest(BaseModel):
    target: str

@app.get("/")
def index():
    return {"message": "Nmap Simple API is running."}

@app.post("/scan")
def scan(request: ScanRequest):
    target = request.target
    if not target:
        raise HTTPException(status_code=400, detail="No target specified")
    try:
        result = subprocess.run(["nmap", "-F", target], capture_output=True, text=True, timeout=30)
        return {"output": result.stdout, "error": result.stderr}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs")
def get_logs():
    log_path = "/app/logs/daily_scan.log"
    if not os.path.exists(log_path):
        raise HTTPException(status_code=404, detail="Log file not found.")
    try:
        with open(log_path, "r") as f:
            content = f.read()
        return {"log": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scanned-ips")
def get_scanned_ips():
    ips_path = "/app/logs/nmap_scanned_ips.txt"
    if not os.path.exists(ips_path):
        raise HTTPException(status_code=404, detail="Scanned IPs file not found.")
    try:
        with open(ips_path, "r") as f:
            ips = [line.strip() for line in f if line.strip()]
        return {"scanned_ips": ips}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
