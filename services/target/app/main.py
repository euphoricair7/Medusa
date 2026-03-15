"""
Medusa Target — vulnerable app for labs.

Vulnerabilities:
  /ping?host=...  → command injection  (MITRE T1059)
  /read?path=...  → path traversal     (MITRE T1005)

NOT IN PROD ENV.
"""
import subprocess
from fastapi import FastAPI, Query

app = FastAPI(title="medusa Target", description="Vulnerable app — lab only")


@app.get("/")
def index():
    return {"status": "running", "note": "vulnerable lab target"}


# VULN: command injection
@app.get("/ping")
def ping(host: str = Query(default="localhost")):
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return {"stdout": result.stdout, "stderr": result.stderr}


# VULN: path traversal
@app.get("/read")
def read_file(path: str = Query(default="/etc/hostname")):
    try:
        with open(path) as f:
            return {"path": path, "content": f.read()}
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)