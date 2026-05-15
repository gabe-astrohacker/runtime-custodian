from fastapi import FastAPI, HTTPException
import subprocess

app = FastAPI()


@app.get("/ping")
def ping():
    return {"ok": True}


@app.get("/echo")
def echo():
    try:
        result = subprocess.run(
            ["/usr/bin/echo", "hello-from-subprocess"],
            capture_output=True,
            text=True,
            check=True,
        )
        return {
            "endpoint": "echo",
            "output": result.stdout.strip(),
        }
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/bad")
def bad():
    """
    Deliberate policy-violation endpoint for experiments.
    Keep it out of the normal allow policy.
    """
    try:
        result = subprocess.run(
            ["/usr/bin/id"],
            capture_output=True,
            text=True,
            check=True,
        )
        return {
            "endpoint": "bad",
            "output": result.stdout.strip(),
        }
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=str(e))