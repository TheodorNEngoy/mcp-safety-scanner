import uvicorn

# Public bind: should be flagged.
uvicorn.run("app:app", host="0.0.0.0", port=8000)

