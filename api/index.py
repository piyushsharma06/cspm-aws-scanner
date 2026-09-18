
from fastapi import FastAPI

app = FastAPI(
    title="Mini-CSPM AWS Scanner",
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "message": "Mini-CSPM API is running",
        "status": "healthy",
    }


@app.get("/health")
def health_check():
    return {"status": "ok"}
