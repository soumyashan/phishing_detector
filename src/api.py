import sys
import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel


# Make src directory importable
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from explain_detector import generate_explanation


app = FastAPI(
    title="AI Phishing Email Detector",
    description="AI-powered phishing email detection API",
    version="1.0.0"
)


class EmailRequest(BaseModel):
    email_text: str


# ─────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/predict")
def predict_email(request: EmailRequest):

    result = generate_explanation(
        request.email_text
    )

    return result


# ─────────────────────────────────────────────
# FRONTEND
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return FileResponse(
        "frontend/index.html"
    )


# Serve all frontend files:
# styles.css, app.js, pages.js, parser.js, etc.
app.mount(
    "/",
    StaticFiles(
        directory="frontend"
    ),
    name="frontend"
)