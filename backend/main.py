from functools import lru_cache
import sys
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import settings
from ml.inference.cnn_bilstm_predictor import CNNBiLSTMURLPredictor
from ml.security.url_security_analyzer import URLInputError, URLSecurityAnalyzer

app = FastAPI(
    title="NIVARA API",
    description="Digital Safety Application Backend",
    version="0.1.0",
    debug=settings.debug
)

url_security_analyzer = URLSecurityAnalyzer()


class URLAnalysisRequest(BaseModel):
    url: str = Field(min_length=1, max_length=8192)
    follow_redirects: bool = True


@lru_cache(maxsize=1)
def get_url_predictor():
    """Load the saved Phase 2 model once per backend process."""
    return CNNBiLSTMURLPredictor()


@app.get("/")
async def root():
    return {
        "application": "NIVARA",
        "version": "0.1.0",
        "status": "running",
        "message": "Check before you trust."
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "nivara-backend"
    }


@app.get("/api/v1/status")
async def api_status():
    return {
        "api_version": "v1",
        "endpoints": {
            "health": "/health",
            "qr_decode": "/api/v1/qr/decode (not yet implemented)",
            "url_analyze": "/api/v1/analyze/url"
        },
        "ml_model": "Character-Level CNN + BiLSTM (Phase 2)",
        "qr_scanner": "not implemented yet"
    }


@app.post("/api/v1/analyze/url")
async def analyze_url(request: URLAnalysisRequest):
    """Return independent ML and URL-security evidence; no fused decision."""
    try:
        analysis = url_security_analyzer.analyze(request.url, follow_redirects=request.follow_redirects)
    except URLInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        prediction = get_url_predictor().predict(request.url)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Saved URL model is unavailable") from exc
    analysis["ml"] = {
        "prediction": prediction["prediction"],
        "prediction_index": prediction["prediction_index"],
        "confidence": prediction["confidence"],
        "probabilities": prediction["probabilities"],
        "model": prediction["model"],
    }
    return analysis


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=settings.debug
    )
