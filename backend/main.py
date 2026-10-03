from functools import lru_cache
import sys
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import settings
from ml.inference.cnn_bilstm_predictor import CNNBiLSTMURLPredictor
from ml.security.risk_fusion import RiskFusionEngine
from ml.security.threat_intelligence import ThreatIntelligenceAggregator
from ml.security.url_security_analyzer import URLInputError, URLSecurityAnalyzer

app = FastAPI(
    title="NIVARA API",
    description="Digital Safety Application Backend",
    version="0.1.0",
    debug=settings.debug
)

url_security_analyzer = URLSecurityAnalyzer()
threat_intelligence_aggregator = ThreatIntelligenceAggregator.from_environment()
risk_fusion_engine = RiskFusionEngine()


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
def analyze_url(request: URLAnalysisRequest):
    """Return independent URL evidence and an explainable Phase 3C decision."""
    analyzer_failed = False
    try:
        analysis = url_security_analyzer.analyze(request.url, follow_redirects=request.follow_redirects)
    except URLInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception:
        # Preserve a useful, non-PROCEED response if evidence extraction fails.
        # Do not echo the submitted URL because credentials may appear in it.
        analyzer_failed = True
        analysis = {
            "analysis_status": "unavailable",
            "url": None,
            "normalized_url": None,
            "url_structure": None,
            "domain_characteristics": None,
            "security_indicators": None,
            "phase2_ml_features": None,
            "redirect_analysis": {
                "resolution_status": "error",
                "reason": "security_analysis_unavailable",
                "http_status_code": None,
                "redirect_chain": [],
                "redirect_count": 0,
                "final_url": None,
                "final_hostname": None,
                "final_destination_features": None,
                "hostname_changed": None,
                "domain_changed": None,
                "crossed_registered_domains": None,
                "https_changed": None,
                "shortened_url_expanded": None,
                "excessive_redirects": None,
                "max_redirects": None,
            },
            "final_destination_features": None,
            "threat_intelligence": {
                "status": "unavailable", "providers": [],
                "matched_providers": [], "categories": [],
            },
            "risk_decision": None,
        }

    if analyzer_failed:
        prediction = None
    else:
        try:
            prediction = get_url_predictor().predict(request.url)
        except Exception:
            prediction = None
    if prediction is None:
        analysis["ml"] = {
            "status": "unavailable",
            "prediction": None,
            "prediction_index": None,
            "confidence": None,
            "probabilities": None,
            "model": "cnn_bilstm",
        }
    else:
        analysis["ml"] = {
            "prediction": prediction["prediction"],
            "prediction_index": prediction["prediction_index"],
            "confidence": prediction["confidence"],
            "probabilities": prediction["probabilities"],
            "model": prediction["model"],
        }
    if not analyzer_failed:
        try:
            analysis["threat_intelligence"] = threat_intelligence_aggregator.check(analysis["normalized_url"])
        except Exception:
            # Threat intelligence is optional; it must not make core URL analysis fail.
            analysis["threat_intelligence"] = {
                "status": "unavailable",
                "providers": [],
                "matched_providers": [],
                "categories": [],
            }
    analysis["risk_decision"] = risk_fusion_engine.evaluate(
        url=request.url,
        ml_prediction=analysis["ml"],
        security_analysis=analysis,
        threat_intelligence=analysis["threat_intelligence"],
        redirect_analysis=analysis["redirect_analysis"],
    )
    return analysis


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=settings.debug
    )
