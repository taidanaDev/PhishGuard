"""
PhishGuard Backend API
A phishing URL detection service powered by a TF-IDF + LinearSVC ML model
trained on the PhiUSIIL Phishing URL Dataset (235,795 URLs).
"""

import json
import re
import threading
import time
import warnings
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import joblib
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

# Suppress sklearn version mismatch warnings
warnings.filterwarnings("ignore", category=UserWarning)

# ── App Setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description="Phishing URL detection API using ML (PhiUSIIL Dataset)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Frontend team: restrict this to your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Model Loading ──────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
MODEL_PATH = BASE_DIR / "model.pkl"
METRICS_PATH = BASE_DIR / "metrics.json"

model = None
model_lock = threading.Lock()

with open(METRICS_PATH, "r") as f:
    model_metrics = json.load(f)

# Label encoding: 0 = Phishing, 1 = Legitimate
LABEL_MAP = {0: "phishing", 1: "legitimate"}


def get_model():
    """Load the ML model once, on the first prediction request."""
    global model

    if model is not None:
        return model

    with model_lock:
        if model is not None:
            return model

        if not MODEL_PATH.exists():
            raise HTTPException(status_code=500, detail=f"Model file not found: {MODEL_PATH}")

        print(f"Loading ML model from {MODEL_PATH}...", flush=True)
        start = time.perf_counter()
        try:
            model = joblib.load(MODEL_PATH)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Model load failed: {str(e)}")

        elapsed = round(time.perf_counter() - start, 2)
        print(f"Model loaded successfully in {elapsed}s.", flush=True)
        return model

# ── Helpers ────────────────────────────────────────────────────────────────────

def extract_url_features(url: str) -> dict:
    """Extract human-readable features from a URL for the response payload."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        path = parsed.path
        query = parsed.query

        has_ip = bool(
            re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain)
        )
        subdomain_count = max(0, len(domain.split(".")) - 2)
        tld = domain.split(".")[-1] if "." in domain else ""
        suspicious_tlds = {"xyz", "tk", "ml", "gq", "cf", "ga", "pw", "cc", "top", "ru"}
        special_chars = len(re.findall(r"[@=?&%#~;]", url))

        flags = []
        if has_ip:
            flags.append("IP address used as domain")
        if not parsed.scheme == "https":
            flags.append("Not using HTTPS")
        if subdomain_count > 2:
            flags.append(f"Excessive subdomains ({subdomain_count})")
        if tld.lower() in suspicious_tlds:
            flags.append(f"Suspicious TLD (.{tld})")
        if len(url) > 75:
            flags.append(f"Unusually long URL ({len(url)} chars)")
        if special_chars > 5:
            flags.append(f"Many special characters ({special_chars})")
        if re.search(r"(login|verify|secure|account|update|confirm|bank|paypal|signin)", url, re.I):
            flags.append("Contains sensitive keywords")
        if "@" in url:
            flags.append("Contains @ symbol (redirect trick)")
        if "//" in path:
            flags.append("Double slashes in path")

        return {
            "domain": domain,
            "scheme": parsed.scheme,
            "tld": tld,
            "url_length": len(url),
            "has_https": parsed.scheme == "https",
            "has_ip_address": has_ip,
            "subdomain_count": subdomain_count,
            "special_char_count": special_chars,
            "suspicious_flags": flags,
        }
    except Exception:
        return {}


def get_risk_level(phishing_prob: float) -> str:
    if phishing_prob >= 0.80:
        return "high"
    elif phishing_prob >= 0.50:
        return "medium"
    elif phishing_prob >= 0.25:
        return "low"
    else:
        return "safe"


# ── Request / Response Schemas ─────────────────────────────────────────────────

class URLCheckRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty.")
        if len(v) > 2048:
            raise ValueError("URL is too long (max 2048 characters).")
        # Auto-prepend scheme if missing
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        return v


class BulkURLCheckRequest(BaseModel):
    urls: list[str]

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v):
        if not v:
            raise ValueError("URLs list must not be empty.")
        if len(v) > 50:
            raise ValueError("Maximum 50 URLs per batch request.")
        return v


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "service": "PhishGuard API",
        "status": "running",
        "version": "1.0.0",
        "model": model_metrics.get("best_model"),
        "trained_at": model_metrics.get("trained_at"),
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "model_loaded": model is not None,
    }


@app.get("/model/info", tags=["Model"])
def model_info():
    """Returns metadata about the loaded ML model and its performance metrics."""
    best = model_metrics.get("best_model", "tfidf_linearsvc_calibrated")
    best_metrics = model_metrics.get("models", {}).get(best, {})
    return {
        "best_model": best,
        "trained_at": model_metrics.get("trained_at"),
        "dataset": model_metrics.get("dataset"),
        "performance": {
            "accuracy": best_metrics.get("accuracy"),
            "precision": best_metrics.get("precision"),
            "recall": best_metrics.get("recall"),
            "f1_score": best_metrics.get("f1"),
            "roc_auc": best_metrics.get("roc_auc"),
        },
        "all_models": {
            name: {
                "accuracy": m.get("accuracy"),
                "f1_score": m.get("f1"),
                "roc_auc": m.get("roc_auc"),
            }
            for name, m in model_metrics.get("models", {}).items()
        },
    }


@app.post("/predict", tags=["Prediction"])
def predict_url(request: URLCheckRequest):
    """
    Analyze a single URL for phishing.

    Returns a prediction (legitimate / phishing), confidence scores,
    risk level, and a breakdown of suspicious URL features.
    """
    url = request.url
    start = time.perf_counter()

    try:
        clf = get_model()
        proba = clf.predict_proba([url])[0]
        pred_label = clf.predict([url])[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model prediction failed: {str(e)}")

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    phishing_prob = float(proba[0])   # class 0 = phishing
    legit_prob = float(proba[1])       # class 1 = legitimate
    prediction = LABEL_MAP[int(pred_label)]
    risk = get_risk_level(phishing_prob)
    features = extract_url_features(url)

    return {
        "url": url,
        "prediction": prediction,
        "is_phishing": prediction == "phishing",
        "risk_level": risk,
        "confidence": {
            "phishing": round(phishing_prob, 6),
            "legitimate": round(legit_prob, 6),
        },
        "url_features": features,
        "meta": {
            "model_used": model_metrics.get("best_model"),
            "inference_time_ms": elapsed_ms,
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
        },
    }


@app.post("/predict/bulk", tags=["Prediction"])
def predict_bulk(request: BulkURLCheckRequest):
    """
    Analyze up to 50 URLs in one request.

    Returns predictions for each URL plus an overall summary.
    """
    urls = request.urls
    # Normalize URLs
    normalized = []
    for u in urls:
        u = u.strip()
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        normalized.append(u)

    start = time.perf_counter()
    try:
        clf = get_model()
        probas = clf.predict_proba(normalized)
        preds = clf.predict(normalized)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk prediction failed: {str(e)}")

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    results = []
    phishing_count = 0
    for i, url in enumerate(normalized):
        phishing_prob = float(probas[i][0])
        legit_prob = float(probas[i][1])
        prediction = LABEL_MAP[int(preds[i])]
        if prediction == "phishing":
            phishing_count += 1

        results.append({
            "url": url,
            "prediction": prediction,
            "is_phishing": prediction == "phishing",
            "risk_level": get_risk_level(phishing_prob),
            "confidence": {
                "phishing": round(phishing_prob, 6),
                "legitimate": round(legit_prob, 6),
            },
        })

    return {
        "results": results,
        "summary": {
            "total": len(urls),
            "phishing_detected": phishing_count,
            "legitimate": len(urls) - phishing_count,
            "phishing_rate": round(phishing_count / len(urls) * 100, 2),
        },
        "meta": {
            "model_used": model_metrics.get("best_model"),
            "inference_time_ms": elapsed_ms,
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
        },
    }


# ── Error Handlers ─────────────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )
