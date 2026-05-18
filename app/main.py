"""
PhishGuard Backend API
A phishing URL detection service powered by a trained URL feature model.
"""

import json
import re
import threading
import time
import warnings
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

warnings.filterwarnings("ignore", category=UserWarning)

app = FastAPI(
    title="PhishGuard API",
    description="Phishing URL detection API using ML URL features",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
MODEL_PATH = BASE_DIR / "model.pkl"
FEATURE_COLUMNS_PATH = BASE_DIR / "feature_columns.pkl"
LABEL_ENCODER_PATH = BASE_DIR / "label_encoder.pkl"
METRICS_PATH = BASE_DIR / "metrics.json"

model = None
feature_columns = None
label_encoder = None
model_lock = threading.Lock()

if METRICS_PATH.exists():
    with open(METRICS_PATH, "r") as f:
        model_metrics = json.load(f)
else:
    model_metrics = {}


def load_artifacts():
    """Load model artifacts once, on first use."""
    global model, feature_columns, label_encoder

    if model is not None and feature_columns is not None and label_encoder is not None:
        return model, feature_columns, label_encoder

    with model_lock:
        if model is not None and feature_columns is not None and label_encoder is not None:
            return model, feature_columns, label_encoder

        missing = [
            str(path)
            for path in (MODEL_PATH, FEATURE_COLUMNS_PATH, LABEL_ENCODER_PATH)
            if not path.exists()
        ]
        if missing:
            raise HTTPException(status_code=500, detail=f"Missing model artifacts: {', '.join(missing)}")

        print("Loading ML artifacts...", flush=True)
        start = time.perf_counter()
        try:
            model = joblib.load(MODEL_PATH)
            feature_columns = joblib.load(FEATURE_COLUMNS_PATH)
            label_encoder = joblib.load(LABEL_ENCODER_PATH)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Model artifact load failed: {str(e)}")

        elapsed = round(time.perf_counter() - start, 2)
        print(f"ML artifacts loaded successfully in {elapsed}s.", flush=True)
        return model, feature_columns, label_encoder


def extract_url_features(url: str) -> dict:
    """Extract human-readable features from a URL for the response payload."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        path = parsed.path
        tld = domain.split(".")[-1] if "." in domain else ""

        has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain))
        subdomain_count = max(0, len(domain.split(".")) - 2)
        suspicious_tlds = {"xyz", "tk", "ml", "gq", "cf", "ga", "pw", "cc", "top", "ru", "xwq"}
        common_tlds = {"com", "org", "net", "edu", "gov", "mil", "io", "co", "us", "uk", "ph", "dev", "app", "ai"}
        special_chars = len(re.findall(r"[@=?&%#~;]", url))

        flags = []
        if has_ip:
            flags.append("IP address used as domain")
        if parsed.scheme != "https":
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


def extract_model_features(url: str) -> dict:
    """Extract the 18 feature columns used by the retrained random forest."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    decoded_url = unquote(url)

    url_len = len(url)
    domain_len = len(domain)
    has_ip = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain)))
    tld = domain.split(".")[-1] if "." in domain else ""
    subdomain_count = max(0, len(domain.split(".")) - 2)

    obfuscated_chars = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    has_obfuscation = int(obfuscated_chars > 0 or decoded_url != url)
    letters = len(re.findall(r"[A-Za-z]", url))
    digits = len(re.findall(r"\d", url))
    other_special_chars = len(re.findall(r"[^A-Za-z0-9]", url))

    return {
        "URLLength": url_len,
        "DomainLength": domain_len,
        "IsDomainIP": has_ip,
        "TLDLength": len(tld),
        "NoOfSubDomain": subdomain_count,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": obfuscated_chars,
        "ObfuscationRatio": obfuscated_chars / url_len if url_len else 0,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / url_len if url_len else 0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / url_len if url_len else 0,
        "NoOfEqualsInURL": url.count("="),
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "NoOfOtherSpecialCharsInURL": other_special_chars,
        "SpacialCharRatioInURL": other_special_chars / url_len if url_len else 0,
        "IsHTTPS": int(parsed.scheme == "https"),
    }


def build_feature_frame(urls: list[str], columns: list[str]) -> pd.DataFrame:
    rows = [extract_model_features(url) for url in urls]
    return pd.DataFrame(rows).reindex(columns=columns, fill_value=0)


def get_label_probabilities(clf, encoder, proba_row):
    class_to_probability = {
        encoder.inverse_transform([int(class_value)])[0]: float(proba_row[index])
        for index, class_value in enumerate(clf.classes_)
    }
    fake_prob = class_to_probability.get("fake", 0.0)
    safe_prob = class_to_probability.get("safe", 0.0)
    return fake_prob, safe_prob


def get_risk_level(fake_prob: float) -> str:
    if fake_prob >= 0.80:
        return "high"
    if fake_prob >= 0.50:
        return "medium"
    if fake_prob >= 0.25:
        return "low"
    return "safe"




def get_rule_fake_probability(url: str, features: dict) -> float:
    """Conservative URL rule score used as a guardrail around the model."""
    flags = set(features.get("suspicious_flags", []))
    score = 0.0

    if features.get("has_ip_address"):
        score += 0.35
    if not features.get("has_https"):
        score += 0.20
    if any(flag.startswith("Suspicious TLD") for flag in flags):
        score += 0.35
    if any(flag.startswith("Uncommon TLD") for flag in flags):
        score += 0.25
    if "Contains sensitive keywords" in flags:
        score += 0.30
    if "Contains @ symbol (redirect trick)" in flags:
        score += 0.35
    if any(flag.startswith("Excessive subdomains") for flag in flags):
        score += 0.20
    if any(flag.startswith("Unusually long URL") for flag in flags):
        score += 0.15
    if any(flag.startswith("Many special characters") for flag in flags):
        score += 0.15

    sensitive_hits = re.findall(
        r"(login|verify|secure|account|update|confirm|bank|paypal|signin|password|credential|wallet|prize|gift|free|limited|urgent)",
        url,
        re.I,
    )
    if len(sensitive_hits) >= 3:
        score += 0.30
    elif re.search(r"(password|credential|wallet|prize|gift|free|limited|urgent)", url, re.I):
        score += 0.15

    if re.search(r"(paypal|google|microsoft|apple|facebook|bank)", url, re.I) and any(
        flag.startswith(("Suspicious TLD", "Uncommon TLD")) for flag in flags
    ):
        score += 0.20

    return min(score, 1.0)
def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


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
        return normalize_url(v)


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


@app.get("/", tags=["Health"])
def root():
    return {
        "service": "PhishGuard API",
        "status": "running",
        "version": "1.0.0",
        "model": model_metrics.get("best_model", "random_forest_url_features"),
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
    return {
        "best_model": model_metrics.get("best_model", "random_forest_url_features"),
        "trained_at": model_metrics.get("trained_at"),
        "dataset": model_metrics.get("dataset"),
        "labels": ["fake", "safe"],
        "feature_columns": feature_columns if feature_columns is not None else None,
    }


@app.post("/predict", tags=["Prediction"])
def predict_url(request: URLCheckRequest):
    url = request.url
    start = time.perf_counter()

    try:
        clf, columns, encoder = load_artifacts()
        feature_frame = build_feature_frame([url], columns)
        proba = clf.predict_proba(feature_frame)[0]
        encoded_label = int(clf.predict(feature_frame)[0])
        decoded_label = encoder.inverse_transform([encoded_label])[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model prediction failed: {str(e)}")

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    fake_prob, safe_prob = get_label_probabilities(clf, encoder, proba)
    features = extract_url_features(url)
    rule_fake_prob = get_rule_fake_probability(url, features)
    fake_prob = max(fake_prob, rule_fake_prob)
    safe_prob = min(safe_prob, 1.0 - fake_prob)
    is_fake = decoded_label == "fake" or fake_prob >= 0.80

    return {
        "url": url,
        "prediction": "phishing" if is_fake else "legitimate",
        "label": decoded_label,
        "is_phishing": is_fake,
        "risk_level": get_risk_level(fake_prob),
        "confidence": {
            "phishing": round(fake_prob, 6),
            "legitimate": round(safe_prob, 6),
            "fake": round(fake_prob, 6),
            "safe": round(safe_prob, 6),
        },
        "url_features": features,
        "model_features": extract_model_features(url),
        "meta": {
            "model_used": model_metrics.get("best_model", "random_forest_url_features"),
            "inference_time_ms": elapsed_ms,
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
        },
    }


@app.post("/predict/bulk", tags=["Prediction"])
def predict_bulk(request: BulkURLCheckRequest):
    normalized = [normalize_url(url) for url in request.urls]
    start = time.perf_counter()

    try:
        clf, columns, encoder = load_artifacts()
        feature_frame = build_feature_frame(normalized, columns)
        probas = clf.predict_proba(feature_frame)
        encoded_preds = clf.predict(feature_frame)
        decoded_preds = encoder.inverse_transform(encoded_preds.astype(int))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk prediction failed: {str(e)}")

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    results = []
    fake_count = 0

    for i, url in enumerate(normalized):
        fake_prob, safe_prob = get_label_probabilities(clf, encoder, probas[i])
        features = extract_url_features(url)
        rule_fake_prob = get_rule_fake_probability(url, features)
        fake_prob = max(fake_prob, rule_fake_prob)
        safe_prob = min(safe_prob, 1.0 - fake_prob)
        is_fake = decoded_preds[i] == "fake" or fake_prob >= 0.80
        if is_fake:
            fake_count += 1

        results.append({
            "url": url,
            "prediction": "phishing" if is_fake else "legitimate",
            "label": decoded_preds[i],
            "is_phishing": is_fake,
            "risk_level": get_risk_level(fake_prob),
            "confidence": {
                "phishing": round(fake_prob, 6),
                "legitimate": round(safe_prob, 6),
                "fake": round(fake_prob, 6),
                "safe": round(safe_prob, 6),
            },
        })

    return {
        "results": results,
        "summary": {
            "total": len(normalized),
            "phishing_detected": fake_count,
            "legitimate": len(normalized) - fake_count,
            "phishing_rate": round(fake_count / len(normalized) * 100, 2),
        },
        "meta": {
            "model_used": model_metrics.get("best_model", "random_forest_url_features"),
            "inference_time_ms": elapsed_ms,
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
        },
    }


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





