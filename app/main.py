from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import numpy as np
import pandas as pd
import pickle
import os
import logging
from logging.handlers import RotatingFileHandler
import json
import time
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from fastapi import Depends, Security, HTTPException
from fastapi.security import APIKeyHeader


# Configure application logger
logger = logging.getLogger("cyber_scaler")
logger.setLevel(logging.INFO)

# Ensure logs directory exists (both locally and in Docker)
os.makedirs("logs", exist_ok=True)

# Log format: one JSON per line
log_formatter = logging.Formatter('%(message)s')

# File handler: logs/cyber_scaler.log with rotation
file_handler = RotatingFileHandler(
    "logs/cyber_scaler.log",
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=3
)
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)


# Also log to console (useful in dev / Docker)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)


app = FastAPI(title="🚀 Cyber Intrusion API", version="1.0.0")
API_KEY = "supersecretkey123"
API_KEY_NAME = "X-API-Key"

# auto_error=False so we can log missing header ourselves
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def validate_api_key(x_api_key: str = Security(api_key_header)) -> str:
    """
    Validates API key from X-API-Key header.
    Logs both missing and invalid keys.
    """
    if not x_api_key:
        # Missing header
        error_log = {
            "event": "auth_failed",
            "reason": "missing_api_key",
            "timestamp": time.time(),
        }
        logger.warning(json.dumps(error_log))
        raise HTTPException(
            status_code=401,
            detail="Missing API Key",
        )

    if x_api_key != API_KEY:
        # Wrong key
        error_log = {
            "event": "auth_failed",
            "reason": "invalid_api_key",
            "timestamp": time.time(),
            "provided_key": x_api_key,
        }
        logger.warning(json.dumps(error_log))
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key",
        )

    # Success
    success_log = {
        "event": "auth_success",
        "timestamp": time.time(),
    }
    logger.info(json.dumps(success_log))

    return x_api_key


# Global pipeline variable
rf_pipeline = None

def load_model():
    global rf_pipeline
    if rf_pipeline is None:
        model_path = os.path.join(os.path.dirname(__file__), '..', 'artifacts', 'cyber_rf_pipeline.pkl')

        if not os.path.exists(model_path):
            raise RuntimeError(f"Model file not found at {model_path}")

        with open(model_path, 'rb') as f:
            rf_pipeline = pickle.load(f)

        print("✅ RF pipeline loaded from artifacts/cyber_rf_pipeline.pkl")


class CyberRequest(BaseModel):
    network_packet_size: float = 1500.0
    protocol_type: str = "TCP"
    login_attempts: int = 1
    session_duration: float = 60.0
    failed_logins: int = 0
    unusual_time_access: int = 0  # 0/1
    ip_reputation_score: float = 7.5
    browser_type: str = "Chrome"  # we’ll use this as categorical

class CyberResponse(BaseModel):
    attack_probability: float
    is_attack: bool
    confidence: str
    message: str
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_log = {
        "event": "unhandled_exception",
        "timestamp": time.time(),
        "path": request.url.path,
        "method": request.method,
        "error_type": type(exc).__name__,
        "error_detail": str(exc),
    }
    logger.error(json.dumps(error_log))

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error. Please contact support.",
            "error_type": type(exc).__name__,
        },
    )

@app.get("/")
def root():
    return {"message": "🔥 Cyber API LIVE!", "docs": "/docs"}

@app.post("/predict", response_model=CyberResponse)
def predict(
    request: CyberRequest,
    api_key: str = Depends(validate_api_key),
):
    global rf_pipeline
    load_model()
    ...


    start_time = time.time()

    # 1) Log incoming request
    request_log = {
        "event": "prediction_request",
        "timestamp": time.time(),
        "path": "/predict",
        "features": request.dict(),
    }
    logger.info(json.dumps(request_log))

    # 2) Build input DataFrame with EXACT same columns as training
    #    Features we trained on: [web:10][web:51]
    #    ['network_packet_size', 'protocol_type', 'login_attempts',
    #     'session_duration', 'encryption_used', 'ip_reputation_score',
    #     'failed_logins', 'browser_type', 'unusual_time_access']
    input_row = {
        "network_packet_size": request.network_packet_size,
        "protocol_type": request.protocol_type,
        "login_attempts": request.login_attempts,
        "session_duration": request.session_duration,
        "encryption_used": "AES-256",  # or any default; RF will handle as category
        "ip_reputation_score": request.ip_reputation_score,
        "failed_logins": request.failed_logins,
        "browser_type": request.browser_type,
        "unusual_time_access": request.unusual_time_access,
    }

    input_df = pd.DataFrame([input_row])

    # 3) Predict probability using RF pipeline
    try:
        proba = rf_pipeline.predict_proba(input_df)[0][1]  # prob of attack=1
        prob = float(proba)
    except Exception as e:
        # Log error and raise HTTPException (we’ll improve in Expt 3.3)
        error_log = {
            "event": "prediction_error",
            "timestamp": time.time(),
            "path": "/predict",
            "features": input_row,
            "error": str(e),
        }
        logger.error(json.dumps(error_log))
        raise HTTPException(status_code=500, detail="Model inference failed")

    # 4) Threat classification
    if prob > 0.9:
        confidence, message = "CRITICAL", "🚨 BLOCK IP IMMEDIATELY!"
    elif prob > 0.7:
        confidence, message = "HIGH", "⚠️ QUARANTINE TRAFFIC"
    elif prob > 0.3:
        confidence, message = "MEDIUM", "🟡 CLOSE MONITORING"
    else:
        confidence, message = "LOW", "✅ SAFE TRAFFIC"

    response_body = {
        "attack_probability": prob,
        "is_attack": prob > 0.5,
        "confidence": confidence,
        "message": message,
    }

    # 5) Log response with latency
    response_log = {
        "event": "prediction_response",
        "timestamp": time.time(),
        "path": "/predict",
        "latency_ms": round((time.time() - start_time) * 1000, 2),
        "features": request.dict(),
        "result": response_body,
    }
    logger.info(json.dumps(response_log))

    return CyberResponse(**response_body)

@app.get("/health")
def health():
    try:
        load_model()
        return {"status": "healthy", "model": "rf_pipeline_loaded"}
    except Exception as e:
        logger.error(json.dumps({
            "event": "health_check_error",
            "error": str(e),
            "timestamp": time.time()
        }))
        return {"status": "error", "model": "failed", "detail": str(e)}

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8001, reload=False)
