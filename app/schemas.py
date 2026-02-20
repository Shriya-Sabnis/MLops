from pydantic import BaseModel
from typing import Optional
import numpy as np

class CyberRequest(BaseModel):
    network_packet_size: float
    protocol_type: str
    login_attempts: int
    session_duration: float
    failed_logins: int
    unusual_time_access: int
    ip_reputation_score: float
    # Add other features from your dataset
    
    class Config:
        schema_extra = {
            "example": {
                "network_packet_size": 1500.5,
                "protocol_type": "TCP",
                "login_attempts": 3,
                "session_duration": 120.5,
                "failed_logins": 0,
                "unusual_time_access": 0,
                "ip_reputation_score": 8.2
            }
        }

class CyberResponse(BaseModel):
    attack_probability: float
    is_attack: bool
    confidence: str
    message: str
    
    class Config:
        schema_extra = {
            "example": {
                "attack_probability": 0.92,
                "is_attack": True,
                "confidence": "HIGH",
                "message": "🚨 IMMEDIATE ACTION: Block IP & Alert SOC"
            }
        }
