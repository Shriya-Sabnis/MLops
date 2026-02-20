import joblib

import pickle
import numpy as np
from typing import Dict, Tuple, Any

class CyberModel:
    def __init__(self, model_path: str = 'cyber_nn_model.h5', scaler_path: str = 'cyber_scaler.pkl'):
        """Load trained cyber intrusion detection model"""
        print("🔄 Loading Cyber Intrusion Neural Network...")
        self.model = joblib.load(model_path)
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        print("✅ Cyber NN loaded successfully!")
        print(f"Model input shape: {self.model.input_shape}")
    
    def preprocess(self, data: Dict[str, Any]) -> np.ndarray:
        """Convert request data → model input format"""
        # Get feature names from training data
        feature_order = [
            'network_packet_size', 'protocol_type', 'login_attempts', 
            'session_duration', 'failed_logins', 'unusual_time_access', 
            'ip_reputation_score'  # Add other features as needed
        ]
        
        # Extract values in correct order
        input_array = np.array([[
            data.get('network_packet_size', 0),
            0 if data.get('protocol_type', '') == '' else hash(data['protocol_type']) % 10,  # Simple encoding
            data.get('login_attempts', 0),
            data.get('session_duration', 0),
            data.get('failed_logins', 0),
            data.get('unusual_time_access', 0),
            data.get('ip_reputation_score', 0)
        ]])
        
        # Scale features
        input_scaled = self.scaler.transform(input_array)
        return input_scaled
    
    def predict(self, data: Dict[str, Any]) -> Tuple[float, bool, str]:
        """Make cyber threat prediction"""
        processed = self.preprocess(data)
        prob = self.model.predict(processed, verbose=0)[0][0]
        is_attack = prob > 0.5
        
        # Confidence levels
        if prob > 0.9:
            confidence = "CRITICAL"
            message = "🚨 IMMEDIATE BLOCK - Zero-day attack detected!"
        elif prob > 0.7:
            confidence = "HIGH"
            message = "⚠️  High risk - Quarantine IP immediately"
        elif prob > 0.3:
            confidence = "MEDIUM"
            message = "🟡 Monitor closely - Suspicious activity"
        else:
            confidence = "LOW"
            message = "✅ Traffic appears safe"
            
        return float(prob), is_attack, confidence

# Global model instance (loaded once at startup)
cyber_model = CyberModel()
