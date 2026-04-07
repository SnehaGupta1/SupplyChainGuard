"""
ML Prediction Module
Loads trained models and makes predictions on new packages.
"""

import os
import pickle
import numpy as np
from config.settings import ML_MODELS_DIR


class MalwarePredictor:
    """
    Loads trained models and predicts if a package is malicious.
    """

    def __init__(self):
        self.models = {}
        self._load_models()

    def _load_models(self):
        """Load all available trained models"""
        model_files = {
            "isolation_forest": "isolation_forest.pkl",
            "random_forest": "random_forest.pkl"
        }

        for name, filename in model_files.items():
            path = os.path.join(ML_MODELS_DIR, filename)
            if os.path.exists(path):
                try:
                    with open(path, "rb") as f:
                        self.models[name] = pickle.load(f)
                except Exception as e:
                    print(f"Warning: Could not load {name}: {e}")

    def predict(self, feature_vector):
        """
        Run predictions using all available models.
        Returns combined prediction result.
        """
        results = {
            "models_available": list(self.models.keys()),
            "predictions": {},
            "is_suspicious": False,
            "confidence": 0.0
        }

        if not self.models:
            results["warning"] = "No trained models available"
            return results

        feature_array = np.array(feature_vector).reshape(1, -1)

        # Isolation Forest
        if "isolation_forest" in self.models:
            model = self.models["isolation_forest"]
            prediction = model.predict(feature_array)[0]
            score = model.score_samples(feature_array)[0]

            results["predictions"]["isolation_forest"] = {
                "prediction": "anomaly" if prediction == -1 else "normal",
                "anomaly_score": round(float(score), 4),
                "is_anomaly": prediction == -1
            }

        # Random Forest
        if "random_forest" in self.models:
            model = self.models["random_forest"]
            prediction = model.predict(feature_array)[0]
            probabilities = model.predict_proba(feature_array)[0]

            results["predictions"]["random_forest"] = {
                "prediction": "malicious" if prediction == 1 else "safe",
                "confidence": round(float(max(probabilities)), 4),
                "malicious_probability": round(float(probabilities[1]) if len(probabilities) > 1 else 0, 4),
                "is_malicious": prediction == 1
            }

        # Combined verdict
        suspicious_votes = 0
        total_votes = 0

        for model_name, pred in results["predictions"].items():
            total_votes += 1
            if pred.get("is_anomaly") or pred.get("is_malicious"):
                suspicious_votes += 1

        if total_votes > 0:
            results["is_suspicious"] = suspicious_votes > (total_votes / 2)
            results["confidence"] = round(suspicious_votes / total_votes, 2)

        return results