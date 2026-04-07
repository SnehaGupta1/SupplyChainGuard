"""
ML Model Training Module
Trains anomaly detection models on package features.
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix
)
from config.settings import ML_MODELS_DIR


class ModelTrainer:
    """
    Trains and evaluates ML models for malicious package detection.
    """

    def __init__(self):
        self.models = {}
        os.makedirs(ML_MODELS_DIR, exist_ok=True)

    def train_isolation_forest(self, features, contamination=0.1):
        """
        Train Isolation Forest for unsupervised anomaly detection.
        Useful when you have mostly clean packages.
        """
        model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )

        model.fit(features)
        self.models["isolation_forest"] = model

        # Evaluate on training data
        predictions = model.predict(features)
        anomaly_count = sum(1 for p in predictions if p == -1)

        result = {
            "model": "IsolationForest",
            "total_samples": len(features),
            "anomalies_detected": anomaly_count,
            "anomaly_percentage": round(anomaly_count / len(features) * 100, 2),
            "contamination": contamination
        }

        # Save model
        model_path = os.path.join(ML_MODELS_DIR, "isolation_forest.pkl")
        with open(model_path, "wb") as f:
            pickle.dump(model, f)

        result["model_path"] = model_path
        return result

    def train_random_forest(self, features, labels):
        """
        Train Random Forest for supervised classification.
        Requires labeled data (0=safe, 1=malicious).
        """
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42,
            stratify=labels
        )

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )

        model.fit(X_train, y_train)
        self.models["random_forest"] = model

        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True)

        result = {
            "model": "RandomForest",
            "accuracy": round(accuracy, 4),
            "confusion_matrix": cm.tolist(),
            "classification_report": report,
            "feature_importance": dict(zip(
                [f"feature_{i}" for i in range(features.shape[1])],
                model.feature_importances_.tolist()
            ))
        }

        # Save model
        model_path = os.path.join(ML_MODELS_DIR, "random_forest.pkl")
        with open(model_path, "wb") as f:
            pickle.dump(model, f)

        result["model_path"] = model_path
        return result