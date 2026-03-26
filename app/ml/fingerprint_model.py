"""
Random Forest Fingerprint Classifier
──────────────────────────────────────
Features (4):  [banner_score, timing_score, filesystem_score, protocol_depth_score]
Output:        honeypot_confidence  (0.0 → 1.0)

On first run with no trained model, falls back to a simple weighted heuristic.
As RedOps collects more fingerprint results with ground truth labels, the model
improves via retrain() called from the campaign feedback loop.
"""
import os
import json
import logging
import numpy as np
from pathlib import Path
from typing import List

log = logging.getLogger("redops.ml.fingerprint")

MODEL_PATH = Path("models/fingerprint_rf.pkl")

# Feature weights for the heuristic fallback
# Derived from domain knowledge — banner is strongest signal
HEURISTIC_WEIGHTS = [0.40, 0.25, 0.20, 0.15]


class FingerprintClassifier:
    """
    Wraps scikit-learn RandomForestClassifier with train/predict/persist.
    Falls back to weighted heuristic when model file doesn't exist.
    """

    def __init__(self, model=None):
        self._model = model

    @classmethod
    def load(cls) -> "FingerprintClassifier":
        """Load trained model from disk, or return heuristic classifier."""
        if MODEL_PATH.exists():
            try:
                import joblib
                model = joblib.load(MODEL_PATH)
                log.info("Loaded RF model from %s", MODEL_PATH)
                return cls(model=model)
            except Exception as e:
                log.warning("Failed to load RF model: %s — using heuristic", e)
        else:
            log.info("No trained model found at %s — using heuristic scorer", MODEL_PATH)
        return cls(model=None)

    def predict(self, features: List[float]) -> float:
        """
        features: [banner_score, timing_score, filesystem_score, protocol_depth_score]
        Returns: honeypot_confidence in [0.0, 1.0]
        """
        x = np.array(features, dtype=float).reshape(1, -1)
        # Replace NaN with 0
        x = np.nan_to_num(x, nan=0.0)

        if self._model is not None:
            try:
                proba = self._model.predict_proba(x)[0]
                # Class 1 = honeypot
                classes = list(self._model.classes_)
                idx = classes.index(1) if 1 in classes else -1
                return float(proba[idx]) if idx >= 0 else float(proba[1])
            except Exception as e:
                log.warning("RF predict failed: %s — falling back to heuristic", e)

        return self._heuristic(x[0])

    def _heuristic(self, features: np.ndarray) -> float:
        """Weighted linear combination — used before enough training data exists."""
        weights = np.array(HEURISTIC_WEIGHTS)
        score = float(np.dot(features[:len(weights)], weights))
        return min(1.0, max(0.0, score))

    @classmethod
    def retrain(cls, X: List[List[float]], y: List[int]) -> "FingerprintClassifier":
        """
        Retrain on accumulated labeled examples.
        X: list of [banner, timing, fs, proto] feature vectors
        y: list of 0 (real) or 1 (honeypot) labels
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        import joblib

        if len(X) < 10:
            log.warning("Only %d samples — need at least 10 to retrain", len(X))
            return cls.load()

        Xarr = np.array(X, dtype=float)
        yarr = np.array(y, dtype=int)

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=5,
            min_samples_leaf=2,
            class_weight="balanced",  # handle imbalanced real/honeypot ratio
            random_state=42,
        )
        model.fit(Xarr, yarr)

        # Cross-val for logging
        if len(X) >= 20:
            scores = cross_val_score(model, Xarr, yarr, cv=5, scoring="roc_auc")
            log.info("RF retrained | CV ROC-AUC: %.3f ± %.3f", scores.mean(), scores.std())

        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        log.info("Model saved to %s", MODEL_PATH)

        return cls(model=model)


def seed_synthetic_training_data():
    """
    Seed the model with synthetic examples so it works on first run.
    In production, replace with real labeled data.
    """
    # [banner, timing, filesystem, protocol_depth]
    honeypot_samples = [
        [0.9, 0.8, 0.7, 0.8],
        [1.0, 0.9, 0.8, 0.9],
        [0.8, 0.7, 0.6, 0.7],
        [0.7, 0.8, 0.9, 0.6],
        [0.9, 0.6, 0.7, 0.8],
        [0.8, 0.9, 0.8, 0.7],
        [1.0, 0.7, 0.9, 0.9],
        [0.7, 0.6, 0.8, 0.8],
    ]
    real_samples = [
        [0.0, 0.1, 0.1, 0.1],
        [0.0, 0.2, 0.0, 0.0],
        [0.1, 0.3, 0.1, 0.2],
        [0.0, 0.1, 0.2, 0.1],
        [0.1, 0.2, 0.1, 0.0],
        [0.0, 0.1, 0.0, 0.1],
        [0.1, 0.3, 0.2, 0.1],
        [0.0, 0.2, 0.1, 0.0],
    ]

    X = honeypot_samples + real_samples
    y = [1] * len(honeypot_samples) + [0] * len(real_samples)

    log.info("Seeding RF model with %d synthetic samples", len(X))
    FingerprintClassifier.retrain(X, y)