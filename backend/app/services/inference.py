import joblib
import numpy as np
import os
from typing import Dict, Any

class InferenceService:
    def __init__(self, model_dir: str):
        self.model_dir = model_dir
        self.labels = ['urgency', 'authority', 'fear', 'impersonation']
        self._load_models()

    def _load_models(self):
        v_path = os.path.join(self.model_dir, 'vectorizer_baseline.joblib')
        m_path = os.path.join(self.model_dir, 'model_baseline.joblib')
        try:
            self.vectorizer = joblib.load(v_path)
            self.clf = joblib.load(m_path)
            self.feature_names = self.vectorizer.get_feature_names_out()
        except Exception as e:
            raise RuntimeError(f"Failed to load models: {e}")

    def analyze_text(self, text: str) -> Dict[str, Any]:
        try:
            X_vec = self.vectorizer.transform([text])
            probs_raw = self.clf.predict_proba(X_vec)
            
            # Handle list vs array return (different sklearn/wrapper behaviors)
            if isinstance(probs_raw, list):
                # multi-output format: list of [n_samples, 2] arrays
                # we want the positive class (column 1) for each label
                probs = [float(p[0][1]) for p in probs_raw]
            else:
                # one-vs-rest format: single [n_samples, n_classes] array
                probs = probs_raw[0]
            
            detections = {}
            for i, label in enumerate(self.labels):
                prob = float(probs[i])
                top_features = []
                
                try:
                    if prob > 0.1 and hasattr(self.clf, 'estimators_'):
                        estimator = self.clf.estimators_[i]
                        # Support both coef_ and other attribute names
                        if hasattr(estimator, 'coef_'):
                            coef = estimator.coef_[0]
                            feature_indices = X_vec.indices
                            contrib = []
                            for idx in feature_indices:
                                if idx < len(self.feature_names):
                                    contrib.append((self.feature_names[idx], float(coef[idx])))
                            contrib.sort(key=lambda x: x[1], reverse=True)
                            top_features = [{"word": word, "weight": weight} for word, weight in contrib[:3] if weight > 0]
                except Exception as inner_e:
                    print(f"Error extracting features for {label}: {inner_e}")
                
                detections[label] = {"probability": prob, "top_features": top_features}
                
            return {
                "max_risk_score": float(np.max(probs)),
                "detections": detections
            }
        except Exception as e:
            print(f"Inference Error: {e}")
            raise RuntimeError(f"Analysis failed: {str(e)}")

inference_service = None

def get_inference_service():
    global inference_service
    if inference_service is None:
        # Reach the root directory D:\coding_files\DTLshit
        # current file is in D:\coding_files\DTLshit\backend\app\services\inference.py
        current_dir = os.path.dirname(os.path.abspath(__file__))
        backend_dir = os.path.dirname(os.path.dirname(current_dir))
        root_dir = os.path.dirname(backend_dir)
        model_path = os.path.join(root_dir, 'models')
        print(f"[PhishTrace] Initializing InferenceService with path: {model_path}")
        inference_service = InferenceService(model_path)
    return inference_service
