import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from ml.features.url_features import URLFeatureExtractor


class URLPredictor:
    """
    URL threat prediction module for single-URL inference.
    Uses the trained Random Forest model.
    """

    def __init__(self, model_name='random_forest'):
        """
        Initialize the predictor with a trained model.

        Args:
            model_name: Name of the trained model to use
        """
        self.model_name = model_name
        self.model = None
        self.scaler = None
        self.feature_extractor = URLFeatureExtractor()
        self.label_mapping = None
        self.reverse_label_mapping = None
        self.feature_names = None

        self._load_model()

    def _load_model(self):
        """Load the trained model and metadata."""
        models_dir = Path("ml/saved_models")

        # Load model
        model_path = models_dir / f"{self.model_name}.joblib"
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")

        self.model = joblib.load(model_path)

        # Load scaler if exists
        scaler_path = models_dir / f"{self.model_name}_scaler.joblib"
        if scaler_path.exists():
            self.scaler = joblib.load(scaler_path)

        # Load metadata
        metadata_path = models_dir / f"{self.model_name}_metadata.json"
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)

        self.label_mapping = metadata['label_mapping']
        self.reverse_label_mapping = metadata['reverse_label_mapping']
        self.feature_names = metadata['feature_names']

        print(f"Model loaded: {self.model_name}")
        print(f"Feature count: {len(self.feature_names)}")
        print(f"Classes: {list(self.label_mapping.keys())}")

    def predict(self, url):
        """
        Predict the threat class of a single URL.

        Args:
            url: URL string to classify

        Returns:
            Dictionary with prediction results
        """
        if not isinstance(url, str):
            url = str(url)

        # Extract features
        features_df = self.feature_extractor.extract_features([url])

        # Ensure feature order matches training
        features_df = features_df[self.feature_names]

        # Scale if needed
        if self.scaler is not None:
            features = self.scaler.transform(features_df.values)
        else:
            features = features_df.values

        # Predict
        prediction_idx = self.model.predict(features)[0]
        prediction_class = self.reverse_label_mapping[str(prediction_idx)]

        # Get probability if available
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(features)[0]
            prob_dict = {
                self.reverse_label_mapping[str(i)]: float(prob)
                for i, prob in enumerate(probabilities)
            }
        else:
            prob_dict = None

        # Build result
        result = {
            'url': url,
            'prediction': prediction_class,
            'prediction_index': int(prediction_idx),
            'confidence': float(max(probabilities)) if prob_dict is not None else None,
            'probabilities': prob_dict,
            'model': self.model_name
        }

        return result

    def predict_batch(self, urls):
        """
        Predict threat classes for multiple URLs.

        Args:
            urls: List of URL strings

        Returns:
            List of prediction result dictionaries
        """
        results = []
        for url in urls:
            result = self.predict(url)
            results.append(result)
        return results


def test_inference():
    """Test the inference module with sample URLs."""
    print("=" * 60)
    print("URL PREDICTOR INFERENCE TEST")
    print("=" * 60)

    # Initialize predictor
    predictor = URLPredictor(model_name='random_forest')

    # Test URLs (not from training set)
    test_urls = [
        "https://www.google.com",
        "http://secure-login-bank.com/account/verify",
        "http://192.168.1.100/admin/login.php",
        "phishing-site.com/login.php",
        "http://example.com/path/to/file.exe",
        "https://legitimate-site.com/normal/page"
    ]

    print(f"\nTesting {len(test_urls)} URLs:\n")

    for url in test_urls:
        result = predictor.predict(url)
        print(f"URL: {url}")
        print(f"Prediction: {result['prediction']}")
        if result['confidence']:
            print(f"Confidence: {result['confidence']:.4f}")
        if result['probabilities']:
            print(f"Probabilities: {result['probabilities']}")
        print()


if __name__ == "__main__":
    test_inference()
