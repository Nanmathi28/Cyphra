"""
QR Tampering Detection Pipeline

This module provides the structure for QR image tampering detection using EfficientNetB0.

STATUS: NOT TRAINED - Dataset Limitation

The current QR dataset (data/qr/) contains only benign QR code images (48,923 samples).
No tampered/manipulated QR code samples are available.

Therefore, the tampering detection model cannot be trained at this time.

Required dataset structure for training:
- data/qr/genuine/ - Authentic QR code images
- data/qr/tampered/ - Manipulated/tampered QR code images

When such a dataset becomes available, the following pipeline can be used:
"""

import torch
import torch.nn as nn
import torchvision.models as models
from torchvision import transforms
from PIL import Image
from pathlib import Path
import json
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)


class QRTamperingDetector(nn.Module):
    """
    QR Tampering Detection Model using EfficientNetB0.

    Architecture:
    - EfficientNetB0 (pretrained on ImageNet)
    - Custom classifier head (binary: genuine vs tampered)
    """

    def __init__(self, num_classes=2):
        super(QRTamperingDetector, self).__init__()

        # Load pretrained EfficientNetB0
        self.efficientnet = models.efficientnet_b0(pretrained=True)

        # Modify classifier head
        num_features = self.efficientnet.classifier[1].in_features
        self.efficientnet.classifier = nn.Sequential(
            nn.Dropout(p=0.2, inplace=True),
            nn.Linear(num_features, num_classes)
        )

    def forward(self, x):
        return self.efficientnet(x)


class QRTamperingPipeline:
    """
    Pipeline for QR tampering detection.
    """

    def __init__(self, model_path=None):
        """
        Initialize the pipeline.

        Args:
            model_path: Path to trained model (if available)
        """
        self.model = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
        ])
        self.label_mapping = {0: 'genuine', 1: 'tampered'}

        if model_path and Path(model_path).exists():
            self.load_model(model_path)

    def load_model(self, model_path):
        """Load a trained model."""
        self.model = QRTamperingDetector(num_classes=2)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.to(self.device)
        self.model.eval()
        print(f"Model loaded from: {model_path}")

    def predict(self, image_path):
        """
        Predict if a QR image is genuine or tampered.

        Args:
            image_path: Path to QR image

        Returns:
            Dictionary with prediction results
        """
        if self.model is None:
            raise ValueError("Model not loaded. Train and save a model first.")

        # Load and preprocess image
        image = Image.open(image_path).convert('RGB')
        image_tensor = self.transform(image).unsqueeze(0).to(self.device)

        # Predict
        with torch.no_grad():
            outputs = self.model(image_tensor)
            probabilities = torch.softmax(outputs, dim=1)
            prediction = torch.argmax(probabilities, dim=1).item()

        result = {
            'image_path': str(image_path),
            'prediction': self.label_mapping[prediction],
            'prediction_index': prediction,
            'confidence': float(probabilities[0][prediction]),
            'probabilities': {
                self.label_mapping[i]: float(probabilities[0][i])
                for i in range(len(self.label_mapping))
            }
        }

        return result


def check_dataset_status():
    """Check the status of the QR dataset for tampering detection."""
    qr_data_path = Path("data/qr/QR codes")

    print("=" * 60)
    print("QR TAMPERING DETECTION - DATASET STATUS")
    print("=" * 60)

    print(f"\nQR dataset path: {qr_data_path}")
    print(f"Dataset exists: {qr_data_path.exists()}")

    if qr_data_path.exists():
        subdirs = [d for d in qr_data_path.iterdir() if d.is_dir()]
        print(f"\nSubdirectories found: {[d.name for d in subdirs]}")

        for subdir in subdirs:
            files = list(subdir.rglob('*.png'))
            print(f"  {subdir.name}: {len(files)} PNG files")

        # Check for required classes
        has_genuine = any('genuine' in d.name.lower() for d in subdirs)
        has_tampered = any('tampered' in d.name.lower() for d in subdirs)

        print(f"\nDataset suitable for tampering detection:")
        print(f"  Has genuine class: {has_genuine}")
        print(f"  Has tampered class: {has_tampered}")

        if not (has_genuine and has_tampered):
            print(f"\nWARNING: Dataset does not contain both genuine and tampered classes.")
            print(f"Tampering detection model cannot be trained with current dataset.")
            print(f"\nCurrent dataset appears to contain only benign QR codes.")
            print(f"To train tampering detection, a labeled dataset with both classes is required.")

    return has_genuine and has_tampered if qr_data_path.exists() else False


if __name__ == "__main__":
    # Check dataset status
    can_train = check_dataset_status()

    if not can_train:
        print(f"\n{'=' * 60}")
        print("QR TAMPERING DETECTION STATUS: NOT TRAINED")
        print('=' * 60)
        print("\nReason: Current QR dataset contains only benign samples.")
        print("Action: Obtain labeled dataset with genuine and tampered QR codes.")
        print("\nPipeline structure is ready for future training when data is available.")
