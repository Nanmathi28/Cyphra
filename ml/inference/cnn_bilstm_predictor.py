"""Independent single-URL inference for the saved character CNN-BiLSTM."""

from __future__ import annotations

import json
from pathlib import Path

import torch

from ml.models.url_cnn_bilstm import URLCharCNNBiLSTM, encode_urls


ROOT = Path(__file__).resolve().parents[2]


class CNNBiLSTMURLPredictor:
    def __init__(self, model_path=None, vocabulary_path=None, metadata_path=None, device=None):
        self.model_path = Path(model_path) if model_path else ROOT / "ml/saved_models/cnn_bilstm.pt"
        self.vocabulary_path = Path(vocabulary_path) if vocabulary_path else ROOT / "ml/saved_models/cnn_bilstm_vocab.json"
        self.metadata_path = Path(metadata_path) if metadata_path else ROOT / "ml/saved_models/cnn_bilstm_metadata.json"
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))

        with self.metadata_path.open(encoding="utf-8") as stream:
            self.metadata = json.load(stream)
        with self.vocabulary_path.open(encoding="utf-8") as stream:
            self.vocab = json.load(stream)["char_to_index"]

        payload = torch.load(self.model_path, map_location=self.device, weights_only=True)
        self.label_mapping = payload["label_mapping"]
        self.reverse_label_mapping = payload["reverse_label_mapping"]
        model_config = payload["model_config"]
        self.max_length = int(model_config["max_length"])
        self.model = URLCharCNNBiLSTM(
            vocab_size=len(self.vocab),
            num_classes=len(self.label_mapping),
            embedding_dim=model_config["embedding_dim"],
            cnn_channels=model_config["cnn_channels"],
            lstm_hidden=model_config["lstm_hidden"],
            dropout=model_config["dropout"],
        ).to(self.device)
        self.model.load_state_dict(payload["model_state_dict"])
        self.model.eval()

    def predict(self, url: str) -> dict:
        if not isinstance(url, str) or not url:
            raise ValueError("url must be a non-empty string")
        encoded = encode_urls([url], self.vocab, self.max_length)
        inputs = torch.as_tensor(encoded, device=self.device, dtype=torch.long)
        with torch.inference_mode():
            probabilities = torch.softmax(self.model(inputs), dim=1)[0].cpu().tolist()
        predicted_index = int(max(range(len(probabilities)), key=probabilities.__getitem__))
        probability_map = {
            self.reverse_label_mapping[str(i)]: float(probabilities[i])
            for i in range(len(probabilities))
        }
        return {
            "url": url,
            "prediction": self.reverse_label_mapping[str(predicted_index)],
            "prediction_index": predicted_index,
            "confidence": probability_map[self.reverse_label_mapping[str(predicted_index)]],
            "probabilities": probability_map,
            "model": "cnn_bilstm",
        }
