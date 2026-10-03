"""Character-level URL classification model and sequence encoding helpers."""

from __future__ import annotations

from typing import Mapping, Sequence

import numpy as np
import torch
from torch import nn


PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"


def build_character_vocabulary(urls: Sequence[str]) -> dict[str, int]:
    """Build a deterministic vocabulary from training URLs only."""
    characters = sorted({character for url in urls for character in str(url)})
    return {PAD_TOKEN: 0, UNK_TOKEN: 1, **{char: i + 2 for i, char in enumerate(characters)}}


def encode_urls(urls: Sequence[str], char_to_index: Mapping[str, int], max_length: int) -> np.ndarray:
    """Encode URLs with right padding and truncation into compact integer arrays."""
    if max_length < 1:
        raise ValueError("max_length must be positive")
    if len(char_to_index) > 256:
        dtype = np.uint16
    else:
        dtype = np.uint8
    encoded = np.zeros((len(urls), max_length), dtype=dtype)
    unknown_index = char_to_index[UNK_TOKEN]
    for row, url in enumerate(urls):
        for column, character in enumerate(str(url)[:max_length]):
            encoded[row, column] = char_to_index.get(character, unknown_index)
    return encoded


class URLCharCNNBiLSTM(nn.Module):
    """Compact CNN then bidirectional LSTM over character sequences."""

    def __init__(
        self,
        vocab_size: int,
        num_classes: int,
        embedding_dim: int = 32,
        cnn_channels: int = 64,
        lstm_hidden: int = 64,
        dropout: float = 0.35,
    ) -> None:
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.convolution = nn.Sequential(
            nn.Conv1d(embedding_dim, cnn_channels, kernel_size=5, padding=2),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2, stride=2),
            nn.Conv1d(cnn_channels, cnn_channels, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2, stride=2),
        )
        self.bilstm = nn.LSTM(
            input_size=cnn_channels,
            hidden_size=lstm_hidden,
            batch_first=True,
            bidirectional=True,
        )
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(lstm_hidden * 2, num_classes),
        )

    def forward(self, token_ids: torch.Tensor) -> torch.Tensor:
        embedded = self.embedding(token_ids).transpose(1, 2)
        features = self.convolution(embedded).transpose(1, 2)
        sequence, _ = self.bilstm(features)
        pooled = sequence.mean(dim=1)
        return self.classifier(pooled)
