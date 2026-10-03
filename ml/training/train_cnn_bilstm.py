"""Train and evaluate a character-level URL CNN-BiLSTM on saved Phase 2 splits."""

from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.models.url_cnn_bilstm import URLCharCNNBiLSTM, build_character_vocabulary, encode_urls


SPLITS = ROOT / "ml" / "data" / "splits"
MODELS = ROOT / "ml" / "saved_models"
REPORTS = ROOT / "ml" / "reports"
RESULTS_PATH = REPORTS / "test_evaluation_results.json"
VOCAB_PATH = MODELS / "cnn_bilstm_vocab.json"
CHECKPOINT_PATH = MODELS / "cnn_bilstm_best.pt"
MODEL_PATH = MODELS / "cnn_bilstm.pt"
METADATA_PATH = MODELS / "cnn_bilstm_metadata.json"
EVALUATION_PATH = REPORTS / "cnn_bilstm_evaluation.json"


def _load_aligned_splits():
    """Recover raw URLs using the exact seeded split procedure and verify labels."""
    cleaned_path = ROOT / "ml" / "data" / "url_dataset_cleaned.csv"
    cleaned = pd.read_csv(cleaned_path)
    with (SPLITS / "split_metadata.json").open(encoding="utf-8") as stream:
        split_meta = json.load(stream)
    with (SPLITS / "label_mapping.json").open(encoding="utf-8") as stream:
        label_mapping = json.load(stream)
    with (SPLITS / "reverse_label_mapping.json").open(encoding="utf-8") as stream:
        reverse_label_mapping = json.load(stream)

    if len(cleaned) != split_meta["total_samples"]:
        raise ValueError("Cleaned dataset size does not match saved split metadata")
    y = cleaned["type"].map(label_mapping).to_numpy(dtype=np.int64)
    indices = np.arange(len(cleaned))
    train_val_idx, test_idx = train_test_split(
        indices,
        test_size=split_meta["test_ratio"],
        stratify=y,
        random_state=split_meta["random_seed"],
    )
    train_idx, val_idx = train_test_split(
        train_val_idx,
        test_size=split_meta["val_ratio"] / (split_meta["train_ratio"] + split_meta["val_ratio"]),
        stratify=y[train_val_idx],
        random_state=split_meta["random_seed"],
    )

    partitions = {}
    for name, idx in (("train", train_idx), ("val", val_idx), ("test", test_idx)):
        saved = pd.read_csv(SPLITS / f"{name}.csv")
        labels = y[idx]
        saved_labels = saved["label"].map(label_mapping).to_numpy(dtype=np.int64)
        if len(saved) != len(idx) or not np.array_equal(labels, saved_labels):
            raise ValueError(f"Recovered {name} rows do not match the saved Phase 2 split")
        partitions[name] = {
            "urls": cleaned.iloc[idx]["url"].astype(str).to_numpy(),
            "labels": labels,
            "indices": idx,
        }

    # The cleaned CSV has six duplicate URLs with conflicting labels. Keep the
    # fixed test split intact, but remove any such URL from train/validation so
    # neither the same string nor a contradictory label can cross those sets.
    ambiguous_urls = set(
        cleaned.groupby("url")["type"].nunique().loc[lambda counts: counts > 1].index.astype(str)
    )
    excluded = {}
    for name in ("train", "val"):
        keep = np.array([url not in ambiguous_urls for url in partitions[name]["urls"]])
        excluded[name] = int((~keep).sum())
        partitions[name]["urls"] = partitions[name]["urls"][keep]
        partitions[name]["labels"] = partitions[name]["labels"][keep]

    train_urls, val_urls, test_urls = (partitions[name]["urls"] for name in ("train", "val", "test"))
    if set(train_urls) & set(val_urls) or set(train_urls) & set(test_urls) or set(val_urls) & set(test_urls):
        raise ValueError("Exact URL overlap remains across character-model splits")

    return partitions, label_mapping, reverse_label_mapping, split_meta, excluded, len(ambiguous_urls)


def _length_statistics(urls):
    lengths = pd.Series(urls).str.len()
    return {
        "p50": float(lengths.quantile(0.50)),
        "p90": float(lengths.quantile(0.90)),
        "p95": float(lengths.quantile(0.95)),
        "p97": float(lengths.quantile(0.97)),
        "p99": float(lengths.quantile(0.99)),
        "max": int(lengths.max()),
    }


def _predict(model, data_loader, device):
    model.eval()
    predictions = []
    with torch.inference_mode():
        for inputs, _ in data_loader:
            logits = model(inputs.to(device, dtype=torch.long))
            predictions.append(logits.argmax(dim=1).cpu().numpy())
    return np.concatenate(predictions)


def _metrics(y_true, y_pred, label_mapping, reverse_label_mapping, inference_ms=None):
    label_ids = list(range(len(label_mapping)))
    names = [reverse_label_mapping[str(i)] for i in label_ids]
    matrix = confusion_matrix(y_true, y_pred, labels=label_ids)
    benign_id = label_mapping["benign"]
    malicious_ids = [value for name, value in label_mapping.items() if name != "benign"]
    actual_malicious = np.isin(y_true, malicious_ids)
    false_negatives = int(np.sum(actual_malicious & (y_pred == benign_id)))
    total_malicious = int(actual_malicious.sum())
    precision_each = precision_score(y_true, y_pred, labels=label_ids, average=None, zero_division=0)
    recall_each = recall_score(y_true, y_pred, labels=label_ids, average=None, zero_division=0)
    f1_each = f1_score(y_true, y_pred, labels=label_ids, average=None, zero_division=0)
    return {
        "model_name": "cnn_bilstm",
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_weighted": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "inference_time_ms": inference_ms,
        "false_negatives": false_negatives,
        "total_malicious": total_malicious,
        "false_negative_rate": float(false_negatives / total_malicious) if total_malicious else 0.0,
        "per_class_metrics": {
            name: {
                "precision": float(precision_each[i]),
                "recall": float(recall_each[i]),
                "f1": float(f1_each[i]),
            }
            for i, name in enumerate(names)
        },
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_labels": names,
        "classification_report": classification_report(
            y_true, y_pred, labels=label_ids, target_names=names, output_dict=True, zero_division=0
        ),
    }


def _single_inference_ms(model, device, vocab, max_length, urls):
    # Measure repeated batch-size-one calls after warm-up; report mean per call.
    batch = torch.as_tensor(encode_urls(urls[:1], vocab, max_length), device=device, dtype=torch.long)
    model.eval()
    with torch.inference_mode():
        for _ in range(10):
            model(batch)
        start = time.perf_counter()
        for _ in range(100):
            model(batch)
        if device.type == "cuda":
            torch.cuda.synchronize()
    return (time.perf_counter() - start) * 1000.0 / 100


def train_cnn_bilstm():
    seed = 42
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.set_num_threads(min(8, torch.get_num_threads()))

    config = {
        "seed": seed,
        "embedding_dim": 32,
        "cnn_channels": 64,
        "lstm_hidden": 64,
        "dropout": 0.35,
        "batch_size": 512,
        "learning_rate": 0.001,
        "max_epochs": 8,
        "early_stopping_patience": 3,
        "optimizer": "Adam",
        "loss": "class-weighted CrossEntropyLoss (balanced weights)",
        "max_length_percentile": 0.97,
        "num_workers": 0,
    }
    MODELS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    print("Loading and verifying the existing Phase 2 splits...")
    partitions, label_mapping, reverse_label_mapping, split_meta, excluded, ambiguous_count = _load_aligned_splits()
    train_urls = partitions["train"]["urls"].tolist()
    val_urls = partitions["val"]["urls"].tolist()
    test_urls = partitions["test"]["urls"].tolist()
    y_train = partitions["train"]["labels"]
    y_val = partitions["val"]["labels"]
    y_test = partitions["test"]["labels"]

    length_stats = _length_statistics(train_urls)
    max_length = int(pd.Series(train_urls).str.len().quantile(config["max_length_percentile"], interpolation="higher"))
    config["max_length"] = max_length
    config["train_url_length_statistics"] = length_stats
    config["train_urls_truncated"] = int((pd.Series(train_urls).str.len() > max_length).sum())
    config["val_urls_truncated"] = int((pd.Series(val_urls).str.len() > max_length).sum())
    config["test_urls_truncated"] = int((pd.Series(test_urls).str.len() > max_length).sum())

    print(f"Train-only URL lengths: p50={length_stats['p50']:.0f}, p95={length_stats['p95']:.0f}, p97={length_stats['p97']:.0f}, p99={length_stats['p99']:.0f}")
    print(f"Selected max sequence length: {max_length}; train examples truncated: {config['train_urls_truncated']}")
    print(f"Effective split sizes: train={len(train_urls)}, validation={len(val_urls)}, test={len(test_urls)}")
    print(f"Excluded conflicting-label URLs from train/validation: {ambiguous_count} URL strings; rows={excluded}")

    vocab = build_character_vocabulary(train_urls)
    with VOCAB_PATH.open("w", encoding="utf-8") as stream:
        json.dump({"char_to_index": vocab, "pad_token": "<PAD>", "unknown_token": "<UNK>"}, stream, ensure_ascii=True, indent=2)
    print(f"Training vocabulary size: {len(vocab)}")

    encoded = {
        name: torch.from_numpy(encode_urls(partitions[name]["urls"].tolist(), vocab, max_length))
        for name in ("train", "val", "test")
    }
    labels = {name: torch.from_numpy(partitions[name]["labels"].astype(np.int64)) for name in partitions}
    loaders = {
        "train": DataLoader(TensorDataset(encoded["train"], labels["train"]), batch_size=config["batch_size"], shuffle=True),
        "val": DataLoader(TensorDataset(encoded["val"], labels["val"]), batch_size=config["batch_size"], shuffle=False),
        "test": DataLoader(TensorDataset(encoded["test"], labels["test"]), batch_size=config["batch_size"], shuffle=False),
    }

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Training device: {device}")
    class_counts = np.bincount(y_train, minlength=len(label_mapping))
    class_weights = len(y_train) / (len(class_counts) * class_counts.astype(np.float64))
    class_weights_tensor = torch.tensor(class_weights, dtype=torch.float32, device=device)
    model = URLCharCNNBiLSTM(
        vocab_size=len(vocab),
        num_classes=len(label_mapping),
        embedding_dim=config["embedding_dim"],
        cnn_channels=config["cnn_channels"],
        lstm_hidden=config["lstm_hidden"],
        dropout=config["dropout"],
    ).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights_tensor)
    optimizer = torch.optim.Adam(model.parameters(), lr=config["learning_rate"])

    best_macro_f1 = -1.0
    best_epoch = 0
    epochs_without_improvement = 0
    epoch_records = []
    training_start = time.perf_counter()
    training_seconds = 0.0

    for epoch in range(1, config["max_epochs"] + 1):
        epoch_start = time.perf_counter()
        model.train()
        loss_sum = 0.0
        correct = 0
        seen = 0
        for batch_number, (batch_x, batch_y) in enumerate(loaders["train"], start=1):
            batch_x = batch_x.to(device=device, dtype=torch.long)
            batch_y = batch_y.to(device=device, dtype=torch.long)
            optimizer.zero_grad(set_to_none=True)
            logits = model(batch_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            size = batch_y.size(0)
            loss_sum += loss.item() * size
            correct += int((logits.argmax(dim=1) == batch_y).sum().item())
            seen += size
            if batch_number % 200 == 0:
                elapsed = time.perf_counter() - epoch_start
                print(f"Epoch {epoch}/{config['max_epochs']} batch {batch_number}/{len(loaders['train'])}; loss={loss.item():.4f}; elapsed={elapsed / 60:.1f} min")

        train_seconds = time.perf_counter() - epoch_start
        training_seconds += train_seconds
        val_pred = _predict(model, loaders["val"], device)
        val_macro = float(f1_score(y_val, val_pred, average="macro", zero_division=0))
        val_accuracy = float(accuracy_score(y_val, val_pred))
        record = {
            "epoch": epoch,
            "train_loss": loss_sum / seen,
            "train_accuracy": correct / seen,
            "validation_accuracy": val_accuracy,
            "validation_macro_f1": val_macro,
            "epoch_seconds": train_seconds,
        }
        epoch_records.append(record)
        print(f"Epoch {epoch}: train_loss={record['train_loss']:.4f}, train_accuracy={record['train_accuracy']:.4f}, val_accuracy={val_accuracy:.4f}, val_macro_f1={val_macro:.4f}, train_minutes={train_seconds / 60:.1f}")

        if val_macro > best_macro_f1:
            best_macro_f1 = val_macro
            best_epoch = epoch
            epochs_without_improvement = 0
            torch.save({"model_state_dict": model.state_dict(), "model_config": config}, CHECKPOINT_PATH)
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= config["early_stopping_patience"]:
                print("Early stopping: validation macro F1 did not improve.")
                break

    wall_training_seconds = time.perf_counter() - training_start
    checkpoint = torch.load(CHECKPOINT_PATH, map_location=device, weights_only=True)
    model.load_state_dict(checkpoint["model_state_dict"])

    # The test set is accessed only after training, validation checkpoint
    # selection, and early stopping have completed.
    test_pred = _predict(model, loaders["test"], device)
    inference_ms = _single_inference_ms(model, device, vocab, max_length, [test_urls[0]])
    evaluation = _metrics(y_test, test_pred, label_mapping, reverse_label_mapping, inference_ms)

    model_payload = {
        "model_state_dict": model.state_dict(),
        "model_config": {key: config[key] for key in ("embedding_dim", "cnn_channels", "lstm_hidden", "dropout", "max_length")},
        "label_mapping": label_mapping,
        "reverse_label_mapping": reverse_label_mapping,
        "vocab_size": len(vocab),
    }
    torch.save(model_payload, MODEL_PATH)

    metadata = {
        "model_name": "cnn_bilstm",
        "architecture": "Character Embedding -> Conv1D/ReLU/MaxPool -> Conv1D/ReLU/MaxPool -> BiLSTM -> Mean Pool -> Dense multiclass logits",
        "model_path": str(MODEL_PATH.relative_to(ROOT)),
        "vocabulary_path": str(VOCAB_PATH.relative_to(ROOT)),
        "training_config": config,
        "label_mapping": label_mapping,
        "reverse_label_mapping": reverse_label_mapping,
        "split_sizes_from_saved_phase2": split_meta,
        "effective_sample_counts": {name: len(partitions[name]["labels"]) for name in partitions},
        "excluded_conflicting_url_rows": excluded,
        "ambiguous_url_strings_in_source": ambiguous_count,
        "best_epoch": best_epoch,
        "best_validation_macro_f1": best_macro_f1,
        "epochs_completed": len(epoch_records),
        "epoch_history": epoch_records,
        "training_seconds": training_seconds,
        "training_wall_seconds": wall_training_seconds,
        "device": str(device),
        "class_counts_train": {reverse_label_mapping[str(i)]: int(class_counts[i]) for i in range(len(class_counts))},
    }
    with METADATA_PATH.open("w", encoding="utf-8") as stream:
        json.dump(metadata, stream, indent=2)
    with EVALUATION_PATH.open("w", encoding="utf-8") as stream:
        json.dump(evaluation, stream, indent=2)

    if RESULTS_PATH.exists():
        with RESULTS_PATH.open(encoding="utf-8") as stream:
            all_results = json.load(stream)
    else:
        all_results = {}
    all_results["cnn_bilstm"] = evaluation
    with RESULTS_PATH.open("w", encoding="utf-8") as stream:
        json.dump(all_results, stream, indent=2)

    print(f"Training time (epochs only): {training_seconds:.2f} seconds")
    print(f"Training wall time: {wall_training_seconds:.2f} seconds")
    print(f"Best epoch: {best_epoch}; validation macro F1: {best_macro_f1:.4f}")
    print("Held-out test metrics:")
    for key in ("accuracy", "precision_weighted", "recall_weighted", "f1_macro", "f1_weighted", "false_negatives", "total_malicious", "false_negative_rate", "inference_time_ms"):
        print(f"  {key}: {evaluation[key]}")
    print(f"Saved model: {MODEL_PATH}")
    print(f"Saved vocabulary: {VOCAB_PATH}")
    print(f"Saved metadata: {METADATA_PATH}")
    print(f"Saved evaluation: {EVALUATION_PATH}")
    return metadata, evaluation


if __name__ == "__main__":
    train_cnn_bilstm()
