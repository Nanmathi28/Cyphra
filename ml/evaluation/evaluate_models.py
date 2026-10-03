import pandas as pd
import numpy as np
import json
import time
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import joblib
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)


def load_test_data():
    """Load test data and metadata."""
    splits_dir = Path("ml/data/splits")

    print("Loading test data...")

    test_df = pd.read_csv(splits_dir / "test.csv")

    with open(splits_dir / "label_mapping.json", 'r') as f:
        label_mapping = json.load(f)

    with open(splits_dir / "reverse_label_mapping.json", 'r') as f:
        reverse_label_mapping = json.load(f)

    with open(splits_dir / "feature_names.json", 'r') as f:
        feature_names = json.load(f)

    # Separate features and labels
    X_test = test_df[feature_names].values
    y_test = test_df['label'].map(label_mapping).values

    print(f"Test set: {X_test.shape}")

    return X_test, y_test, label_mapping, reverse_label_mapping, feature_names


def evaluate_model(model_name, X_test, y_test, label_mapping, reverse_label_mapping, feature_names):
    """Evaluate a single model on test set."""
    print(f"\n{'=' * 60}")
    print(f"Evaluating {model_name}")
    print('=' * 60)

    models_dir = Path("ml/saved_models")

    # Load model
    model_path = models_dir / f"{model_name}.joblib"
    print(f"Loading model from: {model_path}")
    model = joblib.load(model_path)

    # Load scaler if exists
    scaler = None
    scaler_path = models_dir / f"{model_name}_scaler.joblib"
    if scaler_path.exists():
        print(f"Loading scaler from: {scaler_path}")
        scaler = joblib.load(scaler_path)
        X_test = scaler.transform(X_test)

    # Load metadata
    metadata_path = models_dir / f"{model_name}_metadata.json"
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)

    # Measure inference time
    start_time = time.time()
    y_pred = model.predict(X_test)
    inference_time = time.time() - start_time
    avg_inference_time = inference_time / len(X_test) * 1000  # in milliseconds

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted')
    recall = recall_score(y_test, y_pred, average='weighted')
    f1 = f1_score(y_test, y_pred, average='weighted')
    macro_f1 = f1_score(y_test, y_pred, average='macro')

    # Per-class metrics
    precision_per_class = precision_score(y_test, y_pred, average=None)
    recall_per_class = recall_score(y_test, y_pred, average=None)
    f1_per_class = f1_score(y_test, y_pred, average=None)

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)

    # Classification report
    target_names = [reverse_label_mapping[str(i)] for i in range(len(label_mapping))]
    class_report = classification_report(y_test, y_pred, target_names=target_names, output_dict=True)

    # Calculate false negatives (important for security)
    # False negative = actual malicious, predicted benign
    benign_idx = label_mapping['benign']
    malicious_classes = [label_mapping['phishing'], label_mapping['malware'], label_mapping['defacement']]

    false_negatives = 0
    total_malicious = 0

    for i in range(len(y_test)):
        if y_test[i] in malicious_classes:
            total_malicious += 1
            if y_pred[i] == benign_idx:
                false_negatives += 1

    false_negative_rate = false_negatives / total_malicious if total_malicious > 0 else 0

    # Print results
    print(f"\nTest Results:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision (weighted): {precision:.4f}")
    print(f"Recall (weighted): {recall:.4f}")
    print(f"F1-score (weighted): {f1:.4f}")
    print(f"F1-score (macro): {macro_f1:.4f}")
    print(f"Inference time: {avg_inference_time:.4f} ms per sample")
    print(f"False negatives: {false_negatives} / {total_malicious} ({false_negative_rate:.4f})")

    print(f"\nPer-class metrics:")
    for i, class_name in enumerate(target_names):
        print(f"  {class_name}:")
        print(f"    Precision: {precision_per_class[i]:.4f}")
        print(f"    Recall: {recall_per_class[i]:.4f}")
        print(f"    F1: {f1_per_class[i]:.4f}")

    # Compile results
    results = {
        'model_name': model_name,
        'accuracy': float(accuracy),
        'precision_weighted': float(precision),
        'recall_weighted': float(recall),
        'f1_weighted': float(f1),
        'f1_macro': float(macro_f1),
        'inference_time_ms': float(avg_inference_time),
        'false_negatives': int(false_negatives),
        'total_malicious': int(total_malicious),
        'false_negative_rate': float(false_negative_rate),
        'per_class_metrics': {
            target_names[i]: {
                'precision': float(precision_per_class[i]),
                'recall': float(recall_per_class[i]),
                'f1': float(f1_per_class[i])
            }
            for i in range(len(target_names))
        },
        'confusion_matrix': cm.tolist(),
        'classification_report': class_report
    }

    return results


def main():
    """Main evaluation pipeline."""
    print("=" * 60)
    print("MODEL EVALUATION ON TEST SET")
    print("=" * 60)

    # Load test data
    X_test, y_test, label_mapping, reverse_label_mapping, feature_names = load_test_data()

    # Models to evaluate
    models_to_evaluate = [
        'logistic_regression',
        'decision_tree',
        'random_forest',
        'xgboost'
    ]

    all_results = {}

    for model_name in models_to_evaluate:
        try:
            results = evaluate_model(model_name, X_test, y_test, label_mapping, reverse_label_mapping, feature_names)
            all_results[model_name] = results
        except Exception as e:
            print(f"Error evaluating {model_name}: {e}")

    # Save all results
    results_dir = Path("ml/reports")
    results_dir.mkdir(exist_ok=True)

    results_path = results_dir / "test_evaluation_results.json"
    with open(results_path, 'w') as f:
        json.dump(all_results, f, indent=2)

    print(f"\n{'=' * 60}")
    print("EVALUATION SUMMARY")
    print('=' * 60)

    # Print comparison table
    print(f"\n{'Model':<20} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Weighted':<12} {'F1-Macro':<10} {'FN Rate':<10}")
    print("-" * 90)

    for model_name, results in all_results.items():
        print(f"{model_name:<20} {results['accuracy']:<10.4f} {results['precision_weighted']:<10.4f} "
              f"{results['recall_weighted']:<10.4f} {results['f1_weighted']:<12.4f} {results['f1_macro']:<10.4f} "
              f"{results['false_negative_rate']:<10.4f}")

    print(f"\nResults saved to: {results_path}")

    return all_results


if __name__ == "__main__":
    main()
