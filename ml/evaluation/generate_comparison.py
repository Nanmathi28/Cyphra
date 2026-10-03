"""Build the Phase 2 model comparison from already-measured evaluation files."""

import json
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "ml" / "reports"


def generate_comparison_report():
    with (REPORTS / "test_evaluation_results.json").open(encoding="utf-8") as stream:
        results = json.load(stream)
    with (REPORTS / "classical_training_summary.json").open(encoding="utf-8") as stream:
        training_summary = json.load(stream)
    with (ROOT / "ml/saved_models/cnn_bilstm_metadata.json").open(encoding="utf-8") as stream:
        cnn_metadata = json.load(stream)

    required = {"logistic_regression", "decision_tree", "random_forest", "xgboost", "cnn_bilstm"}
    missing = required - results.keys()
    if missing:
        raise ValueError(f"Missing measured model results: {sorted(missing)}")

    # Security-first comparison score: false-negative rate is the largest
    # component, then macro F1, weighted F1, and accuracy. Runtime is reported
    # but excluded from selection because the classical and torch measurements
    # use different timing methods in their existing evaluation pipelines.
    weights = {"security_recall": 0.40, "macro_f1": 0.25, "weighted_f1": 0.20, "accuracy": 0.15}
    scores = {}
    comparison = {}
    model_order = ["logistic_regression", "decision_tree", "random_forest", "xgboost", "cnn_bilstm"]
    for model_name in model_order:
        result = results[model_name]
        score = (
            weights["security_recall"] * (1.0 - result["false_negative_rate"])
            + weights["macro_f1"] * result["f1_macro"]
            + weights["weighted_f1"] * result["f1_weighted"]
            + weights["accuracy"] * result["accuracy"]
        )
        scores[model_name] = score
        train_time = (
            cnn_metadata["training_seconds"]
            if model_name == "cnn_bilstm"
            else training_summary[model_name]["training_time"]
        )
        comparison[model_name] = {
            "accuracy": result["accuracy"],
            "precision_weighted": result["precision_weighted"],
            "recall_weighted": result["recall_weighted"],
            "f1_macro": result["f1_macro"],
            "f1_weighted": result["f1_weighted"],
            "inference_time_ms": result["inference_time_ms"],
            "false_negatives": result["false_negatives"],
            "total_malicious": result["total_malicious"],
            "false_negative_rate": result["false_negative_rate"],
            "selection_score": score,
            "training_time_seconds": train_time,
        }

    selected = max(model_order, key=scores.__getitem__)
    selection = {
        "selected_model": selected,
        "selection_date": date.today().isoformat(),
        "selection_rule": "Highest security-first composite score; false-negative rate (40%), macro F1 (25%), weighted F1 (20%), accuracy (15%). Inference time is reported but excluded because timing methods differ across model families.",
        "score_weights": weights,
        "scores": scores,
        "comparison_table": comparison,
        "test_metrics_used_for_final_comparison": True,
    }
    with (REPORTS / "model_selection.json").open("w", encoding="utf-8") as stream:
        json.dump(selection, stream, indent=2)

    headers = ["Model", "Accuracy", "Precision (weighted)", "Recall (weighted)", "Macro F1", "Weighted F1", "Inference ms/sample", "False negatives / malicious", "FN rate", "Score"]
    rows = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]
    labels = {
        "logistic_regression": "Logistic Regression",
        "decision_tree": "Decision Tree",
        "random_forest": "Random Forest",
        "xgboost": "XGBoost",
        "cnn_bilstm": "Character CNN + BiLSTM",
    }
    for name in model_order:
        item = comparison[name]
        fn = f"{item['false_negatives']:,} / {item['total_malicious']:,}"
        cells = [
            labels[name], f"{item['accuracy']:.4f}", f"{item['precision_weighted']:.4f}",
            f"{item['recall_weighted']:.4f}", f"{item['f1_macro']:.4f}",
            f"{item['f1_weighted']:.4f}", f"{item['inference_time_ms']:.6f}",
            fn, f"{item['false_negative_rate']:.4%}", f"{item['selection_score']:.4f}",
        ]
        rows.append("| " + " | ".join(cells) + " |")
    rows.extend([
        "",
        f"Selected by the documented security-first score: **{labels[selected]}**.",
        "Inference measurements are shown for reference and are not included in the score because the classical and PyTorch timing methods differ.",
    ])
    (REPORTS / "model_comparison.md").write_text("\n".join(rows) + "\n", encoding="utf-8")

    print("Model comparison updated from saved measured results.")
    print(f"Selected model: {selected}")
    print(f"Comparison table: {REPORTS / 'model_comparison.md'}")
    print(f"Selection data: {REPORTS / 'model_selection.json'}")
    return selected, selection


if __name__ == "__main__":
    generate_comparison_report()
