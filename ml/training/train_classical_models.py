import pandas as pd
import numpy as np
import json
import time
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import joblib
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)


def load_splits():
    """Load train, validation, and test splits."""
    splits_dir = Path("ml/data/splits")

    print("Loading splits...")

    train_df = pd.read_csv(splits_dir / "train.csv")
    val_df = pd.read_csv(splits_dir / "val.csv")
    test_df = pd.read_csv(splits_dir / "test.csv")

    with open(splits_dir / "label_mapping.json", 'r') as f:
        label_mapping = json.load(f)

    with open(splits_dir / "reverse_label_mapping.json", 'r') as f:
        reverse_label_mapping = json.load(f)

    with open(splits_dir / "feature_names.json", 'r') as f:
        feature_names = json.load(f)

    # Separate features and labels
    X_train = train_df[feature_names].values
    y_train = train_df['label'].map(label_mapping).values

    X_val = val_df[feature_names].values
    y_val = val_df['label'].map(label_mapping).values

    X_test = test_df[feature_names].values
    y_test = test_df['label'].map(label_mapping).values

    print(f"Train: {X_train.shape}")
    print(f"Validation: {X_val.shape}")
    print(f"Test: {X_test.shape}")

    return X_train, X_val, X_test, y_train, y_val, y_test, label_mapping, reverse_label_mapping, feature_names


def train_logistic_regression(X_train, y_train, X_val, y_val, label_mapping):
    """Train Logistic Regression model."""
    print("\n" + "=" * 60)
    print("Training Logistic Regression")
    print("=" * 60)

    start_time = time.time()

    # Scale features for Logistic Regression
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    # Train model
    model = LogisticRegression(
        max_iter=1000,
        random_state=42,
        n_jobs=-1,
        multi_class='multinomial',
        solver='lbfgs'
    )

    model.fit(X_train_scaled, y_train)

    training_time = time.time() - start_time

    # Evaluate
    y_val_pred = model.predict(X_val_scaled)
    val_accuracy = accuracy_score(y_val, y_val_pred)

    print(f"Training time: {training_time:.2f} seconds")
    print(f"Validation accuracy: {val_accuracy:.4f}")

    return model, scaler, training_time, val_accuracy


def train_decision_tree(X_train, y_train, X_val, y_val, label_mapping):
    """Train Decision Tree model."""
    print("\n" + "=" * 60)
    print("Training Decision Tree")
    print("=" * 60)

    start_time = time.time()

    model = DecisionTreeClassifier(
        random_state=42,
        max_depth=20,
        min_samples_split=10,
        class_weight='balanced'
    )

    model.fit(X_train, y_train)

    training_time = time.time() - start_time

    # Evaluate
    y_val_pred = model.predict(X_val)
    val_accuracy = accuracy_score(y_val, y_val_pred)

    print(f"Training time: {training_time:.2f} seconds")
    print(f"Validation accuracy: {val_accuracy:.4f}")

    return model, None, training_time, val_accuracy


def train_random_forest(X_train, y_train, X_val, y_val, label_mapping):
    """Train Random Forest model."""
    print("\n" + "=" * 60)
    print("Training Random Forest")
    print("=" * 60)

    start_time = time.time()

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        max_depth=20,
        class_weight='balanced'
    )

    model.fit(X_train, y_train)

    training_time = time.time() - start_time

    # Evaluate
    y_val_pred = model.predict(X_val)
    val_accuracy = accuracy_score(y_val, y_val_pred)

    print(f"Training time: {training_time:.2f} seconds")
    print(f"Validation accuracy: {val_accuracy:.4f}")

    return model, None, training_time, val_accuracy


def train_xgboost(X_train, y_train, X_val, y_val, label_mapping):
    """Train XGBoost model."""
    print("\n" + "=" * 60)
    print("Training XGBoost")
    print("=" * 60)

    try:
        import xgboost as xgb
    except ImportError:
        print("XGBoost not installed, skipping...")
        return None, None, 0, 0

    start_time = time.time()

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        n_jobs=-1,
        objective='multi:softprob',
        num_class=len(label_mapping)
    )

    model.fit(X_train, y_train)

    training_time = time.time() - start_time

    # Evaluate
    y_val_pred = model.predict(X_val)
    val_accuracy = accuracy_score(y_val, y_val_pred)

    print(f"Training time: {training_time:.2f} seconds")
    print(f"Validation accuracy: {val_accuracy:.4f}")

    return model, None, training_time, val_accuracy


def save_model(model, scaler, model_name, training_time, val_accuracy, feature_names, label_mapping, reverse_label_mapping):
    """Save model and metadata."""
    models_dir = Path("ml/saved_models")
    models_dir.mkdir(exist_ok=True)

    # Save model
    model_path = models_dir / f"{model_name}.joblib"
    joblib.dump(model, model_path)

    # Save scaler if exists
    scaler_path = None
    if scaler is not None:
        scaler_path = models_dir / f"{model_name}_scaler.joblib"
        joblib.dump(scaler, scaler_path)

    # Save metadata
    metadata = {
        'model_name': model_name,
        'training_time': training_time,
        'val_accuracy': val_accuracy,
        'feature_names': feature_names,
        'label_mapping': label_mapping,
        'reverse_label_mapping': reverse_label_mapping,
        'model_path': str(model_path),
        'scaler_path': str(scaler_path) if scaler_path else None
    }

    metadata_path = models_dir / f"{model_name}_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"Model saved to: {model_path}")
    print(f"Metadata saved to: {metadata_path}")

    return metadata


def main():
    """Main training pipeline."""
    print("=" * 60)
    print("CLASSICAL ML MODEL TRAINING")
    print("=" * 60)

    # Load data
    X_train, X_val, X_test, y_train, y_val, y_test, label_mapping, reverse_label_mapping, feature_names = load_splits()

    results = {}

    # Train Logistic Regression
    try:
        lr_model, lr_scaler, lr_time, lr_acc = train_logistic_regression(X_train, y_train, X_val, y_val, label_mapping)
        lr_metadata = save_model(lr_model, lr_scaler, "logistic_regression", lr_time, lr_acc, feature_names, label_mapping, reverse_label_mapping)
        results['logistic_regression'] = lr_metadata
    except Exception as e:
        print(f"Logistic Regression training failed: {e}")

    # Train Decision Tree
    try:
        dt_model, dt_scaler, dt_time, dt_acc = train_decision_tree(X_train, y_train, X_val, y_val, label_mapping)
        dt_metadata = save_model(dt_model, dt_scaler, "decision_tree", dt_time, dt_acc, feature_names, label_mapping, reverse_label_mapping)
        results['decision_tree'] = dt_metadata
    except Exception as e:
        print(f"Decision Tree training failed: {e}")

    # Train Random Forest
    try:
        rf_model, rf_scaler, rf_time, rf_acc = train_random_forest(X_train, y_train, X_val, y_val, label_mapping)
        rf_metadata = save_model(rf_model, rf_scaler, "random_forest", rf_time, rf_acc, feature_names, label_mapping, reverse_label_mapping)
        results['random_forest'] = rf_metadata
    except Exception as e:
        print(f"Random Forest training failed: {e}")

    # Train XGBoost
    try:
        xgb_model, xgb_scaler, xgb_time, xgb_acc = train_xgboost(X_train, y_train, X_val, y_val, label_mapping)
        if xgb_model is not None:
            xgb_metadata = save_model(xgb_model, xgb_scaler, "xgboost", xgb_time, xgb_acc, feature_names, label_mapping, reverse_label_mapping)
            results['xgboost'] = xgb_metadata
    except Exception as e:
        print(f"XGBoost training failed: {e}")

    # Save training summary
    summary_path = Path("ml/reports/classical_training_summary.json")
    summary_path.parent.mkdir(exist_ok=True)

    with open(summary_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nTraining summary saved to: {summary_path}")

    print("\n" + "=" * 60)
    print("CLASSICAL ML TRAINING COMPLETED")
    print("=" * 60)

    for model_name, metadata in results.items():
        print(f"\n{model_name}:")
        print(f"  Training time: {metadata['training_time']:.2f}s")
        print(f"  Validation accuracy: {metadata['val_accuracy']:.4f}")


if __name__ == "__main__":
    main()
