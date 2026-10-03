import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from pathlib import Path
import pickle
import json
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from ml.features.url_features import extract_features_from_dataframe


def create_train_val_test_split():
    """
    Create stratified train/validation/test splits from the cleaned URL dataset.
    Uses a fixed random seed for reproducibility.
    """

    # Configuration
    RANDOM_SEED = 42
    TRAIN_RATIO = 0.70
    VAL_RATIO = 0.15
    TEST_RATIO = 0.15

    # Paths
    cleaned_path = Path("ml/data/url_dataset_cleaned.csv")
    output_dir = Path("ml/data/splits")
    output_dir.mkdir(exist_ok=True)

    print("=" * 60)
    print("TRAIN/VALIDATION/TEST SPLIT")
    print("=" * 60)

    # Load cleaned dataset
    print(f"\nLoading cleaned dataset from: {cleaned_path}")
    df = pd.read_csv(cleaned_path)

    print(f"Total samples: {len(df)}")
    print(f"Class distribution:\n{df['type'].value_counts()}")

    # Extract features
    print("\nExtracting features...")
    features_df, labels_df = extract_features_from_dataframe(df, url_column='url')

    print(f"Features extracted: {features_df.shape[1]} features")
    print(f"Feature names: {features_df.columns.tolist()}")

    # Encode labels
    label_mapping = {label: idx for idx, label in enumerate(sorted(df['type'].unique()))}
    reverse_label_mapping = {idx: label for label, idx in label_mapping.items()}

    print(f"\nLabel mapping: {label_mapping}")

    # Convert labels to numeric
    y = df['type'].map(label_mapping).values
    X = features_df.values

    # First split: train + val vs test
    print(f"\nSplitting data (train+val: {TRAIN_RATIO+VAL_RATIO}, test: {TEST_RATIO})...")
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y,
        test_size=TEST_RATIO,
        stratify=y,
        random_state=RANDOM_SEED
    )

    # Second split: train vs val
    val_ratio_adjusted = VAL_RATIO / (TRAIN_RATIO + VAL_RATIO)
    print(f"Splitting train+val (train: {TRAIN_RATIO}, val: {VAL_RATIO})...")
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val,
        test_size=val_ratio_adjusted,
        stratify=y_train_val,
        random_state=RANDOM_SEED
    )

    # Print split statistics
    print(f"\n=== SPLIT STATISTICS ===")
    print(f"Train: {len(X_train)} samples ({len(X_train)/len(df)*100:.2f}%)")
    print(f"Validation: {len(X_val)} samples ({len(X_val)/len(df)*100:.2f}%)")
    print(f"Test: {len(X_test)} samples ({len(X_test)/len(df)*100:.2f}%)")

    print(f"\nTrain class distribution:")
    train_counts = pd.Series(y_train).map(reverse_label_mapping).value_counts()
    print(train_counts)

    print(f"\nValidation class distribution:")
    val_counts = pd.Series(y_val).map(reverse_label_mapping).value_counts()
    print(val_counts)

    print(f"\nTest class distribution:")
    test_counts = pd.Series(y_test).map(reverse_label_mapping).value_counts()
    print(test_counts)

    # Save splits
    print(f"\nSaving splits to: {output_dir}")

    # Save as CSV with labels
    train_df = pd.DataFrame(X_train, columns=features_df.columns)
    train_df['label'] = pd.Series(y_train).map(reverse_label_mapping)
    train_df.to_csv(output_dir / "train.csv", index=False)

    val_df = pd.DataFrame(X_val, columns=features_df.columns)
    val_df['label'] = pd.Series(y_val).map(reverse_label_mapping)
    val_df.to_csv(output_dir / "val.csv", index=False)

    test_df = pd.DataFrame(X_test, columns=features_df.columns)
    test_df['label'] = pd.Series(y_test).map(reverse_label_mapping)
    test_df.to_csv(output_dir / "test.csv", index=False)

    # Save label mapping
    with open(output_dir / "label_mapping.json", 'w') as f:
        json.dump(label_mapping, f, indent=2)

    with open(output_dir / "reverse_label_mapping.json", 'w') as f:
        json.dump(reverse_label_mapping, f, indent=2)

    # Save feature names
    with open(output_dir / "feature_names.json", 'w') as f:
        json.dump(features_df.columns.tolist(), f, indent=2)

    # Save split metadata
    metadata = {
        'random_seed': RANDOM_SEED,
        'train_ratio': TRAIN_RATIO,
        'val_ratio': VAL_RATIO,
        'test_ratio': TEST_RATIO,
        'total_samples': len(df),
        'train_samples': len(X_train),
        'val_samples': len(X_val),
        'test_samples': len(X_test),
        'n_features': X_train.shape[1],
        'n_classes': len(label_mapping),
        'classes': list(label_mapping.keys()),
        'train_distribution': train_counts.to_dict(),
        'val_distribution': val_counts.to_dict(),
        'test_distribution': test_counts.to_dict()
    }

    with open(output_dir / "split_metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"Train set saved: {output_dir / 'train.csv'}")
    print(f"Validation set saved: {output_dir / 'val.csv'}")
    print(f"Test set saved: {output_dir / 'test.csv'}")
    print(f"Label mapping saved: {output_dir / 'label_mapping.json'}")
    print(f"Feature names saved: {output_dir / 'feature_names.json'}")
    print(f"Metadata saved: {output_dir / 'split_metadata.json'}")

    print(f"\nData split completed successfully")

    return metadata


if __name__ == "__main__":
    create_train_val_test_split()
