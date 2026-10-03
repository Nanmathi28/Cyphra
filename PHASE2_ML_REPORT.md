# CYPHRA Phase 2 ML Report

**Date:** 2026-10-03  
**Status:** URL model experiment completed; QR tampering model remains pending

## Scope and existing work

Phase 2 reuses the cleaned URL data and the saved stratified 70/15/15 train, validation, and test methodology. The four previously trained classical models and their saved artifacts were preserved; their saved test metrics were reused without retraining. The character model consumes raw URL characters and does not use the 42 engineered features as its input.

The existing split CSVs contain engineered features and labels, but not raw URLs or source row indices. The original seeded stratification procedure was therefore replayed against the cleaned dataset to recover each partition's URL rows. The recovered labels matched all three saved split CSVs.

## Character-level CNN + BiLSTM

### Data and preprocessing

- Source: `ml/data/url_dataset_cleaned.csv`; 641,125 rows, four original classes.
- Effective training inputs: **448,779 URLs** (448,787 in saved split before duplicate-label exclusions).
- Effective validation inputs: **96,167 URLs** (96,169 before exclusions).
- Held-out test inputs: **96,169 URLs**, all retained from the saved test split.
- Six URL strings occur under conflicting labels in the source data. Their eight training rows and two validation rows were excluded to avoid contradictory/overlapping examples. The test split was left unchanged. One conflicting URL pair remains in the test set and is noted as a data limitation.
- Vocabulary: **325 entries**, including PAD and UNK; constructed from training URLs only and saved as JSON.
- Maximum sequence length: **160 characters**, the training-only 97th percentile (p95=134, p97=160, p99=235). Right padding uses index 0; unknown characters use index 1; longer URLs are truncated. **13,349 training URLs** exceed 160 characters.

### Architecture and training

Character IDs → 32-dimensional embedding → Conv1D (64 channels, kernel 5), ReLU and max-pooling → Conv1D (64 channels, kernel 3), ReLU and max-pooling → bidirectional LSTM (64 hidden units per direction) → mean sequence pooling → dropout (0.35) → four-class dense output.

Training used weighted cross-entropy with balanced class weights, Adam at learning rate 0.001, batch size 512, seed 42, and a maximum of 8 epochs. Validation macro F1 selected the checkpoint; early-stopping patience was 3 epochs. Training ran on CPU. The best checkpoint was epoch 7, with validation macro F1 **0.9616** and validation accuracy **0.9717**. The configured maximum of 8 epochs was reached.

- Epoch training time: **2,463.05 seconds** (41 min 03 sec).
- Training-loop wall time: **2,583.91 seconds** (43 min 04 sec), including validation passes.

### Held-out test results

Evaluation used the unchanged saved test split (96,169 rows). False negative means an actual malicious class (defacement, malware, or phishing) predicted as benign.

| Metric | Result |
|---|---:|
| Accuracy | 0.9719 |
| Precision, weighted | 0.9732 |
| Recall, weighted | 0.9719 |
| Macro F1 | 0.9615 |
| Weighted F1 | 0.9723 |
| False negatives | 536 / 31,957 malicious URLs |
| False-negative rate | 1.6773% |
| Single-URL inference time | 14.003 ms per URL |

Per-class metrics:

| Class | Precision | Recall | F1 |
|---|---:|---:|---:|
| benign | 0.9915 | 0.9731 | 0.9822 |
| defacement | 0.9864 | 0.9976 | 0.9920 |
| malware | 0.9754 | 0.9484 | 0.9617 |
| phishing | 0.8762 | 0.9464 | 0.9100 |

Confusion matrix (actual rows, predicted columns; order: benign, defacement, malware, phishing):

```text
[[62482,    20,   17, 1693],
 [    2, 14261,    7,   26],
 [    8,     7, 3364,  168],
 [  526,   169,   61,13358]]
```

The classification report is saved in `ml/reports/cnn_bilstm_evaluation.json`.

## Comparison and model selection

The four classical entries below use the existing measured results; no classical model was retrained. False-negative counts use each model's saved evaluation. Inference timings are reported as measured, but use different timing methods across the existing classical evaluation and the CNN single-item benchmark; they are not used in the selection score.

| Model | Accuracy | Precision (weighted) | Recall (weighted) | Macro F1 | Weighted F1 | Inference ms/URL | False negatives / malicious | FN rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.9097 | 0.9057 | 0.9097 | 0.8564 | 0.9043 | 0.000213 | 5,334 / 31,957 | 16.6912% |
| Decision Tree | 0.9483 | 0.9518 | 0.9483 | 0.9262 | 0.9495 | 0.000458 | 980 / 31,957 | 3.0666% |
| Random Forest | 0.9668 | 0.9671 | 0.9668 | 0.9537 | 0.9668 | 0.006172 | 1,099 / 31,957 | 3.4390% |
| XGBoost | 0.9608 | 0.9602 | 0.9608 | 0.9371 | 0.9599 | 0.002320 | 2,188 / 31,957 | 6.8467% |
| Character CNN + BiLSTM | 0.9719 | 0.9732 | 0.9719 | 0.9615 | 0.9723 | 14.003175 | 536 / 31,957 | 1.6773% |

The current selected URL model is **Character CNN + BiLSTM**, based on the saved test comparison and the documented security-first score: 40% lower false-negative rate, 25% macro F1, 20% weighted F1, and 15% accuracy. It scored 0.9739, ahead of Random Forest at 0.9630. This selection prioritizes missed threats; the CNN-BiLSTM has notably higher measured single-URL latency, and latency comparison is limited by different timing procedures.

The comparison table is also saved in `ml/reports/model_comparison.md`; machine-readable metrics and selection are in `ml/reports/test_evaluation_results.json` and `ml/reports/model_selection.json`.

## Saved model and inference verification

- Model: `ml/saved_models/cnn_bilstm.pt`
- Best validation checkpoint: `ml/saved_models/cnn_bilstm_best.pt`
- Vocabulary: `ml/saved_models/cnn_bilstm_vocab.json`
- Configuration, mappings, training history, and metadata: `ml/saved_models/cnn_bilstm_metadata.json`
- Test metrics: `ml/reports/cnn_bilstm_evaluation.json`
- Independent single-URL predictor: `ml/inference/cnn_bilstm_predictor.py`

The saved model was reloaded in a fresh predictor instance and run on five distinct URLs from the held-out test partition that were not present in training. Each returned a predicted class, confidence, and class probabilities summing to 1.0. These are inference checks, not a separate accuracy estimate. Outputs are recorded in `ml/reports/cnn_bilstm_inference_samples.json`.

## Limitations and remaining work

- URL source labels contain six exact URL strings with conflicting classes; ten such rows were excluded from training and validation. The saved test split retains one contradictory duplicate pair, so that pair cannot receive a consistent URL-only prediction for both labels.
- The 160-character sequence length truncates 2.97% of the training URLs; longer inputs lose their suffix during inference as well.
- Phishing has the weakest class F1 (0.9100), and most malicious-to-benign errors are phishing URLs (526 of 536).
- The CNN-BiLSTM CPU latency is higher than the recorded classical timings. Timing methods differ, so production latency should be benchmarked using one shared protocol and target hardware.
- QR tampering detection is **not trained**. EfficientNetB0 training remains pending because the available QR data has no verified genuine-versus-tampered label structure. No tampered labels or synthetic results were created.
- Mobile UI, risk fusion, threat intelligence, redirect analysis, OCR, and final backend integration remain outside this experiment and were not started.
