| Model | Accuracy | Precision (weighted) | Recall (weighted) | Macro F1 | Weighted F1 | Inference ms/sample | False negatives / malicious | FN rate | Score |
|---|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.9097 | 0.9057 | 0.9097 | 0.8564 | 0.9043 | 0.000213 | 5,334 / 31,957 | 16.6912% | 0.8647 |
| Decision Tree | 0.9483 | 0.9518 | 0.9483 | 0.9262 | 0.9495 | 0.000458 | 980 / 31,957 | 3.0666% | 0.9514 |
| Random Forest | 0.9668 | 0.9671 | 0.9668 | 0.9537 | 0.9668 | 0.006172 | 1,099 / 31,957 | 3.4390% | 0.9630 |
| XGBoost | 0.9608 | 0.9602 | 0.9608 | 0.9371 | 0.9599 | 0.002320 | 2,188 / 31,957 | 6.8467% | 0.9430 |
| Character CNN + BiLSTM | 0.9719 | 0.9732 | 0.9719 | 0.9615 | 0.9723 | 14.003175 | 536 / 31,957 | 1.6773% | 0.9739 |

Selected by the documented security-first score: **Character CNN + BiLSTM**.
Inference measurements are shown for reference and are not included in the score because the classical and PyTorch timing methods differ.
