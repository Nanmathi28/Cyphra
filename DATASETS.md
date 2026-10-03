# NIVARA Dataset Documentation

## Overview

NIVARA uses two separate datasets for different stages of the application pipeline:
1. **QR Dataset** — For QR code detection and decoding testing
2. **URL Dataset** — For URL safety classification (ML model training)

These datasets are kept separate because they serve different purposes in the NIVARA architecture.

---

## 1. QR Dataset

### Source File
- **Original:** `qr.zip` (227 MB)
- **Working copy:** `data/qr/`

### Dataset Structure
```
data/qr/
└── QR codes/
    └── benign/
        └── benign/
            ├── benign_0.png
            ├── benign_1.png
            └── ... (48,923 total PNG files)
```

### Characteristics
- **Total samples:** 48,923 QR code images
- **File type:** PNG images
- **Image format:** 1-bit grayscale (black and white)
- **Image dimensions:** 370×370 pixels and 410×410 pixels
- **Labels:** Only one class — "benign"
- **Class distribution:** 100% benign (48,923), 0% malicious (0)
- **File naming:** Sequential numbering (benign_0.png to benign_53182.png)

### Purpose in NIVARA
The QR dataset is used for:
- Testing QR code detection algorithms
- Benchmarking QR scanner performance
- Validating QR decoding functionality
- Testing the QR scanning pipeline

### Known Limitations
- **No malicious samples:** The dataset contains only benign QR codes
- **Cannot train safety classifier:** Without malicious examples, this dataset cannot train a QR safety classification model
- **Single class:** Only provides negative (benign) examples

### Future Use
If malicious QR samples are obtained, they would need to be combined with this dataset to create a binary classification dataset for QR code safety detection.

---

## 2. URL Dataset

### Source File
- **Original:** `url.zip` (17.7 MB)
- **Working copy:** `data/url/malicious_phish.csv`
- **Cleaned version:** `ml/data/url_dataset_cleaned.csv`

### Dataset Structure
Single CSV file with two columns:
- `url` (string) — The URL to classify
- `type` (string) — The label (benign, phishing, malware, defacement)

### Original Dataset Characteristics
- **Total samples:** 651,191 rows
- **Columns:** 2 columns (`url`, `type`)
- **Labels/classes:** 4 classes
  - benign: 428,103 (65.7%)
  - defacement: 96,457 (14.8%)
  - phishing: 94,111 (14.5%)
  - malware: 32,520 (5.0%)
- **Missing values:** None
- **Duplicate URLs:** 10,066 (1.5%)

### Data Cleaning Performed
1. **Duplicate removal:** Removed 10,066 duplicate URLs (kept first occurrence)
2. **Validation:** Confirmed no missing values in either column
3. **Data type validation:** Confirmed both columns are strings

### Cleaned Dataset Characteristics
- **Total samples:** 641,125 rows
- **Rows removed:** 10,066
- **Class distribution after cleaning:**
  - benign: 428,080 (66.77%)
  - defacement: 95,308 (14.87%)
  - phishing: 94,092 (14.68%)
  - malware: 23,645 (3.69%)

### URL Characteristics (from EDA)
- **URL length statistics:**
  - Mean: 59.76 characters
  - Median: 47 characters
  - Min: 1 character
  - Max: 2,175 characters
  - Std dev: 44.89 characters

- **URL characteristics:**
  - Has http://: 162,317 (25.32%)
  - Has https://: 15,637 (2.44%)
  - Has www.: 122,418 (19.09%)
  - Has IP address: 12,488 (1.95%)
  - Unique domains: 197,295

- **URL length by class:**
  - phishing: Mean 45.85, Median 35
  - benign: Mean 57.68, Median 46
  - defacement: Mean 86.13, Median 81
  - malware: Mean 46.61, Median 37

### Purpose in NIVARA
The URL dataset is used for:
- Training the ML model for URL safety classification
- Validating the threat detection pipeline
- Providing the core threat detection capability

### Known Limitations
- **Class imbalance:** Benign class is majority (66.77%), but imbalance is manageable
- **Age:** Dataset from 2021 — may not reflect recent attack patterns
- **No real-time data:** Static dataset, not updated with new threats

---

## 3. Why Datasets Are Kept Separate

The QR and URL datasets represent different stages of the NIVARA pipeline and should not be combined:

### Different Data Types
- QR dataset: Images (PNG)
- URL dataset: Text (CSV)

### Different Purposes
- QR dataset: Input stage (QR detection/decoding)
- URL dataset: Analysis stage (URL safety classification)

### No Direct Mapping
- There is no mapping between QR images and URLs in the datasets
- QR codes may contain URLs, but the datasets are independent

### Pipeline Architecture
```
User scans QR code (using QR scanner tested on QR dataset)
        ↓
QR code is decoded to extract content
        ↓
If content is a URL → URL is extracted
        ↓
URL is analyzed by ML model (trained on URL dataset)
        ↓
Risk assessment is returned to user
```

---

## 4. Data Leakage Prevention

### URL Dataset
- **Duplicates removed:** 10,066 duplicate URLs removed to prevent same URL appearing in train/validation/test splits
- **Stratified split recommended:** Maintain class distribution across splits
- **No overlap:** Ensure no URL appears in more than one split

### QR Dataset
- **Sequential naming:** Files are numbered sequentially — requires random shuffling before any split
- **No duplicates apparent:** Sequential naming suggests no duplicates
- **Single class:** Cannot train classifier anyway

---

## 5. Files Generated

### Data Cleaning
- `ml/data/url_dataset_cleaned.csv` — Cleaned URL dataset (duplicates removed)
- `ml/data/cleaning_report.txt` — Detailed cleaning report

### Exploratory Data Analysis
- `ml/data/eda_report.txt` — Detailed EDA report with statistics

### Original Files (Preserved)
- `qr.zip` — Original QR dataset (unchanged)
- `url.zip` — Original URL dataset (unchanged)
- `data/qr/` — Extracted QR dataset working copy
- `data/url/malicious_phish.csv` — Extracted URL dataset working copy

---

## 6. Next Steps

### For URL Dataset
1. Design feature extraction pipeline based on EDA findings
2. Perform stratified train/validation/test split (70/15/15)
3. Train and evaluate ML models (Logistic Regression, Random Forest, etc.)
4. Select best model based on evaluation metrics
5. Save trained model for deployment

### For QR Dataset
1. Use for testing QR decoding libraries (pyzbar)
2. Benchmark QR scanner performance
3. If malicious QR samples are obtained later, combine for binary classification

---

## 7. References

- URL dataset cleaning script: `ml/data/clean_url_dataset.py`
- URL dataset EDA script: `ml/data/eda_url_dataset.py`
- Cleaning report: `ml/data/cleaning_report.txt`
- EDA report: `ml/data/eda_report.txt`
