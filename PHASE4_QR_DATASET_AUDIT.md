# Phase 4 QR Dataset Audit

## 1. Objective

Determine whether the available QR images provide verified ground truth for EfficientNetB0 visual genuine-versus-tampered classification. This was a read-only dataset audit; no model was trained and no labels or data were changed.

## 2. Dataset locations

- Source archive: [`qr.zip`](qr.zip)
- Extracted working copy: [`data/qr/`](data/qr/)
- Existing project notes: [`DATASETS.md`](DATASETS.md), [`PHASE2_ML_REPORT.md`](PHASE2_ML_REPORT.md)

The project notes are stale or inconsistent with the observed files: `DATASETS.md` describes 48,923 benign images and no malicious samples, while both the ZIP and extracted copy currently contain 200,000 images in two candidate folders. The QR section of `ml/training/qr_tampering_pipeline.py` also states the older 48,923 benign-only inventory. Those files were not edited as part of this audit.

## 3. Dataset inventory and folder structure

The archive is 227,358,917 bytes and contains 200,000 members: 200,000 PNGs, 185,581,039 uncompressed bytes, and no CSV, JSON, TXT, documentation, or other non-image metadata files. There are no duplicate ZIP member names. The extracted copy independently contains 200,000 files, all PNG.

One QR-related ZIP was found in the project root: `qr.zip`. The other root ZIP, `url.zip`, is the separate URL dataset archive.

| Candidate folder (not a verified label) | Images | Share | Filename index range |
|---|---:|---:|---:|
| `QR codes/benign/benign/` | 100,000 | 50% | `benign_0.png`–`benign_99999.png` |
| `QR codes/malicious/malicious/` | 100,000 | 50% | `malicious_316254.png`–`malicious_416253.png` |

The folder-count balance is 1:1. It is not evidence that the folders represent the required visual classes.

## 4. Label semantics

No label definition, provenance note, source URL, or license was found in the ZIP or its extracted tree. Therefore, the archive does not establish that “benign” means a genuine visual QR, or that “malicious” means a visually tampered QR. The project’s older `DATASETS.md` claims that malicious QR images are absent, but that claim conflicts with the files present and still does not define visual tampering.

The defensible interpretation is **unknown label semantics**. “Malicious” could refer to the encoded URL’s reputation, visual manipulation, or another dataset-specific rule. Folder names alone cannot resolve this. No verified genuine-versus-tampered ground truth exists in the inspected files.

## 5. Image statistics and quality

All 200,000 archive entries have valid PNG signatures and nonzero dimensions in their IHDR header. This header check is exhaustive; it is not a full pixel decode of every image. OpenCV decoded 9/10 selected samples.

| Statistic | `benign/benign` candidate folder | `malicious/malicious` candidate folder |
|---|---:|---:|
| Dimensions | 370×370: 5,212; 410×410: 94,780; 450×450: 8 | 370×370: 10,371; 410×410: 89,612; 450×450: 16; 490×490: 1 |
| Width/height range | 370–450 / 370–450 | 370–490 / 370–490 |
| Aspect ratio | 1.0 throughout | 1.0 throughout |
| PNG color mode / bit depth | grayscale (`L`), 1-bit | grayscale (`L`), 1-bit |
| Transparency | none indicated by PNG color type | none indicated by PNG color type |
| File size | 708–1,101 bytes; median 940 | 718–1,234 bytes; median 934 |

Input preprocessing for EfficientNetB0 would need grayscale-to-RGB conversion, resizing or padding to a consistent input size, and the model’s normal normalization. The dimension distributions differ somewhat by candidate folder, so a model could learn resolution/rendering cues if these are correlated with the folder name. All images are square, monochrome, and very small files; no JPEG compression applies.

## 6. Duplicate and leakage analysis

- Exact file-content duplicates: **0** SHA-256 duplicate groups across the archive; no duplicate images found between candidate folders.
- Extracted/archive identity: all 6 deterministic extracted samples (first, middle, last in each folder) match the corresponding archive file byte-for-byte. This is a sample comparison, not a full 200,000-file comparison.
- Near-duplicate images were not exhaustively searched.
- Five selected samples per candidate folder were tested for QR decoding; nine of ten yielded URL-bearing indexed text payloads. Payload duplication across all images was not exhaustively tested.
- The dataset has no train/validation/test split folders. A future split must group by decoded payload or source QR before splitting to reduce leakage from repeated URLs or related images.

## 7. Payload and visual observations

OpenCV decoded 4/5 selected samples in the benign candidate folder and 5/5 in the malicious candidate folder. The nine decoded payloads resemble indexed pandas Series text including a URL and trailing `Name: url, dtype: object`. The one undecoded file still has a valid PNG header and looks like a QR code on visual inspection, so it is not treated as corrupted. The decoded benign-folder examples included `www.google.com` and `www.pediaview.com`; malicious-folder examples included `atualizacaodedados.online` and `mdtcs.net`. This sample is consistent with QR images encoding URLs whose destination categories may differ. It does not prove all URLs’ current safety, the labels’ provenance, or the dataset’s complete label rule.

The existing contact sheet shows representative black-and-white QR codes without obvious overlays or visible image manipulation. This is a sample-only visual observation, not an image-level ground-truth label. Evidence favors a distinction in encoded content/reputation over visible tampering, but without source documentation that remains an evidence-based inference rather than a verified definition.

## 8. Data leakage risks

There is no supplied split or metadata for grouping related samples. If this data is later repurposed for URL reputation classification, split by normalized URL/payload (and ideally source/domain) before creating train, validation, and test sets. For a visual tampering classifier, use paired genuine and manipulated variants grouped by their original QR/payload so variants cannot leak across splits. Do not treat the present folder separation as proof of either task’s ground truth.

## 9. Suitability decision

**NOT SUITABLE** for training the intended EfficientNetB0 genuine-versus-tampered QR classifier. There are two balanced candidate folders, but no trustworthy definition that either folder represents visual tampering. Training a tampering model on these folder names would risk teaching destination reputation or rendering artifacts as tampering.

The images could be investigated for a separate QR-encoded URL reputation task after the original label semantics, URL labels, source, and license are verified. That is distinct from the QR visual/tampering classifier and should not replace the existing URL threat model without a separately defined evaluation.

## 10. Recommendation and EfficientNetB0 data requirements

Do not train EfficientNetB0 on this dataset for visual tampering detection. Obtain or curate a documented dataset with explicit image-level labels such as `genuine` and `tampered`, and keep destination reputation as a separate metadata field. Each row should include a stable image ID, source/provenance and license, parent/original QR ID, encoded payload (or payload hash), destination-reputation label if known, genuine/tampered label, manipulation type/region, generation or alteration process, dimensions, and whether it remains decodable.

The minimum useful structure is two independently verified visual classes with documented provenance and enough examples from multiple payloads and manipulation types to support held-out evaluation. Prefer paired unmodified/manipulated variants. Make train/validation/test partitions by parent QR or payload group (for example, 70/15/15 only after group assignment); never split variants or duplicates across partitions. Report the actual class counts and metrics only after training on verified labels.

## 11. Limitations

- No dataset documentation, source reference, or license was present in the archive/extracted tree; label provenance remains unresolved.
- Header validation does not equal full pixel decoding. Only ten representative files were QR-decoded; the contact sheet is also representative only.
- Exact duplicates were exhaustively checked in the archive; extracted-file byte identity was sampled, not checked for every file.
- Near-duplicate and all-payload duplicate scans were not run.
- URL hosts in examples are observations from embedded samples, not current reputation lookups.

## Audit artifacts

- Machine-readable measurements: [`ml/reports/qr_dataset_audit.json`](ml/reports/qr_dataset_audit.json)
- Reusable read-only inventory script: [`ml/audit_qr_dataset.py`](ml/audit_qr_dataset.py)
- Representative contact sheet: [`ml/reports/qr_dataset_contact_sheet.png`](ml/reports/qr_dataset_contact_sheet.png)

