# Phase 4 QR Dataset Source and Label Research

**Conclusion: Existing dataset only suitable for another task.** The source is identified with high confidence as the Kaggle dataset **Benign and Malicious QR codes** by Samah Malibari (`samahsadiq`). The class distinction is the reputation of the encoded URL (benign versus malicious URL), not whether the QR image is genuine versus visually tampered. The Kaggle record says the license is **Unknown**, so the source is identified but reuse is not license-cleared.

## Questions and scope

This research establishes where the local 200,000-image archive came from, what the two labels mean, whether it supplies visual-tampering ground truth, and whether a better-documented QR tampering dataset is available. It is read-only: no images were downloaded, extracted, relabeled, or edited, and no models were trained.

## Local evidence reviewed

I read `PHASE4_QR_DATASET_AUDIT.md`, `ml/reports/qr_dataset_audit.json`, `DATASETS.md`, `PHASE1A_REPORT.md`, `PHASE2_ML_REPORT.md`, the QR training pipeline, package requirements, tracked repository history, and the available PowerShell history. The local documentation only identifies `qr.zip` as a path; it gives an obsolete 48,923-image benign-only inventory and no original URL or license. The repository has two initial commits, no root README, and no additional QR source note. The relevant shell-history search had no QR/Kaggle download command. The archive has no comment or accompanying metadata/document files; the PNG files contain only IHDR, IDAT, and IEND chunks (no embedded text metadata).

The source archive itself contains 200,000 PNGs under the two candidate folders, with 185,581,039 uncompressed bytes. Its paths include `QR codes/benign/benign/benign_0.png` and `QR codes/malicious/malicious/malicious_316254.png`, matching the Kaggle listing’s naming and structure. The Kaggle listing reports 200,000 files and exactly 185,581,039 total bytes. Its first 20 file-list records are the same as the local archive’s first 20 records, with matching per-file uncompressed byte sizes. The local archive total, class counts, layout, names, and these file records make this a high-confidence source match; the local folder did not retain a download receipt or a separately recorded source-archive SHA-256.

## Original source and label definition

The [official Kaggle dataset page](https://www.kaggle.com/datasets/samahsadiq/benign-and-malicious-qr-codes) and its [Kaggle dataset metadata record](https://www.kaggle.com/api/v1/datasets/metadata/samahsadiq/benign-and-malicious-qr-codes) identify the dataset as **Benign and Malicious QR codes**, by Samah Malibari, with 100,000 images per folder. Kaggle’s source description says:

- The images were generated with Python from the creator’s **Benign and Malicious URLs** dataset.
- It used the first 100,000 URLs of each URL class.
- The images encode real URLs; the malicious folder contains QR codes encoding real malicious URLs, and Kaggle explicitly warns against visiting them.
- The underlying URL dataset’s official metadata describes its `label` as `benign` or `malicious` and `result` as 0 for benign and 1 for malicious.
- Kaggle marks the QR dataset’s license as **Unknown**.

The underlying source is the creator’s [Benign and Malicious URLs dataset](https://www.kaggle.com/datasets/samahsadiq/benign-and-malicious-urls), itself documented as a balanced URL-classification dataset sourced from other URL lists. This establishes that the QR labels mean **encoded URL maliciousness/reputation**, not visual alteration. There is no `genuine`/`tampered` annotation, no manipulation metadata, and no paired original/manipulated variants documented by the source. The two folders are separate URL-label groups rendered as QR images.

An independent scholarly paper cites the same Kaggle dataset and describes its 200,000 balanced QR images as representing real URLs, with malicious codes linked to potentially harmful sites. It also references a separate 1,000-image Mendeley dataset as 500 benign/500 malicious URL QR codes. This corroborates the URL-label interpretation; it is not evidence of visual tampering. See [Efficient Malicious QR Code Detection System Using an Advanced Deep Learning Approach, §3.2](https://www.techscience.com/CMES/v145n1/64345/html).

### License

Kaggle’s official metadata reports **Unknown** for this dataset’s license. The source paper does not state a separate data license. Do not assume Kaggle-hosted files are automatically open-licensed or that any license on the upstream URL datasets covers these generated QR image files. Obtain a clear license/permission before redistribution or training use.

## Existing dataset task assessment

| Proposed task | Supported by its labels? | Finding |
|---|---|---|
| Benign-URL QR vs malicious-URL QR image classification | Yes, according to source documentation | It may support research on classifying QR images by the reputation label of their encoded URL, subject to license review and label/source validation. |
| Genuine vs visually tampered QR detection | No | No tamper labels, altered-image provenance, original/manipulated pairs, or visual manipulation taxonomy are supplied. |
| QR decoding or scanner robustness | Partly | The files are QR images, but this is not a paired clean/degraded robustness corpus and one of ten audit samples did not decode with OpenCV. |

The source says both folders were generated in Python, one loop per URL class. That also creates a potential shortcut risk: URL length, QR density/version/rendering, and payload characteristics could correlate with the URL labels. A model evaluated on these images would not thereby demonstrate detection of tampering.

## Recommended documented dataset for visual tampering

The closest directly relevant documented source found is **Innovative QR Code System for Tamper-Proof Generation and Fraud-Resistant Verification** by Suliman A. Alsuhibany, *Sensors* (2025), [DOI 10.3390/s25133855](https://doi.org/10.3390/s25133855), with the full article available through [PubMed Central](https://pmc.ncbi.nlm.nih.gov/articles/PMC12252379/).

The article describes a 5,000-image task-specific dataset with five classes, 1,000 images each: `PatternA`, `PatternA_reprinted`, `PatternB`, `PatternB_reprinted`, and `Unclassified`. Pattern A and B are QR codes with different market watermarks; Unclassified is unwatermarked. The reprinted classes are derived by capturing and reprinting the Pattern A/B codes to simulate fraudulent reuse. Images were printed and captured with cameras, and included noise, blur, rotation, and lower-resolution conditions. Thus, the label semantics are closer to visual authenticity/reprint fraud than URL reputation.

**Pair status:** the paper describes the reprint classes as derived from Pattern A/B, establishing class-level lineage, but does not describe a released row-level pair manifest or stable parent IDs. Do not assume one-to-one pairs can be reconstructed from the public article alone.

**Access and license:** the paper’s data availability statement says the data are available from the corresponding author upon reasonable request. The article itself is CC BY 4.0, but that does not establish a separate license for the underlying image dataset. Request the data and explicit dataset-use terms from the author before using it. This is a useful candidate to evaluate after receiving its files and class manifest; it is task-specific to watermark/reprint authentication, not a general-purpose corpus of arbitrary QR image tampering.

### Other datasets checked and not recommended as tamper labels

- [QR-DN1.0](https://pmc.ncbi.nlm.nih.gov/articles/PMC8627996/) describes distorted/noisy QR images and non-distorted ground-truth counterparts, under CC BY. It is for distortion/reconstruction and scan robustness, not genuine-versus-fraudulent QR authenticity.
- [Mendeley: Dataset of 1000 Images of Malicious and Benign QR codes](https://data.mendeley.com/datasets/cmhh7744sp/1) defines classes through verified malicious URLs versus legitimate URLs. Its listed license is CC BY 4.0, but its semantics are URL reputation, not visual tampering.
- The [AQRI ground-truth record on Zenodo](https://zenodo.org/records/20325847) concerns adversarial QR images, but access to its files is restricted and the record does not provide an open dataset license or a paired clean/tampered release. It is not a presently accessible training recommendation.

## Recommendation

Keep NIVARA’s modalities distinct. The local Kaggle-derived dataset is semantically for **QR image classification by encoded URL reputation**, and its license is currently unknown. Do not use it for EfficientNetB0 genuine-versus-tampered training. For that Phase 4 objective, first request the 5,000-image watermark/reprint dataset above and obtain written dataset-use terms and its available lineage metadata. If a generic tampering detector is intended, ensure the eventual corpus separately labels the image manipulation itself, includes parent IDs for any original/reprint pairs, and records URL reputation as an independent field.

## Limitations

- Local archive identity is supported by the exact official dataset title, creator, counts, folder paths, total uncompressed bytes, and matching first-page filenames/sizes. A source download receipt or original-archive hash was not retained locally, so the transfer chain cannot be proven cryptographically.
- Kaggle’s page has limited browser-rendered text; its public metadata API supplied the dataset description, source, counts, creator, and `Unknown` license field.
- This report did not visit any encoded URLs, download external datasets, request restricted files, or contact dataset authors.
- Research reflects the sources available on 4 October 2026; dataset access and licensing can change.
