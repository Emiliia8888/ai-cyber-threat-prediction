# CIC-IDS2017 to CIC-IDS2018: Cross-Dataset Botnet Detection

## Project Case Study

### 1. Project Overview

This project investigates the ability of a machine learning model to detect Botnet network traffic across different network intrusion detection datasets.

The primary objective was to evaluate whether a binary Botnet detection model trained on CIC-IDS2017 could generalize to CIC-IDS2018.

Rather than relying exclusively on conventional validation metrics, the project focused on cross-dataset evaluation, decision-threshold behavior, feature ablation, and the limitations of within-dataset validation.

**Key technologies:**
- Python
- XGBoost
- pandas
- NumPy
- scikit-learn
- CIC-IDS2017
- CIC-IDS2018

### 2. Problem Statement

Machine learning models for network intrusion detection can achieve strong validation results while performing poorly in different network environments.

This creates a practical challenge: a model that performs well on its training dataset may not reliably detect the same attack category in another dataset.

The project investigated three questions:

1. Does a Botnet detection model trained on CIC-IDS2017 generalize to CIC-IDS2018?
2. How does the decision threshold affect Botnet detection and false-positive rates?
3. Does removing the ECE Flag Count feature improve cross-dataset performance or model stability?

### 3. Experimental Approach

#### 3.1 Cross-Dataset Evaluation

A binary XGBoost Botnet classifier trained on CIC-IDS2017 was evaluated on the CIC-IDS2018 Botnet-Friday dataset.

The default classification threshold was 0.5.

The evaluation included:
- Accuracy
- Macro F1
- Botnet precision
- Botnet recall
- Botnet F1
- ROC-AUC
- Average precision
- Confusion matrix counts

A second threshold experiment examined the trade-off between Botnet recall and benign false-positive rate.

#### 3.2 Within-Dataset Block Validation

A separate experiment trained and evaluated an XGBoost model using contiguous blocks from CIC-IDS2018 Botnet-Friday data.

- Training block: 192,896 rows
- Test block: 38,580 rows

This experiment was treated separately from cross-dataset evaluation.

The purpose was to understand the difference between performance within one dataset and performance when transferring a model between datasets.

#### 3.3 ECE Feature Ablation

A controlled experiment evaluated the influence of ECE Flag Count using five random seeds:

`7, 21, 42, 100, 123`

Three feature configurations were compared:

- `baseline`
- `ece_zeroed`
- `without_ece_flag`

The experiment used a decision threshold of 0.01 and evaluated results on both CIC-IDS2017 and CIC-IDS2018.

### 4. Results

#### 4.1 Cross-Dataset Generalization

The CIC-IDS2017-trained model produced the following results on CIC-IDS2018 Botnet-Friday at threshold 0.5:

| Metric | Result |
|---|---:|
| Accuracy | 0.8121 |
| Macro F1 | 0.4483 |
| Botnet precision | 0.0547 |
| Botnet recall | 0.00018 |
| Botnet F1 | 0.00036 |
| ROC-AUC | 0.9372 |
| Average precision | 0.6455 |

The confusion matrix showed:

| Outcome | Count |
|---|---:|
| True positives | 26 |
| False negatives | 144,509 |
| False positives | 449 |
| True negatives | 626,603 |

Despite a ROC-AUC of 0.9372, the model detected only 26 of 144,535 Botnet samples at the default threshold.

This demonstrates that strong probability-ranking performance does not necessarily translate into useful classification at a particular operating threshold.

#### 4.2 Decision-Threshold Trade-off

Lowering the decision threshold from 0.5 to 0.005 increased Botnet recall to approximately 95.5%.

However, the benign false-positive rate increased to approximately 9.0%.

This illustrates an important operational trade-off: increasing attack detection sensitivity can also substantially increase false alarms.

A threshold should therefore be selected according to operational requirements and validated without optimizing against the external test set.

#### 4.3 Within-Dataset Block Validation

The separate CIC-IDS2018 block-validation experiment achieved:

| Metric | Result |
|---|---:|
| Precision | 0.9981 |
| Recall | 0.9998 |
| F1 | 0.9989 |
| False-positive rate | 0.0010 |
| ROC-AUC | 1.0000 |
| Average precision | 1.0000 |

These results are substantially stronger than the cross-dataset results.

However, the experiment used contiguous row blocks rather than a verified timestamp-based temporal split.

The near-perfect scores do not establish external generalization and do not independently prove or disprove data leakage, duplicate-flow dependence, or collection artifacts.

#### 4.4 ECE Flag Count Ablation

The controlled five-seed experiment found:

- The `baseline` and `ece_zeroed` variants produced identical metrics across all tested seeds on both datasets.
- Removing ECE changed model behavior and increased variability on CIC-IDS2018.

Mean CIC-IDS2018 ROC-AUC:

| Configuration | Mean ROC-AUC | Standard deviation |
|---|---:|---:|
| Baseline | 0.9132 | 0.0136 |
| ECE zeroed | 0.9132 | 0.0136 |
| Without ECE | 0.9159 | 0.0297 |

**Decision:** ECE Flag Count was retained in the main feature pipeline.

The experiment did not provide sufficient evidence to adopt the feature-removal variant as the primary model.

### 5. Key Findings

The experiments produced several important findings:

1. Strong within-dataset validation results do not guarantee cross-dataset generalization.
2. ROC-AUC alone is insufficient for assessing the practical usefulness of a classifier at a fixed decision threshold.
3. Decision-threshold selection has a substantial impact on the balance between attack detection and false alarms.
4. Near-perfect block-validation metrics require further investigation before they can be interpreted as evidence of robust generalization.
5. The controlled ECE ablation did not demonstrate a benefit from removing ECE Flag Count.

### 6. Limitations

The current research has several limitations:

- External evaluation covers the CIC-IDS2018 Botnet-Friday scenario, not every day, network environment, or attack family.
- The block-validation experiment is not a verified timestamp-based temporal evaluation.
- Potential effects of duplicate flows, row ordering, collection artifacts, and feature dependencies have not been conclusively identified.
- The threshold experiments do not establish a universally optimal operating threshold.
- The results do not establish production readiness.

These limitations are important when interpreting the reported metrics.

### 7. Project Artifacts

The repository contains supporting reports and experiment outputs:

- `reports/CIC_BOTNET_GENERALIZATION_FINAL_REPORT.md`
- `reports/cic_botnet_ece_controlled/FINAL_REPORT.md`
- `reports/cic_botnet_ece_controlled/summary_all_seeds.csv`
- `reports/cic2018_block_validation/metrics.csv`
- `reports/cic2018_block_validation/predictions.csv`

### 8. Conclusion

This project demonstrates a practical challenge in machine learning-based network intrusion detection: a model can achieve strong validation results within one dataset while exhibiting severe detection limitations when evaluated on another dataset.

The most important result was identifying the gap between within-dataset performance and cross-dataset generalization.

The project also demonstrated the importance of examining decision thresholds, false-positive rates, feature ablation, and validation methodology rather than relying on a single performance metric.

**The current model should be treated as an experimental research artifact, not a production-ready intrusion detection system.**