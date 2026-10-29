# CIC-IDS2017 → CIC-IDS2018: Botnet Generalization — Final Report

## 1. Objective

Evaluate whether a binary Botnet detection model trained on CIC-IDS2017 generalizes to CIC-IDS2018, and distinguish cross-dataset generalization from validation within CIC-IDS2018.

## 2. Cross-dataset evaluation

The model trained on CIC-IDS2017 was evaluated on the CIC-IDS2018 Botnet-Friday dataset.

At the default decision threshold of 0.5:

| Metric | Result |
|---|---:|
| Accuracy | 0.8121 |
| Macro F1 | 0.4483 |
| Bot precision | 0.0547 |
| Bot recall | 0.00018 |
| Bot F1 | 0.00036 |
| ROC-AUC | 0.9372 |
| Average precision | 0.6455 |
| True positives | 26 |
| False negatives | 144,509 |
| False positives | 449 |
| True negatives | 626,603 |

Despite a high ROC-AUC, the model detects only 26 of 144,535 Bot samples at the default threshold. This demonstrates that ranking performance alone does not guarantee useful classification at a particular operating threshold.

Lowering the threshold to 0.005 raises recall to approximately 95.5%, but the benign false-positive rate rises to approximately 9.0%. Threshold selection therefore involves a substantial operational trade-off.

## 3. CIC-IDS2018 block validation

A separate experiment trained an XGBoost model on the first contiguous block of CIC-IDS2018 Botnet-Friday data and evaluated it on the subsequent block.

- Training block: 192,896 rows.
- Test block: 38,580 rows.
- Training labels: 130,951 Bot and 61,945 Benign.
- Test labels: 13,584 Bot and 24,996 Benign.

At threshold 0.5, the block-validation results were:

| Metric | Result |
|---|---:|
| Precision | 0.9981 |
| Recall | 0.9998 |
| F1 | 0.9989 |
| False-positive rate | 0.0010 |
| ROC-AUC | 1.0000 |
| Average precision | 1.0000 |
| True positives | 13,581 |
| False negatives | 3 |
| False positives | 26 |
| True negatives | 24,970 |

These results describe a model trained and tested within CIC-IDS2018. They do not establish that a CIC-IDS2017-trained model generalizes to CIC-IDS2018.

The near-perfect scores warrant caution. They do not, by themselves, prove data leakage. Further evidence about feature construction, row ordering, duplicate flows, and the dataset's collection process would be needed to establish the cause.

## 4. Feature ablation and ECE control

The controlled ECE experiment evaluated five random seeds.

The baseline and ECE-zeroed variants produced identical results across the tested seeds on both evaluation datasets. Removing the ECE feature increased variability on CIC-IDS2018.

**Decision:** retain ECE in the main pipeline. The experiment did not provide evidence that zeroing ECE improves performance.

Other feature-ablation experiments showed that decision-threshold choice materially affects Bot recall and false-positive rates. These results should be interpreted alongside the full precision-recall trade-off, not as evidence that a single threshold is universally optimal.

## 5. Main conclusions

1. The CIC-IDS2017-trained model shows a substantial cross-dataset operating-point problem on CIC-IDS2018: Bot recall is extremely low at threshold 0.5 despite ROC-AUC of approximately 0.937.
2. A lower threshold can recover many Bot detections, but at the cost of more false positives.
3. Near-perfect performance from a model trained and tested on CIC-IDS2018 does not resolve the cross-dataset generalization problem.
4. The block-validation result is a separate within-dataset result and should not be presented as proof of external generalization.
5. The controlled ECE ablation supports retaining ECE in the main pipeline.

## 6. Limitations

- The external evaluation covers the CIC-IDS2018 Botnet-Friday scenario; it does not establish generalization across all days, environments, or attack families.
- The block validation uses contiguous row blocks rather than a verified timestamp-based temporal split.
- Near-perfect block-validation metrics have not independently established whether duplicate flows, collection artifacts, or other sources of dependence affect the result.
- Thresholds are operating choices and should not be selected by optimizing on the external test set.
- The reported results do not establish production readiness.

## 7. Artifacts

- Controlled ECE report: `reports/cic_botnet_ece_controlled/FINAL_REPORT.md`
- ECE experiment summary: `reports/cic_botnet_ece_controlled/summary_all_seeds.csv`
- CIC-IDS2018 block metrics: `reports/cic2018_block_validation/metrics.csv`
- CIC-IDS2018 block predictions: `reports/cic2018_block_validation/predictions.csv`
- Block-validation script: `src/prediction/real_data/cic2018_botnet_block_validation.py`

## 8. Final status

The ECE ablation and CIC-IDS2018 block-validation results have been committed and pushed to GitHub.

The main finding is documented: strong within-dataset results do not guarantee cross-dataset generalization. The current evidence is sufficient to report this limitation honestly; it is not sufficient to claim that the cause has been conclusively identified.

No additional experiments are included in this report.
