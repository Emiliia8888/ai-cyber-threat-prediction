# Research Reports and Experimental Results

This directory contains reports, metrics, diagnostic outputs, and prediction results from the CIC-IDS2017 and CIC-IDS2018 experiments.

The main research objective is to investigate Botnet detection performance across datasets, evaluate decision-threshold behavior, and examine feature importance and model stability.

For the complete research methodology, findings, and limitations, see [PROJECT_CASE_STUDY.md](../PROJECT_CASE_STUDY.md).

## 1. Main Research: Cross-Dataset Botnet Detection

The primary experiment evaluates a binary XGBoost model trained on CIC-IDS2017 and tested on CIC-IDS2018 Botnet-Friday.

Key report:

- [CIC Botnet Generalization Final Report](CIC_BOTNET_GENERALIZATION_FINAL_REPORT.md)

Supporting outputs:

- `cic2018_model_on_cic2017_botnet_predictions.csv`
- `cic_botnet_probability_diagnostics.csv`
- `cic_botnet_low_threshold_analysis.csv`
- `cic_threshold_friday_test.csv`
- `cic_threshold_thursday_validation.csv`

These files support the analysis of cross-dataset performance, prediction probabilities, and decision-threshold trade-offs.

## 2. ECE Feature Ablation and Model Stability

These experiments investigate the effect of ECE Flag Count and related feature configurations.

Main report:

- [Controlled ECE Experiment](cic_botnet_ece_controlled/FINAL_REPORT.md)

Supporting results:

- `cic_botnet_ece_controlled/results_all_seeds.csv`
- `cic_botnet_ece_controlled/summary_all_seeds.csv`
- `cic_botnet_seed_stability/all_runs.csv`
- `cic_botnet_seed_stability/mean_std_summary.csv`
- `cic_botnet_ablation/summary.csv`
- `cic_botnet_ablation_flag_tests/summary.csv`
- `cic_botnet_ablation_single_flag_tests/summary.csv`

These results compare feature configurations and evaluate variability across random seeds.

## 3. CIC-IDS2018 Validation Experiments

This section contains experiments performed within CIC-IDS2018. They should be interpreted separately from cross-dataset evaluation.

### Block validation

- `cic2018_block_validation/metrics.csv`
- `cic2018_block_validation/predictions.csv`

The block-validation results use contiguous row blocks. They are not equivalent to a verified timestamp-based temporal split.

### In-domain evaluation

- `cic2018_botnet_in_domain_summary.csv`
- `cic2018_botnet_in_domain_predictions.csv`

### Feature ablation

- `cic2018_botnet_feature_ablation/summary.csv`

These experiments provide additional context but do not establish generalization to unseen network environments.

## 4. Multiclass CIC-IDS2017 Experiments

These outputs relate to multiclass classification and model evaluation on CIC-IDS2017.

Main metrics and reports:

- `cic_multiclass_metrics.json`
- `cic_multiclass_classification_report.json`
- `cic_multiclass_confusion_matrix.csv`
- `cic_multiclass_xgboost_metrics.json`
- `cic_multiclass_xgboost_classification_report.json`
- `cic_multiclass_xgboost_confusion_matrix.csv`
- `cic_multiclass_xgboost_tuning_metrics.json`
- `cic_multiclass_xgboost_tuning_classification_report.json`
- `cic_multiclass_xgboost_tuning_confusion_matrix.csv`

Feature importance results:

- `xgboost_feature_importance/`

A previous label-normalization snapshot is preserved in:

- `backup_before_label_normalization/`

## 5. Dataset and Feature Diagnostics

Diagnostic outputs are used to investigate dataset composition, feature distributions, and possible distribution shifts.

Examples:

- `cic_attack_distribution_diagnostics.json`
- `cic_class_distribution_diagnostics.json`
- `cic_feature_shift_diagnostics.json`
- `cic_botnet_feature_shift.csv`
- `cic_friday_feature_diagnostic.csv`
- `cic_botnet_feature_importance.csv`
- `cic_attack_family_recall.csv`
- `cic_training_days_comparison.csv`
- `cic_all_days_random_vs_friday.csv`

These files provide supporting analysis. Diagnostic findings should not be interpreted as proof of causality or data leakage without further investigation.

## 6. Additional Experimental Outputs

Other directories and files contain intermediate predictions, threshold tests, scenario comparisons, and experiment-specific outputs.

Examples include:

- `cic_botnet_ablation/`
- `cic_botnet_ablation_flag_tests/`
- `cic_botnet_ablation_single_flag_tests/`
- `cic_botnet_no_flags_experiment/`
- `cic_botnet_no_flags_no_packet_min/`
- `cic_botnet_ece_diagnostics/`
- `cic_xgboost_friday_predictions.csv`
- `cic_xgboost_friday_predictions_with_features.csv`
- `cic_xgboost_friday_diagnostics.json`
- `cic_xgboost_thursday_holdout_metrics.json`
- `cic_xgboost_wednesday_predictions.csv`

These outputs are retained for traceability and further analysis. Not every intermediate result represents a final experiment or a validated model configuration.

## 7. Interpretation and Reproducibility

Important distinctions when interpreting these results:

- Cross-dataset evaluation is different from within-dataset validation.
- Accuracy and ROC-AUC alone do not describe performance at a specific decision threshold.
- Precision, recall, F1, and false-positive rate should be considered together.
- Results from one scenario or attack family should not be generalized to all network environments.
- Intermediate diagnostic outputs are supporting evidence, not standalone conclusions.

The CIC datasets are not included in this repository. Reproducing the experiments requires obtaining the datasets separately and configuring the local data paths expected by the experiment scripts.

See [PROJECT_CASE_STUDY.md](../PROJECT_CASE_STUDY.md) for the main research conclusions and limitations.
