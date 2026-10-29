# ECE Flag Count Ablation — Final Report

## Objective
Determine whether ECE Flag Count itself causes performance degradation
on CIC-IDS2018 or whether removing the feature changes model behavior.

## Experimental setup
- Model: XGBoost binary classifier
- Random seeds: 7, 21, 42, 100, 123
- Decision threshold: 0.01
- Training data: CIC-IDS2017
- Evaluation datasets: CIC-IDS2017 and CIC-IDS2018
- Variants: baseline, ece_zeroed, without_ece_flag

## Results
- baseline and ece_zeroed produced identical metrics across all five seeds
  on both evaluation datasets.
- Removing ECE changed model performance and increased variability across seeds.
- On CIC-IDS2018, the without_ece_flag variant showed substantial variability
  in precision and recall.
- Mean CIC-IDS2018 ROC-AUC:
  - baseline: 0.9132 ± 0.0136
  - ece_zeroed: 0.9132 ± 0.0136
  - without_ece_flag: 0.9159 ± 0.0297

## Decision
Keep ECE Flag Count in the main feature pipeline for now.
Do not adopt the without_ece_flag variant as the primary model.

## Limitations
The experiment does not prove that removing ECE alone causes instability.
Changes in feature-matrix structure and model training behavior may contribute.
CIC-IDS2018 validation remains a separate task.

## Artifacts
- results_all_seeds.csv
- summary_all_seeds.csv
- results_seed_42.csv
- results_seed_42_backup.csv

## Status
ECE ablation experiment completed.
Further investigation is deferred unless new evidence justifies reopening it.
