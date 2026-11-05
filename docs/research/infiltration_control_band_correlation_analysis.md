# Analysis of Correlation Structure Changes within the Infiltration Control Band

## 1. Research Objective

The objective of this experiment was to investigate whether the correlation structure between network traffic features in CIC-IDS2018 differs across different regions of a model-defined control interval.

Particular attention was paid to comparing two feature configurations:

- **baseline_all_76** — the baseline configuration containing all 76 numerical features;
- **without_flow_iat_min** — a configuration in which the `Flow IAT Min` feature was removed.

The study aims to identify stable differences in relationships between features rather than establish causal relationships.

## 2. Data and Experimental Design

The analysis used the Infiltration scenarios from the CIC-IDS2018 dataset, with cross-scenario model transfer between two scenarios:

- **Infil2** — the source dataset;
- **Infil1** — the target dataset.

The model was trained on the source scenario, Infil2. Predictions and feature values from the target scenario, Infil1, were then used for further analysis.

To reduce the influence of exact duplicates across datasets, duplicate rows were removed using row hashing. For the correlation analysis, a balanced sample of 20,000 observations per class was used. The stability of the results was evaluated using five random seeds: 42, 123, 2024, 7, and 99.

Feature preprocessing was performed without target-data leakage: median imputation values were estimated using the training portion of the source dataset, Infil2, and subsequently applied to the target dataset, Infil1.

## 3. Definition of Control Groups

Target observations were divided into groups according to the model's predicted score for the Benign class:

- **Retained** — observations with a Benign score below 0.30;
- **Removed** — observations with a Benign score greater than or equal to 0.30 and below 0.50;
- **Control band** — all observations with a Benign score below 0.50.

Thus, the main comparison was conducted between two subgroups within the same control interval: Retained and Removed.

Importantly, these groups are defined by conditioning on the model score. Therefore, the observed correlation differences characterize the feature structure after this conditional selection and do not necessarily represent the properties of the entire original network traffic population.

## 4. Correlation Analysis Method

Spearman's rank correlation coefficient (ρ) was used to assess relationships between features.

For each feature pair, the following quantities were calculated:

- correlation within the Retained group;
- correlation within the Removed group;
- difference between the correlations:

\[
\Delta \rho = \rho_{\text{Removed}} - \rho_{\text{Retained}}
\]

A positive Δρ indicates that the correlation in the Removed group is stronger or more positive than in the Retained group. A negative value indicates the opposite change.

The exploratory analysis covered 12 feature pairs related to flow timing characteristics, packet transmission rates, and traffic volume.

Correlations were calculated using the original feature values from the target dataset rather than imputed values. This avoided directly introducing artificial imputation values into the correlation structure.

## 5. Statistical Inference Using Bootstrap and Bonferroni Correction

Bootstrap resampling of rows was used to estimate the uncertainty of the differences between correlations. Resampling was performed separately for the Retained and Removed groups.

A total of 20,000 bootstrap iterations were performed for each combination of random seed and feature configuration.

To preserve the dependence between correlation estimates within each group, the same resampled rows were used for all 12 feature pairs in each bootstrap iteration. This ensured consistency of resampling across correlations, although it did not eliminate dependence between the features themselves.

The effect size was defined as:

\[
\Delta \rho = \rho_{\text{Removed}} - \rho_{\text{Retained}}
\]

Bonferroni correction was applied to a family of 24 comparisons within each seed:

\[
m = 12 \times 2 = 24
\]

where 12 represents the number of feature pairs and 2 represents the number of feature configurations.

With a family-wise significance level of α = 0.05, the adjusted significance level for an individual comparison was:

\[
\alpha_{\text{adjusted}} = \frac{0.05}{24} \approx 0.002083
\]

The corresponding confidence level for the bootstrap intervals was approximately 99.7917%.

These intervals are Bonferroni-adjusted marginal percentile bootstrap confidence intervals. They are not max-T simultaneous bootstrap intervals.

The correction was applied separately within each seed, rather than across all 120 comparisons simultaneously. Therefore, the results should not be interpreted as a global correction covering all seeds, feature configurations, and feature pairs together.

## 6. Results

### 6.1. Stable Differences Between Groups

The analysis identified eight feature pairs for which the adjusted bootstrap confidence intervals for the correlation differences excluded zero in all five seeds for both feature configurations.

This indicates that the direction of the statistically supported difference was consistent across all repeated samples used in this experiment.

The eight pairs were:

1. `Bwd IAT Min` — `Bwd IAT Max`;
2. `Bwd IAT Min` — `Bwd IAT Total`;
3. `Bwd Packets/s` — `Flow Packets/s`;
4. `Flow Bytes/s` — `Flow Packets/s`;
5. `Fwd IAT Min` — `Fwd IAT Std`;
6. `Fwd IAT Std` — `Fwd IAT Max`;
7. `Fwd IAT Std` — `Fwd IAT Total`;
8. `Fwd IAT Total` — `Fwd IAT Max`.

For each of these eight pairs, the result was stable across all five seeds in both the baseline configuration and the configuration without `Flow IAT Min`.

### 6.2. Median Changes in Correlation

The table below presents the median Δρ values across the five seeds.

| Feature pair | Baseline Δρ | Without Flow IAT Min Δρ |
|---|---:|---:|
| Bwd IAT Min — Bwd IAT Max | −0.3518 | −0.3601 |
| Bwd IAT Min — Bwd IAT Total | −0.2761 | −0.2849 |
| Bwd Packets/s — Flow Packets/s | −0.2808 | −0.3486 |
| Flow Bytes/s — Flow Packets/s | +0.6179 | +0.4376 |
| Fwd IAT Min — Fwd IAT Std | +0.5010 | +0.4966 |
| Fwd IAT Std — Fwd IAT Max | +0.2325 | +0.2519 |
| Fwd IAT Std — Fwd IAT Total | +0.1470 | +0.1697 |
| Fwd IAT Total — Fwd IAT Max | +0.0474 | +0.0475 |

The largest absolute median changes were observed for the following pairs:

- `Flow Bytes/s` — `Flow Packets/s`: a positive change in correlation;
- `Fwd IAT Min` — `Fwd IAT Std`: a transition from negative correlation in Retained to weak positive correlation in Removed;
- `Bwd IAT Min` — `Bwd IAT Max`: a reduction in positive correlation in Removed;
- `Bwd Packets/s` — `Flow Packets/s`: a reduction in positive correlation in Removed.

The smallest median change among the eight stable pairs was observed for `Fwd IAT Total` — `Fwd IAT Max` (approximately +0.047). Despite its statistical stability, its practical effect size is relatively small.

### 6.3. Correlation Structure Changes for Individual Feature Pairs

For the `Fwd IAT Min` — `Fwd IAT Std` pair in the baseline configuration, the median correlation was approximately −0.4322 in Retained and +0.0802 in Removed. The resulting median difference was +0.5010.

In the configuration without `Flow IAT Min`, the corresponding median values were approximately −0.4054 and +0.0670, respectively, with a median difference of +0.4966.

Thus, this difference persisted after removing `Flow IAT Min` from the feature set.

For the `Flow Bytes/s` — `Flow Packets/s` pair in the baseline configuration, the median correlation changed from approximately +0.0098 in Retained to +0.6659 in Removed. In the configuration without `Flow IAT Min`, the corresponding values were +0.2409 and +0.6601.

This indicates a substantial difference in the relationship between byte transmission rate and packet transmission rate across the two groups, although the magnitude of the effect depended on the feature configuration.

For the `Bwd IAT Min` — `Bwd IAT Max` pair, positive correlation decreased in Removed compared with Retained. The median Δρ was −0.3518 in the baseline configuration and −0.3601 in the configuration without `Flow IAT Min`.

### 6.4. The Role of the Flow IAT Min Feature

Comparing the two feature configurations showed that removing `Flow IAT Min` did not eliminate the identified patterns.

All eight stable pairs retained the same direction of correlation difference, and their adjusted bootstrap confidence intervals excluded zero across all five seeds in both configurations.

This suggests that the observed differences were not exclusively dependent on the presence of `Flow IAT Min` in the feature set.

However, this result does not establish that the correlation structure is entirely independent of `Flow IAT Min`, since removing one feature does not eliminate the potential influence of other related traffic characteristics.

## 7. Robustness and Limitations

The results demonstrate consistency in the direction of the eight differences across five seeds and two feature configurations. However, they should be interpreted in light of the following limitations.

**First, seed dependence.** The five seeds represent repeated samples from the same target scenario rather than five independent experimental datasets. Therefore, consistency across seeds provides evidence of robustness to sampling variation, but does not constitute independent replication.

**Second, conditional group definition.** The Retained and Removed groups are defined by the model score. Consequently, the observed correlation differences may be related to the selection mechanism based on model predictions. They cannot automatically be generalized to the entire traffic population.

**Third, multiple testing.** Bonferroni correction was applied to 24 comparisons separately within each seed. It was not a global correction across all 120 combinations of seeds, feature configurations, and feature pairs.

**Fourth, bootstrap assumptions.** Bootstrap resampling was performed at the row level. Since the available parquet files did not contain accessible timestamps suitable for constructing temporal blocks, temporal block bootstrap was not applied. If observations exhibit unaccounted temporal dependence, ordinary row bootstrap may underestimate uncertainty.

**Fifth, exploratory selection of feature pairs.** The analysis of the 12 feature pairs was exploratory. The identified patterns should therefore be regarded as findings from the investigated pairs, rather than confirmation of hypotheses registered in advance.

**Sixth, interpretation of correlation.** Spearman's correlation describes a monotonic statistical relationship between features. It does not establish causal relationships or, by itself, demonstrate a specific network mechanism.

Finally, statistical stability is not equivalent to practical significance. For example, the change of approximately +0.047 for `Fwd IAT Total` — `Fwd IAT Max` is small in magnitude, despite its stable direction within the conducted analysis.

## 8. Conclusion

The analysis identified stable differences in the correlation structure of network traffic features between the Retained and Removed groups within the model-defined Benign-score control interval when transferring the model from Infil2 to Infil1.

Eight out of the twelve investigated feature pairs exhibited adjusted bootstrap confidence intervals for correlation differences that excluded zero across all five seeds in both feature configurations.

The persistence of these patterns after removing `Flow IAT Min` suggests that the observed differences were not caused exclusively by this feature.

The most notable changes involved relationships between packet timing characteristics and traffic intensity measures. In particular, changes were observed for `Fwd IAT Min` — `Fwd IAT Std`, `Flow Bytes/s` — `Flow Packets/s`, and `Bwd IAT Min` — `Bwd IAT Max`.

Overall, the findings support the hypothesis that the correlation structure of network traffic features is heterogeneous within the model-defined control interval. However, they do not establish causality and require further validation on independent scenarios and datasets.

## 9. Reproducibility

The main stages of the analysis were implemented in separate scripts:

1. `src/prediction/real_data/analyze_infiltration_threshold_distribution.py`
2. `src/prediction/real_data/analyze_infiltration_control_band_correlations.py`
3. `src/prediction/real_data/infer_infiltration_control_band_correlations.py`
4. `src/prediction/real_data/infer_infiltration_control_band_correlations_bonferroni.py`

The results are stored in:

`reports/behavior_relabeling_v2/threshold_distribution_analysis/`

Bootstrap results with Bonferroni correction are stored in:

`reports/behavior_relabeling_v2/threshold_distribution_analysis/control_band_bonferroni_bootstrap/`

Key summary files include:

- `final_control_band_correlations_results.csv`
- `stable_eight_pairs_effect_summary.csv`
- `stable_eight_pairs_worst_case_ci.csv`
- `stable_eight_pairs_full_correlations_summary.csv`
- `control_band_bonferroni_bootstrap_summary.csv`
- `results_manifest.csv`

These materials provide a traceable workflow from descriptive correlation analysis to uncertainty estimation and robustness assessment.