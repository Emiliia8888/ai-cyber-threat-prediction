# Infiltration FP vs Matched Benign Controls
## Caliper Sensitivity Analysis and Fwd IAT Min

## 1. Research objective

This analysis investigates whether confidently misclassified benign
traffic flows (false positives, FP) differ in their timing characteristics
from matched benign control flows in the CIC-IDS2018 Infiltration
cross-scenario setting.

The transfer direction is Infil2 -> Infil1.

The analysis focuses on `Fwd IAT Min` and evaluates whether the observed
paired differences remain consistent under alternative matching calipers
and model feature configurations.

This is an observational comparison. It does not establish that timing
features cause false-positive predictions.

## 2. Experimental design

Two model configurations were compared:

- `baseline_all_76`: baseline model using all 76 features.
- `without_flow_iat_min`: model configuration excluding `Flow IAT Min`.

The comparison outcome was `Fwd IAT Min`. This feature remains available
as an outcome in the second configuration; excluding `Flow IAT Min` from
the model does not remove `Fwd IAT Min` from the post-matching analysis.

Five sampling seeds were used:

`7, 42, 99, 123, 2024`.

Confident false positives were benign target flows predicted as attacks
with score >= 0.90. Benign controls were benign target flows predicted
as benign with score < 0.50.

Matching covariates:

- `Total Fwd Packets`
- `Total Backward Packets`
- `Flow Duration`

The matching procedure used log1p transformation, RobustScaler and
Hungarian optimal assignment with dummy columns, allowing maximum
cardinality one-to-one matching without replacement under the selected
caliper.

The three evaluated calipers were 0.20, 0.25 and 0.30. Calipers refer
to distances in the transformed matching space.

## 3. Matching yield and balance

| Caliper | Total pairs (both variants) | Median FP retention | SMD checks < 0.10 |
|---:|---:|---:|---:|
| 0.20 | 1,063 | 23.27% | 24/30 |
| 0.25 | 1,695 | 35.76% | 26/30 |
| 0.30 | 2,389 | 52.49% | 23/30 |

Caliper 0.25 achieved the highest number of matching-balance checks
below the heuristic absolute SMD threshold of 0.10 (26 of 30).

Caliper 0.20 was more restrictive and retained fewer false positives.
Caliper 0.30 increased the number of matched pairs but did not improve
overall balance.

The SMD threshold is a diagnostic heuristic, not proof that all
confounding has been removed.

## 4. Paired Fwd IAT Min comparison

For each matched pair, the raw difference was defined as:

`FP Fwd IAT Min - Control Fwd IAT Min`.

A positive difference means the FP flow had a larger `Fwd IAT Min`
than its matched benign control.

At caliper 0.25:

- Baseline median paired difference: +94.
- Baseline positive-difference fraction: 56.97%.
- Baseline positive direction in 4 of 5 seeds.
- Without-Flow-IAT-Min median paired difference: +169.5.
- Without-Flow-IAT-Min positive-difference fraction: 58.28%.
- Without-Flow-IAT-Min positive direction in 5 of 5 seeds.

The sign tests were performed per seed, excluding zero differences,
and adjusted using a global Holm correction across the 30 seed-level
tests (3 calipers x 2 variants x 5 seeds).

At caliper 0.25, the direction remained statistically significant
after this correction in 2 of 5 baseline seed tests and 4 of 5
without-Flow-IAT-Min seed tests.

These tests are seed-level resampling analyses of the same underlying
traffic population. They are not independent replications on separate
datasets.

## 5. Bootstrap sensitivity of the pooled matched pairs

The pooled-pair bootstrap used the paired log-ratio:

`log1p(FP Fwd IAT Min) - log1p(Control Fwd IAT Min)`.

For each caliper and variant, 5,000 bootstrap resamples of matched
pairs were used to estimate the median and percentile 95% interval.

| Caliper | Variant | Pairs | Median log-ratio | 95% CI | exp(median) |
|---:|---|---:|---:|---:|---:|
| 0.20 | Baseline | 505 | 0.0000 | [0.0000, 0.3164] | 1.0000 |
| 0.20 | Without Flow IAT Min | 558 | 0.1421 | [0.0029, 0.4341] | 1.1527 |
| 0.25 | Baseline | 832 | 1.0466 | [0.6100, 1.8023] | 2.8479 |
| 0.25 | Without Flow IAT Min | 863 | 0.7578 | [0.4705, 1.0937] | 2.1336 |
| 0.30 | Baseline | 1,175 | 2.1026 | [1.5236, 2.7081] | 8.1875 |
| 0.30 | Without Flow IAT Min | 1,214 | 1.8869 | [1.3148, 2.3383] | 6.5991 |

The exponentiated median is the exponent of the median paired log-ratio.
It can be interpreted as a median-scale multiplicative contrast of
(FP + 1) relative to (control + 1). It is not the ratio of the two
group medians.

At caliper 0.25, both pooled-pair bootstrap intervals are above zero.
At caliper 0.20, the baseline interval includes zero. Caliper 0.30
shows the strongest positive contrast, but has weaker matching balance
than caliper 0.25.

The pooled-pair bootstrap treats the matched pairs as resampling units.
It does not model dependence induced by the shared underlying traffic
population or the repeated seed construction. Its intervals therefore
describe uncertainty within the pooled matched sample, not independent
population-level replication.

A separate seed-wise bootstrap was also conducted. Its results answer
a different question: how stable the effect estimate is within each
seed-specific matched sample. The seed-wise intervals should not be
confused with the pooled-pair intervals above.

## 6. Caliper selection

Caliper 0.25 is selected as the primary analysis setting because it
provides the best observed compromise between:

- matching balance (26/30 SMD checks below 0.10);
- matched sample size (1,695 pairs across both variants);
- median FP retention (35.76%);
- a positive paired Fwd IAT Min direction in most or all seeds,
  depending on the model configuration.

Caliper 0.20 is retained as a restrictive sensitivity analysis.
Caliper 0.30 is retained as a more permissive sensitivity analysis.

The stronger signal at caliper 0.30 should not be interpreted as
evidence that the larger caliper is preferable: increasing the caliper
also permits less similar matches.

## 7. Robustness and limitations

### Matching and duplicate checks

The matched pairs were formed without replacement within each
seed/variant run. The audit found no repeated full 76-feature vectors
within the FP group, within the control group, or shared between the
two groups in the examined matched samples.

This does not prove that each row represents a statistically
independent network session.

### Limited covariate adjustment

Matching was performed on three observed covariates only. Other
unobserved or unmatched traffic characteristics may contribute to
the differences.

### Seed dependence

Different random seeds generated largely different matched samples,
but all samples came from the same underlying CIC-IDS2018 traffic
population. Seeds are not independent datasets.

### No timestamps

The relevant Infil1/Infil2 parquet schemas did not provide suitable
timestamp columns for temporal block resampling. Row order, Flow
Duration and inter-arrival-time features are not substitutes for
actual timestamps. Consequently, a time-block bootstrap was not
performed.

### Heterogeneous paired differences

The paired-difference distributions are heterogeneous and asymmetric.
A positive median does not mean that every FP flow has a larger
`Fwd IAT Min` than its matched control.

### Observational interpretation

The results show an association conditional on matching on the three
observed covariates. They do not establish causality or prove that
`Fwd IAT Min` is the mechanism responsible for false-positive
predictions.

## 8. Conclusion

The sensitivity analysis indicates that the observed `Fwd IAT Min`
difference is dependent on the matching caliper. The restrictive
caliper 0.20 produces fewer matches and a weaker baseline signal.
The permissive caliper 0.30 produces a stronger positive contrast,
but with worse matching balance.

Caliper 0.25 offers the most defensible primary setting because it
achieves the best balance diagnostic among the three tested values
while retaining a substantial matched sample. At this setting,
both model configurations show positive median paired differences,
and the pooled-pair bootstrap intervals are above zero.

The findings support an association between confident false-positive
status and larger `Fwd IAT Min` relative to matched benign controls,
conditional on the three matching covariates. The evidence should be
interpreted as an analysis of one dataset under repeated sampling,
not as independent cross-dataset replication or causal evidence.

## 9. Reproducibility artifacts

The following files accompany this report:

- `caliper_comparison_by_seed.csv`
- `caliper_comparison_summary.csv`
- `caliper_comparison_overall.csv`
- `fwd_iat_min_caliper_bootstrap.csv`
- `fwd_iat_min_caliper_sensitivity.png`

No production model or prediction-engine code was modified as part
of this reporting step.
