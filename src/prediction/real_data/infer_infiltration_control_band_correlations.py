from pathlib import Path
import sys
import warnings

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from sklearn.base import clone
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_tcp_sampling_stability import (
    SAMPLE_SEEDS,
    FILES,
    load_tcp_sample,
)

from compare_infiltration_feature_engineering import build_models

from analyze_infiltration_fp_control_correlations import (
    FEATURE_PAIRS,
    VARIANTS,
    DIRECTION,
    remove_exact_overlaps,
    filter_labels,
    get_attack_probability,
)

warnings.filterwarnings("ignore", category=RuntimeWarning)

ROOT = Path(__file__).resolve().parents[3]

OUTPUT_DIR = (
    ROOT
    / "reports"
    / "behavior_relabeling_v2"
    / "threshold_distribution_analysis"
)

BOOTSTRAP_REPS = 2000
BASE_RANDOM_STATE = 20261105

GROUP_RETAINED = "retained_below_030"
GROUP_REMOVED = "removed_030_to_050"


def spearman_value(x, y):
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)

    valid = np.isfinite(x) & np.isfinite(y)
    x = x[valid]
    y = y[valid]

    if len(x) < 10:
        return np.nan

    if np.unique(x).size < 2 or np.unique(y).size < 2:
        return np.nan

    return float(spearmanr(x, y).statistic)


def bootstrap_difference(
    retained,
    removed,
    rng,
):
    """
    Bootstrap rho_removed - rho_retained.

    Resample rows independently within each group.
    Keep each feature pair together within a row.
    Preserve the original group sizes.
    """

    retained = np.asarray(retained, dtype=float)
    removed = np.asarray(removed, dtype=float)

    retained = retained[
        np.isfinite(retained).all(axis=1)
    ]

    removed = removed[
        np.isfinite(removed).all(axis=1)
    ]

    n_retained = len(retained)
    n_removed = len(removed)

    rho_retained = spearman_value(
        retained[:, 0],
        retained[:, 1],
    )

    rho_removed = spearman_value(
        removed[:, 0],
        removed[:, 1],
    )

    observed_delta = rho_removed - rho_retained

    result = {
        "n_retained": n_retained,
        "n_removed": n_removed,
        "rho_retained": rho_retained,
        "rho_removed": rho_removed,
        "delta_rho": observed_delta,
        "bootstrap_ci_lower": np.nan,
        "bootstrap_ci_upper": np.nan,
        "bootstrap_valid_reps": 0,
    }

    if not np.isfinite(observed_delta):
        return result

    deltas = []

    for _ in range(BOOTSTRAP_REPS):
        retained_idx = rng.integers(
            0,
            n_retained,
            size=n_retained,
        )

        removed_idx = rng.integers(
            0,
            n_removed,
            size=n_removed,
        )

        boot_retained = spearman_value(
            retained[retained_idx, 0],
            retained[retained_idx, 1],
        )

        boot_removed = spearman_value(
            removed[removed_idx, 0],
            removed[removed_idx, 1],
        )

        if (
            np.isfinite(boot_retained)
            and np.isfinite(boot_removed)
        ):
            deltas.append(
                boot_removed - boot_retained
            )

    if deltas:
        lower, upper = np.percentile(
            deltas,
            [2.5, 97.5],
        )

        result["bootstrap_ci_lower"] = float(lower)
        result["bootstrap_ci_upper"] = float(upper)
        result["bootstrap_valid_reps"] = len(deltas)

    return result


def holm_adjust(p_values):
    p_values = np.asarray(p_values, dtype=float)

    adjusted = np.full(
        len(p_values),
        np.nan,
    )

    valid = np.flatnonzero(
        np.isfinite(p_values)
    )

    if len(valid) == 0:
        return adjusted

    order = valid[
        np.argsort(p_values[valid])
    ]

    m = len(order)
    running_max = 0.0

    for rank, index in enumerate(order):
        candidate = (
            (m - rank)
            * p_values[index]
        )

        running_max = max(
            running_max,
            candidate,
        )

        adjusted[index] = min(
            running_max,
            1.0,
        )

    return adjusted


def main():
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    source_name, target_name = DIRECTION
    model_template = build_models()["XGBoost"]

    rows = []

    for seed_index, seed in enumerate(SAMPLE_SEEDS):
        print(f"\nSeed: {seed}", flush=True)

        X_source, y_source = load_tcp_sample(
            FILES[source_name],
            seed,
        )

        X_target, y_target = load_tcp_sample(
            FILES[target_name],
            seed,
        )

        (
            X_source,
            X_target,
            overlap_count,
            source_keep_mask,
            target_keep_mask,
        ) = remove_exact_overlaps(
            X_source,
            X_target,
        )

        y_source = filter_labels(
            y_source,
            source_keep_mask,
        )

        y_target = filter_labels(
            y_target,
            target_keep_mask,
        )

        X_train, _, y_train, _ = train_test_split(
            X_source,
            y_source,
            test_size=0.20,
            random_state=42,
            stratify=y_source,
        )

        imputer = SimpleImputer(
            strategy="median"
        )

        X_train_imp = pd.DataFrame(
            imputer.fit_transform(X_train),
            columns=X_train.columns,
            index=X_train.index,
        )

        X_target_imp = pd.DataFrame(
            imputer.transform(X_target),
            columns=X_target.columns,
            index=X_target.index,
        )

        benign = (
            np.asarray(y_target) == 0
        )

        for variant_index, variant in enumerate(VARIANTS):
            print(
                f"  Variant: {variant}",
                flush=True,
            )

            if variant == "baseline_all_76":
                features = list(X_train.columns)

            elif variant == "without_flow_iat_min":
                features = [
                    column
                    for column in X_train.columns
                    if column != "Flow IAT Min"
                ]

            else:
                raise ValueError(
                    f"Unknown variant: {variant}"
                )

            model = clone(model_template)

            model.fit(
                X_train_imp[features],
                y_train,
            )

            scores = get_attack_probability(
                model,
                X_target_imp[features],
            )

            retained_mask = (
                benign
                & (scores < 0.30)
            )

            removed_mask = (
                benign
                & (scores >= 0.30)
                & (scores < 0.50)
            )

            X_retained = X_target.loc[
                retained_mask
            ]

            X_removed = X_target.loc[
                removed_mask
            ]

            print(
                f"    Retained: {len(X_retained)}, "
                f"Removed: {len(X_removed)}, "
                f"overlaps: {overlap_count}",
                flush=True,
            )

            for pair_index, (
                feature_a,
                feature_b,
            ) in enumerate(FEATURE_PAIRS):

                rng = np.random.default_rng(
                    BASE_RANDOM_STATE
                    + seed_index * 10000
                    + variant_index * 1000
                    + pair_index
                )

                retained = X_retained[
                    [feature_a, feature_b]
                ].to_numpy(dtype=float)

                removed = X_removed[
                    [feature_a, feature_b]
                ].to_numpy(dtype=float)

                result = bootstrap_difference(
                    retained,
                    removed,
                    rng,
                )

                rows.append({
                    "seed": seed,
                    "variant": variant,
                    "feature_a": feature_a,
                    "feature_b": feature_b,
                    **result,
                })

                print(
                    f"      {feature_a} / {feature_b}: "
                    f"delta={result['delta_rho']:.4f}, "
                    f"valid={result['bootstrap_valid_reps']}",
                    flush=True,
                )

    results = pd.DataFrame(rows)

    results["bootstrap_ci_excludes_zero"] = (
        (results["bootstrap_ci_lower"] > 0)
        | (results["bootstrap_ci_upper"] < 0)
    )

    results["holm_p_within_seed"] = np.nan

    for seed in SAMPLE_SEEDS:
        mask = results["seed"] == seed

        results.loc[
            mask,
            "holm_p_within_seed",
        ] = holm_adjust(
            results.loc[
                mask,
                "bootstrap_ci_excludes_zero",
            ].astype(float).to_numpy()
        )

    # Important:
    # CI exclusion is not a p-value.
    # The column above is a descriptive indicator only.
    # Do not interpret the adjusted values as valid Holm p-values.

    output = (
        OUTPUT_DIR
        / "control_band_bootstrap_by_seed.csv"
    )

    results.to_csv(
        output,
        index=False,
    )

    summary = (
        results
        .groupby([
            "variant",
            "feature_a",
            "feature_b",
        ])
        .agg(
            median_delta=("delta_rho", "median"),
            min_delta=("delta_rho", "min"),
            max_delta=("delta_rho", "max"),
            ci_excludes_zero_seeds=(
                "bootstrap_ci_excludes_zero",
                "sum",
            ),
            median_ci_lower=(
                "bootstrap_ci_lower",
                "median",
            ),
            median_ci_upper=(
                "bootstrap_ci_upper",
                "median",
            ),
            median_valid_reps=(
                "bootstrap_valid_reps",
                "median",
            ),
        )
        .reset_index()
    )

    summary_output = (
        OUTPUT_DIR
        / "control_band_bootstrap_summary.csv"
    )

    summary.to_csv(
        summary_output,
        index=False,
    )

    print("\nSaved:", output)
    print("Saved:", summary_output)
    print("Rows:", len(results))
    print(
        "Bootstrap repetitions per comparison:",
        BOOTSTRAP_REPS,
    )


if __name__ == "__main__":
    main()
