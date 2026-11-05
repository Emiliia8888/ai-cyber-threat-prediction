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
    / "control_band_bonferroni_bootstrap"
)

BOOTSTRAP_REPS = 20_000
BASE_RANDOM_STATE = 20261106

FAMILY_SIZE = len(FEATURE_PAIRS) * len(VARIANTS)
FAMILY_ALPHA = 0.05
ADJUSTED_ALPHA = FAMILY_ALPHA / FAMILY_SIZE

LOWER_QUANTILE = ADJUSTED_ALPHA / 2
UPPER_QUANTILE = 1 - ADJUSTED_ALPHA / 2


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


def prepare_group_matrix(X, feature_names):
    return X.loc[:, feature_names].to_numpy(dtype=float)


def calculate_all_deltas(
    retained,
    removed,
    retained_indices=None,
    removed_indices=None,
):
    if retained_indices is None:
        retained_sample = retained
    else:
        retained_sample = retained[retained_indices]

    if removed_indices is None:
        removed_sample = removed
    else:
        removed_sample = removed[removed_indices]

    deltas = np.full(len(FEATURE_PAIRS), np.nan)

    for pair_index, (feature_a, feature_b) in enumerate(
        FEATURE_PAIRS
    ):
        a_index = FEATURE_INDEX[feature_a]
        b_index = FEATURE_INDEX[feature_b]

        rho_retained = spearman_value(
            retained_sample[:, a_index],
            retained_sample[:, b_index],
        )

        rho_removed = spearman_value(
            removed_sample[:, a_index],
            removed_sample[:, b_index],
        )

        if np.isfinite(rho_retained) and np.isfinite(rho_removed):
            deltas[pair_index] = rho_removed - rho_retained

    return deltas


def bootstrap_all_pairs(retained, removed, rng):
    observed = calculate_all_deltas(retained, removed)

    bootstrap_deltas = np.full(
        (BOOTSTRAP_REPS, len(FEATURE_PAIRS)),
        np.nan,
        dtype=float,
    )

    n_retained = len(retained)
    n_removed = len(removed)

    if n_retained < 10 or n_removed < 10:
        raise ValueError(
            "A group contains fewer than 10 rows."
        )

    for iteration in range(BOOTSTRAP_REPS):
        # One row resample per group and iteration.
        # These same row indices are reused for all 12 pairs.
        retained_indices = rng.integers(
            0,
            n_retained,
            size=n_retained,
        )

        removed_indices = rng.integers(
            0,
            n_removed,
            size=n_removed,
        )

        bootstrap_deltas[iteration] = calculate_all_deltas(
            retained,
            removed,
            retained_indices,
            removed_indices,
        )

        if (iteration + 1) % 1000 == 0:
            print(
                f"        Bootstrap: {iteration + 1:,}/"
                f"{BOOTSTRAP_REPS:,}",
                flush=True,
            )

    results = []

    for pair_index, (feature_a, feature_b) in enumerate(
        FEATURE_PAIRS
    ):
        values = bootstrap_deltas[:, pair_index]
        values = values[np.isfinite(values)]

        if len(values) == 0 or not np.isfinite(observed[pair_index]):
            lower = np.nan
            upper = np.nan
        else:
            lower, upper = np.quantile(
                values,
                [LOWER_QUANTILE, UPPER_QUANTILE],
            )

        results.append({
            "feature_a": feature_a,
            "feature_b": feature_b,
            "delta_rho": observed[pair_index],
            "bootstrap_ci_lower_bonferroni": lower,
            "bootstrap_ci_upper_bonferroni": upper,
            "bootstrap_valid_reps": len(values),
            "bootstrap_ci_excludes_zero_bonferroni": (
                bool(lower > 0 or upper < 0)
                if np.isfinite(lower) and np.isfinite(upper)
                else False
            ),
        })

    return results


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    source_name, target_name = DIRECTION
    model_template = build_models()["XGBoost"]

    feature_names = list(dict.fromkeys(
        feature
        for pair in FEATURE_PAIRS
        for feature in pair
    ))

    global FEATURE_INDEX
    FEATURE_INDEX = {
        feature: index
        for index, feature in enumerate(feature_names)
    }

    all_rows = []

    print("Bonferroni-adjusted joint bootstrap", flush=True)
    print("Bootstrap repetitions:", BOOTSTRAP_REPS)
    print("Feature pairs:", len(FEATURE_PAIRS))
    print("Variants:", len(VARIANTS))
    print("Family size per seed:", FAMILY_SIZE)
    print("Adjusted alpha:", ADJUSTED_ALPHA)
    print(
        "Confidence level:",
        100 * (1 - ADJUSTED_ALPHA),
        "%",
        flush=True,
    )

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

        imputer = SimpleImputer(strategy="median")

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

        benign = np.asarray(y_target) == 0

        for variant_index, variant in enumerate(VARIANTS):
            print(f"\n    Variant: {variant}", flush=True)

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

            retained_mask = benign & (scores < 0.30)

            removed_mask = (
                benign
                & (scores >= 0.30)
                & (scores < 0.50)
            )

            X_retained = X_target.loc[retained_mask]
            X_removed = X_target.loc[removed_mask]

            print(
                f"        Retained: {len(X_retained)}, "
                f"Removed: {len(X_removed)}, "
                f"overlaps: {overlap_count}",
                flush=True,
            )

            retained = prepare_group_matrix(
                X_retained,
                feature_names,
            )

            removed = prepare_group_matrix(
                X_removed,
                feature_names,
            )

            rng = np.random.default_rng(
                BASE_RANDOM_STATE
                + seed_index * 10000
                + variant_index * 1000
            )

            results = bootstrap_all_pairs(
                retained,
                removed,
                rng,
            )

            for result in results:
                all_rows.append({
                    "seed": seed,
                    "variant": variant,
                    "n_retained": len(retained),
                    "n_removed": len(removed),
                    "family_size": FAMILY_SIZE,
                    "family_alpha": FAMILY_ALPHA,
                    "adjusted_alpha": ADJUSTED_ALPHA,
                    "confidence_level": 1 - ADJUSTED_ALPHA,
                    **result,
                })

                print(
                    "        "
                    f"{result['feature_a']} / "
                    f"{result['feature_b']}: "
                    f"delta={result['delta_rho']:.4f}, "
                    f"CI=["
                    f"{result['bootstrap_ci_lower_bonferroni']:.4f}, "
                    f"{result['bootstrap_ci_upper_bonferroni']:.4f}"
                    f"], valid={result['bootstrap_valid_reps']}",
                    flush=True,
                )

    results_df = pd.DataFrame(all_rows)

    by_seed_output = (
        OUTPUT_DIR
        / "control_band_bonferroni_bootstrap_by_seed.csv"
    )

    results_df.to_csv(
        by_seed_output,
        index=False,
    )

    summary = (
        results_df
        .groupby(["variant", "feature_a", "feature_b"])
        .agg(
            median_delta=("delta_rho", "median"),
            min_delta=("delta_rho", "min"),
            max_delta=("delta_rho", "max"),
            bonferroni_ci_excludes_zero_seeds=(
                "bootstrap_ci_excludes_zero_bonferroni",
                "sum",
            ),
            median_ci_lower=(
                "bootstrap_ci_lower_bonferroni",
                "median",
            ),
            median_ci_upper=(
                "bootstrap_ci_upper_bonferroni",
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
        / "control_band_bonferroni_bootstrap_summary.csv"
    )

    summary.to_csv(
        summary_output,
        index=False,
    )

    print("\nCompleted.")
    print("Saved:", by_seed_output)
    print("Saved:", summary_output)
    print("Rows:", len(results_df))
    print(
        "Bonferroni family size per seed:",
        FAMILY_SIZE,
    )
    print(
        "Bonferroni-adjusted CI level:",
        f"{100 * (1 - ADJUSTED_ALPHA):.4f}%",
    )


if __name__ == "__main__":
    main()
