
from pathlib import Path
import warnings

import numpy as np
import pandas as pd

from scipy.stats import spearmanr
from sklearn.base import clone
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split

from evaluate_tcp_sampling_stability import (
    SAMPLE_SEEDS,
    FILES,
    load_tcp_sample,
)
from compare_infiltration_feature_engineering import build_models


warnings.filterwarnings("ignore", category=RuntimeWarning)

ROOT = Path(__file__).resolve().parents[3]

OUTPUT_DIR = (
    ROOT
    / "reports"
    / "behavior_relabeling_v2"
    / "fp_control_correlations"
)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

FP_THRESHOLD = 0.90
CONTROL_THRESHOLD = 0.50

VARIANTS = [
    "baseline_all_76",
    "without_flow_iat_min",
]

DIRECTION = ("Infil2", "Infil1")

# Пари обрані на основі попереднього аналізу.
FEATURE_PAIRS = [
    ("Fwd IAT Min", "Fwd IAT Std"),
    ("Fwd IAT Min", "Fwd IAT Total"),
    ("Fwd IAT Min", "Fwd IAT Max"),
    ("Fwd IAT Std", "Fwd IAT Total"),
    ("Fwd IAT Std", "Fwd IAT Max"),
    ("Fwd IAT Total", "Fwd IAT Max"),
    ("Bwd Packets/s", "Flow Packets/s"),
    ("Bwd Packets/s", "Flow Bytes/s"),
    ("Flow Bytes/s", "Flow Packets/s"),
    ("Bwd Packets/s", "Fwd IAT Min"),
    ("Bwd IAT Min", "Bwd IAT Max"),
    ("Bwd IAT Min", "Bwd IAT Total"),
]

LABEL_COLUMN = "Label"


def remove_exact_overlaps(X_source, X_target):
    source_hashes = pd.util.hash_pandas_object(
        X_source,
        index=False,
    )

    target_hashes = pd.util.hash_pandas_object(
        X_target,
        index=False,
    )

    overlap_hashes = set(source_hashes).intersection(
        set(target_hashes)
    )

    source_keep_mask = (
        ~source_hashes.isin(overlap_hashes)
    ).to_numpy()

    target_keep_mask = (
        ~target_hashes.isin(overlap_hashes)
    ).to_numpy()

    X_source_filtered = X_source.iloc[
        np.flatnonzero(source_keep_mask)
    ].copy()

    X_target_filtered = X_target.iloc[
        np.flatnonzero(target_keep_mask)
    ].copy()

    return (
        X_source_filtered,
        X_target_filtered,
        int(len(overlap_hashes)),
        source_keep_mask,
        target_keep_mask,
    )

def filter_labels(y, keep_mask):
    if isinstance(y, pd.Series):
        return y.iloc[
            np.flatnonzero(keep_mask)
        ].to_numpy()

    return np.asarray(y)[keep_mask]

def get_attack_probability(model, X):
    probabilities = model.predict_proba(X)

    classes = list(model.classes_)

    attack_index = classes.index(1)

    return probabilities[:, attack_index]


def safe_spearman(x, y):
    x = pd.Series(x).replace(
        [np.inf, -np.inf],
        np.nan,
    )

    y = pd.Series(y).replace(
        [np.inf, -np.inf],
        np.nan,
    )

    valid = x.notna() & y.notna()

    x = x.loc[valid]
    y = y.loc[valid]

    if len(x) < 10:
        return np.nan, np.nan, len(x)

    if x.nunique() < 2 or y.nunique() < 2:
        return np.nan, np.nan, len(x)

    result = spearmanr(x, y)

    return (
        float(result.statistic),
        float(result.pvalue),
        int(len(x)),
    )


def calculate_correlations(
    X,
    group_name,
    seed,
    variant,
):
    rows = []

    for feature_a, feature_b in FEATURE_PAIRS:

        if (
            feature_a not in X.columns
            or feature_b not in X.columns
        ):
            continue

        rho, p_value, n = safe_spearman(
            X[feature_a],
            X[feature_b],
        )

        rows.append({
            "seed": seed,
            "variant": variant,
            "group": group_name,
            "feature_a": feature_a,
            "feature_b": feature_b,
            "spearman_rho": rho,
            "p_value": p_value,
            "n": n,
        })

    return rows


def main():

    source_name, target_name = DIRECTION

    source_path = FILES[source_name]
    target_path = FILES[target_name]

    model_template = build_models()["XGBoost"]

    all_rows = []
    group_metrics = []

    print("=" * 100)
    print("CONFIDENT FP VS BENIGN CONTROL: CORRELATION ANALYSIS")
    print("=" * 100)

    print(f"\nDirection: {source_name} -> {target_name}")
    print(f"Seeds: {SAMPLE_SEEDS}")
    print(f"Variants: {VARIANTS}")
    print(f"Feature pairs: {len(FEATURE_PAIRS)}")

    for seed in SAMPLE_SEEDS:

        print(f"\nSampling seed: {seed}")

        X_source, y_source = load_tcp_sample(
            source_path,
            seed,
        )

        X_target, y_target = load_tcp_sample(
            target_path,
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
        
        assert len(X_source) == len(y_source), (
        f"Source mismatch: X={len(X_source)}, y={len(y_source)}"
        )
        
        assert len(X_target) == len(y_target), (
        f"Target mismatch: X={len(X_target)}, y={len(y_target)}"
        )
        print(
            f"After overlap removal: "
            f"source={len(X_source)}, target={len(X_target)}, "
            f"overlaps={overlap_count}"
        )

        X_train, X_validation, y_train, y_validation = (
            train_test_split(
                X_source,
                y_source,
                test_size=0.20,
                random_state=42,
                stratify=y_source,
            )
        )

        # Fit imputer only on source training data.
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

        for variant in VARIANTS:

            print(f"\n  Variant: {variant}")

            if variant == "baseline_all_76":
                selected_features = list(X_train.columns)

            elif variant == "without_flow_iat_min":
                selected_features = [
                    c for c in X_train.columns
                    if c != "Flow IAT Min"
                ]

            else:
                raise ValueError(f"Unknown variant: {variant}")

            model = clone(model_template)

            model.fit(
                X_train_imp[selected_features],
                y_train,
            )

            scores = get_attack_probability(
                model,
                X_target_imp[selected_features],
            )

            target_labels = np.asarray(y_target)

            # True Benign target flows only.
            benign_mask = target_labels == 0

            fp_mask = (
                benign_mask
                & (scores >= FP_THRESHOLD)
            )

            control_mask = (
                benign_mask
                & (scores < CONTROL_THRESHOLD)
            )

            X_fp = X_target.loc[fp_mask].copy()
            X_control = X_target.loc[control_mask].copy()

            print(
                f"    FP={len(X_fp)}, "
                f"Control={len(X_control)}"
            )

            group_metrics.append({
                "seed": seed,
                "variant": variant,
                "fp_count": len(X_fp),
                "control_count": len(X_control),
                "fp_threshold": FP_THRESHOLD,
                "control_threshold": CONTROL_THRESHOLD,
            })

            all_rows.extend(
                calculate_correlations(
                    X_fp,
                    "confident_fp",
                    seed,
                    variant,
                )
            )

            all_rows.extend(
                calculate_correlations(
                    X_control,
                    "benign_control",
                    seed,
                    variant,
                )
            )

    details = pd.DataFrame(all_rows)
    metrics = pd.DataFrame(group_metrics)

    details_path = OUTPUT_DIR / "correlation_details.csv"
    metrics_path = OUTPUT_DIR / "group_metrics.csv"

    details.to_csv(details_path, index=False)
    metrics.to_csv(metrics_path, index=False)

    # Compare correlation coefficients between FP and Control.
    comparison_rows = []

    grouped = details.groupby(
        ["seed", "variant", "feature_a", "feature_b"]
    )

    for (seed, variant, feature_a, feature_b), group in grouped:

        fp = group[group["group"] == "confident_fp"]
        control = group[group["group"] == "benign_control"]

        if fp.empty or control.empty:
            continue

        rho_fp = fp.iloc[0]["spearman_rho"]
        rho_control = control.iloc[0]["spearman_rho"]

        comparison_rows.append({
            "seed": seed,
            "variant": variant,
            "feature_a": feature_a,
            "feature_b": feature_b,
            "rho_fp": rho_fp,
            "rho_control": rho_control,
            "rho_difference_fp_minus_control": (
                rho_fp - rho_control
                if pd.notna(rho_fp) and pd.notna(rho_control)
                else np.nan
            ),
            "n_fp": fp.iloc[0]["n"],
            "n_control": control.iloc[0]["n"],
        })

    comparison = pd.DataFrame(comparison_rows)

    comparison_path = (
        OUTPUT_DIR / "correlation_group_comparison.csv"
    )

    comparison.to_csv(comparison_path, index=False)

    # Summary across sampling seeds.
    summary = (
        comparison.groupby(
            ["variant", "feature_a", "feature_b"]
        )
        .agg(
            seeds=("seed", "nunique"),
            median_rho_fp=("rho_fp", "median"),
            median_rho_control=("rho_control", "median"),
            median_rho_difference=(
                "rho_difference_fp_minus_control",
                "median",
            ),
            positive_difference_seeds=(
                "rho_difference_fp_minus_control",
                lambda x: int((x > 0).sum()),
            ),
            negative_difference_seeds=(
                "rho_difference_fp_minus_control",
                lambda x: int((x < 0).sum()),
            ),
        )
        .reset_index()
    )

    summary_path = (
        OUTPUT_DIR / "correlation_summary.csv"
    )

    summary.to_csv(summary_path, index=False)

    print("\n" + "=" * 100)
    print("CORRELATION SUMMARY")
    print("=" * 100)

    if not summary.empty:
        print(
            summary.sort_values(
                ["variant", "median_rho_difference"],
                ascending=[True, False],
            ).to_string(index=False)
        )

    print("\n" + "=" * 100)
    print("GROUP COUNTS")
    print("=" * 100)

    print(metrics.to_string(index=False))

    print("\nOutput directory:")
    print(OUTPUT_DIR)

    print("\nFiles:")
    print(details_path.name)
    print(metrics_path.name)
    print(comparison_path.name)
    print(summary_path.name)

    print("\nExperiment completed.")


if __name__ == "__main__":
    main()
