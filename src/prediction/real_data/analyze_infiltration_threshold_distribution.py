from pathlib import Path
import sys

import numpy as np
import pandas as pd

from sklearn.base import clone
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent),
)

from evaluate_tcp_sampling_stability import (
    SAMPLE_SEEDS,
    FILES,
    load_tcp_sample,
)

from compare_infiltration_feature_engineering import build_models

from analyze_infiltration_fp_control_correlations import (
    VARIANTS,
    DIRECTION,
    remove_exact_overlaps,
    filter_labels,
    get_attack_probability,
)


ROOT = Path(__file__).resolve().parents[3]

OUTPUT_DIR = (
    ROOT
    / "reports"
    / "behavior_relabeling_v2"
    / "threshold_distribution_analysis"
)

FP_OLD = 0.90
FP_NEW = 0.95

CONTROL_OLD = 0.50
CONTROL_NEW = 0.30


def describe_group(X, mask, seed, variant, group, threshold):
    selected = X.loc[mask]
    rows = []

    for feature in selected.columns:
        values = (
            pd.to_numeric(selected[feature], errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .dropna()
        )

        if len(values) == 0:
            continue

        rows.append({
            "seed": seed,
            "variant": variant,
            "group": group,
            "threshold": threshold,
            "feature": feature,
            "n": len(values),
            "median": values.median(),
            "q25": values.quantile(0.25),
            "q75": values.quantile(0.75),
            "iqr": (
                values.quantile(0.75)
                - values.quantile(0.25)
            ),
            "mean": values.mean(),
            "std": values.std(),
        })

    return rows


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    source_name, target_name = DIRECTION

    source_path = FILES[source_name]
    target_path = FILES[target_name]

    model_template = build_models()["XGBoost"]

    rows = []

    print("=" * 80)
    print("THRESHOLD GROUP FEATURE DISTRIBUTION ANALYSIS")
    print("=" * 80)

    for seed in SAMPLE_SEEDS:
        print(f"\nSeed: {seed}")

        X_source, y_source = load_tcp_sample(
            source_path, seed
        )

        X_target, y_target = load_tcp_sample(
            target_path, seed
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

        benign_mask = np.asarray(y_target) == 0

        for variant in VARIANTS:
            print(f"  Variant: {variant}")

            if variant == "baseline_all_76":
                features = list(X_train.columns)

            elif variant == "without_flow_iat_min":
                features = [
                    c for c in X_train.columns
                    if c != "Flow IAT Min"
                ]

            else:
                raise ValueError(variant)

            model = clone(model_template)

            model.fit(
                X_train_imp[features],
                y_train,
            )

            scores = get_attack_probability(
                model,
                X_target_imp[features],
            )

            masks = {
                "FP_original": (
                    benign_mask & (scores >= FP_OLD)
                ),
                "FP_sensitivity": (
                    benign_mask & (scores >= FP_NEW)
                ),
                "Control_original": (
                    benign_mask & (scores < CONTROL_OLD)
                ),
                "Control_sensitivity": (
                    benign_mask & (scores < CONTROL_NEW)
                ),
            }

            for group_name, mask in masks.items():
                rows.extend(
                    describe_group(
                        X_target,
                        mask,
                        seed,
                        variant,
                        group_name,
                        (
                            FP_OLD
                            if group_name == "FP_original"
                            else FP_NEW
                            if group_name == "FP_sensitivity"
                            else CONTROL_OLD
                            if group_name == "Control_original"
                            else CONTROL_NEW
                        ),
                    )
                )

            print(
                f"    FP: "
                f"{masks['FP_original'].sum()} -> "
                f"{masks['FP_sensitivity'].sum()}"
            )

            print(
                f"    Control: "
                f"{masks['Control_original'].sum()} -> "
                f"{masks['Control_sensitivity'].sum()}"
            )

    df = pd.DataFrame(rows)

    output = OUTPUT_DIR / "feature_distribution_summary.csv"

    df.to_csv(output, index=False)

    print("\nSaved:", output)
    print("Rows:", len(df))
    print("Unique features:", df["feature"].nunique())


if __name__ == "__main__":
    main()
