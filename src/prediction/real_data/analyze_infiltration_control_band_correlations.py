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
    FEATURE_PAIRS,
    remove_exact_overlaps,
    filter_labels,
    get_attack_probability,
    safe_spearman,
)


ROOT = Path(__file__).resolve().parents[3]

OUTPUT_DIR = (
    ROOT
    / "reports"
    / "behavior_relabeling_v2"
    / "threshold_distribution_analysis"
)

GROUPS = {
    "retained_below_030": lambda s: s < 0.30,
    "removed_030_to_050": lambda s: (s >= 0.30) & (s < 0.50),
    "original_below_050": lambda s: s < 0.50,
}


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    source_name, target_name = DIRECTION
    model_template = build_models()["XGBoost"]

    rows = []

    for seed in SAMPLE_SEEDS:
        print(f"\nSeed: {seed}")

        X_source, y_source = load_tcp_sample(
            FILES[source_name], seed
        )

        X_target, y_target = load_tcp_sample(
            FILES[target_name], seed
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

        for variant in VARIANTS:
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

            print(f"  {variant}")

            for group_name, threshold_mask in GROUPS.items():
                mask = benign & threshold_mask(scores)
                X_group = X_target.loc[mask]

                print(
                    f"    {group_name}: {len(X_group)}"
                )

                for feature_a, feature_b in FEATURE_PAIRS:
                    if (
                        feature_a not in X_group.columns
                        or feature_b not in X_group.columns
                    ):
                        continue

                    rho, p_value, n = safe_spearman(
                        X_group[feature_a],
                        X_group[feature_b],
                    )

                    rows.append({
                        "seed": seed,
                        "variant": variant,
                        "group": group_name,
                        "feature_a": feature_a,
                        "feature_b": feature_b,
                        "rho": rho,
                        "p_value": p_value,
                        "n": n,
                    })

    result = pd.DataFrame(rows)

    output = (
        OUTPUT_DIR
        / "control_band_correlations_by_seed.csv"
    )

    result.to_csv(output, index=False)

    summary = (
        result
        .groupby([
            "variant",
            "group",
            "feature_a",
            "feature_b",
        ])
        .agg(
            median_rho=("rho", "median"),
            min_rho=("rho", "min"),
            max_rho=("rho", "max"),
            positive_seeds=("rho", lambda x: (x > 0).sum()),
            negative_seeds=("rho", lambda x: (x < 0).sum()),
            median_n=("n", "median"),
        )
        .reset_index()
    )

    summary_output = (
        OUTPUT_DIR
        / "control_band_correlations_summary.csv"
    )

    summary.to_csv(summary_output, index=False)

    print("\nSaved:", output)
    print("Saved:", summary_output)
    print("Rows:", len(result))


if __name__ == "__main__":
    main()
