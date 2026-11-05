
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score, average_precision_score

from compare_infiltration_feature_engineering import (
    FILES,
    SAMPLE_PER_CLASS,
    RANDOM_STATE,
    EXCLUDED_COLUMNS,
    build_models,
    OUTPUT_DIR,
)


# ============================================================
# CONFIGURATION
# ============================================================

SAMPLE_SEEDS = [42, 123, 2024, 7, 99]
MODEL_SEED = RANDOM_STATE
N_JOBS = 4

DETAILS_FILE = OUTPUT_DIR / "tcp_sampling_stability_details.csv"
SUMMARY_FILE = OUTPUT_DIR / "tcp_sampling_stability_summary.csv"


# ============================================================
# LOAD AND SAMPLE TCP DATA
# ============================================================

def load_tcp_sample(path, sample_seed):
    df = pd.read_parquet(path)

    labels = df["Label"].astype(str).str.strip().str.lower()

    # Keep TCP only.
    df = df.loc[df["Protocol"].eq(6)].copy()
    labels = labels.loc[df.index]

    df["target"] = labels.map({
        "benign": 0,
        "infilteration": 1,
        "infiltration": 1,
    })

    df = df.loc[df["target"].notna()].copy()
    df["target"] = df["target"].astype(int)

    excluded = set(EXCLUDED_COLUMNS) | {
        "target",
        "Label",
    }

    numeric_columns = [
        col
        for col in df.select_dtypes(include=np.number).columns
        if col not in excluded
    ]

    # Balanced sampling, with a different seed for each repetition.
    sampled_groups = []

    for class_label in [0, 1]:
        group = df.loc[df["target"] == class_label]

        n = min(len(group), SAMPLE_PER_CLASS)

        if n == 0:
            raise ValueError(
                f"No rows found for class {class_label} in {path}"
            )

        sampled_groups.append(
            group.sample(
                n=n,
                random_state=sample_seed,
            )
        )

    sampled = pd.concat(
        sampled_groups,
        ignore_index=True,
    )

    X = sampled[numeric_columns].replace(
        [np.inf, -np.inf],
        np.nan,
    ).reset_index(drop=True)

    y = sampled["target"].to_numpy(dtype=int)

    if len(X.columns) != 76:
        raise ValueError(
            f"Expected 76 TCP features, found {len(X.columns)}. "
            "Check EXCLUDED_COLUMNS and feature selection."
        )

    return X, y


# ============================================================
# FEATURE GROUPS
# ============================================================

def get_feature_groups(columns):
    timing_tokens = (
        "iat",
        "active",
        "idle",
        "flow duration",
    )

    timing_features = [
        col
        for col in columns
        if any(token in col.lower() for token in timing_tokens)
    ]

    without_timing = [
        col
        for col in columns
        if col not in timing_features
    ]

    return {
        "baseline_all_features": list(columns),
        "without_timing": without_timing,
    }


# ============================================================
# REMOVE EXACT SOURCE-TARGET OVERLAPS
# ============================================================

def remove_exact_overlaps(X_source, y_source, X_target):
    if list(X_source.columns) != list(X_target.columns):
        raise ValueError("Source and target features do not match")

    source_hashes = pd.util.hash_pandas_object(
        X_source,
        index=False,
    ).to_numpy()

    target_hashes = pd.util.hash_pandas_object(
        X_target,
        index=False,
    ).to_numpy()

    keep = ~np.isin(
        source_hashes,
        np.unique(target_hashes),
    )

    removed = int((~keep).sum())

    return (
        X_source.loc[keep].reset_index(drop=True),
        y_source[keep],
        removed,
    )


# ============================================================
# TRAIN AND PREDICT
# ============================================================

def fit_and_predict(X_train, y_train, X_test):
    imputer = SimpleImputer(strategy="median")

    X_train_imp = imputer.fit_transform(X_train)
    X_test_imp = imputer.transform(X_test)

    model = build_models()["XGBoost"]

    # Keep model randomness fixed.
    # Only the data sampling seed changes between repetitions.
    model.set_params(
        random_state=MODEL_SEED,
        n_jobs=N_JOBS,
    )

    model.fit(X_train_imp, y_train)

    return model.predict_proba(X_test_imp)[:, 1]


# ============================================================
# EVALUATE ONE TRANSFER DIRECTION
# ============================================================

def evaluate_direction(
    source_name,
    target_name,
    X_source,
    y_source,
    X_target,
    y_target,
    sample_seed,
):
    X_source, y_source, removed = remove_exact_overlaps(
        X_source,
        y_source,
        X_target,
    )

    groups = get_feature_groups(X_source.columns)

    predictions = {}

    for group_name, features in groups.items():
        predictions[group_name] = fit_and_predict(
            X_source[features],
            y_source,
            X_target[features],
        )

    baseline = predictions["baseline_all_features"]
    without_timing = predictions["without_timing"]

    baseline_roc = roc_auc_score(y_target, baseline)
    reduced_roc = roc_auc_score(y_target, without_timing)

    baseline_pr = average_precision_score(y_target, baseline)
    reduced_pr = average_precision_score(y_target, without_timing)

    return {
        "source": source_name,
        "target": target_name,
        "sample_seed": sample_seed,
        "model_seed": MODEL_SEED,
        "source_rows": len(X_source),
        "target_rows": len(X_target),
        "overlaps_removed": removed,

        "roc_auc_baseline": baseline_roc,
        "roc_auc_without_timing": reduced_roc,
        "roc_auc_difference": reduced_roc - baseline_roc,

        "pr_auc_baseline": baseline_pr,
        "pr_auc_without_timing": reduced_pr,
        "pr_auc_difference": reduced_pr - baseline_pr,
    }


# ============================================================
# MAIN
# ============================================================

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_results = []

    print("TCP SAMPLING STABILITY EXPERIMENT")
    print("=" * 75)
    print(f"Sampling seeds: {SAMPLE_SEEDS}")
    print(f"Model seed: {MODEL_SEED}")
    print(f"Samples per class: {SAMPLE_PER_CLASS:,}")

    for seed in SAMPLE_SEEDS:
        print("\n" + "=" * 75)
        print(f"SAMPLING SEED: {seed}")
        print("=" * 75)

        print("Loading Infil1 sample...")
        X1, y1 = load_tcp_sample(FILES["Infil1"], seed)

        print("Loading Infil2 sample...")
        X2, y2 = load_tcp_sample(FILES["Infil2"], seed)

        if list(X1.columns) != list(X2.columns):
            raise ValueError("Feature columns differ between scenarios")

        print(f"Infil1: {len(X1):,} rows")
        print(f"Infil2: {len(X2):,} rows")

        print("\nInfil1 -> Infil2")

        forward = evaluate_direction(
            "Infil1",
            "Infil2",
            X1,
            y1,
            X2,
            y2,
            seed,
        )

        print(
            f"ROC-AUC: {forward['roc_auc_baseline']:.4f} -> "
            f"{forward['roc_auc_without_timing']:.4f} "
            f"(difference {forward['roc_auc_difference']:+.4f})"
        )

        print(
            f"PR-AUC:  {forward['pr_auc_baseline']:.4f} -> "
            f"{forward['pr_auc_without_timing']:.4f} "
            f"(difference {forward['pr_auc_difference']:+.4f})"
        )

        all_results.append(forward)

        print("\nInfil2 -> Infil1")

        reverse = evaluate_direction(
            "Infil2",
            "Infil1",
            X2,
            y2,
            X1,
            y1,
            seed,
        )

        print(
            f"ROC-AUC: {reverse['roc_auc_baseline']:.4f} -> "
            f"{reverse['roc_auc_without_timing']:.4f} "
            f"(difference {reverse['roc_auc_difference']:+.4f})"
        )

        print(
            f"PR-AUC:  {reverse['pr_auc_baseline']:.4f} -> "
            f"{reverse['pr_auc_without_timing']:.4f} "
            f"(difference {reverse['pr_auc_difference']:+.4f})"
        )

        all_results.append(reverse)

    details = pd.DataFrame(all_results)
    details.to_csv(DETAILS_FILE, index=False)

    metric_columns = [
        "roc_auc_baseline",
        "roc_auc_without_timing",
        "roc_auc_difference",
        "pr_auc_baseline",
        "pr_auc_without_timing",
        "pr_auc_difference",
    ]

    summary = (
        details
        .groupby("source", as_index=False)[metric_columns]
        .agg(["mean", "std"])
    )

    summary.columns = [
        "_".join(str(part) for part in column if str(part))
        if isinstance(column, tuple)
        else str(column)
        for column in summary.columns
    ]

    summary.to_csv(SUMMARY_FILE, index=False)

    print("\n" + "=" * 100)
    print("SAMPLING STABILITY SUMMARY")
    print("=" * 100)

    print(
        summary.to_string(
            index=False,
            float_format=lambda value: f"{value:.4f}",
        )
    )

    print("\nSaved files:")
    print(DETAILS_FILE)
    print(SUMMARY_FILE)

    print("\nExperiment completed.")


if __name__ == "__main__":
    main()
