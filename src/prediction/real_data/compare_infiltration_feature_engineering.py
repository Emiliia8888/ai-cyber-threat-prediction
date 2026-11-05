
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from xgboost import XGBClassifier
from catboost import CatBoostClassifier


DATA_DIR = Path.home() / "Desktop" / "CSE-CIC-IDS2018"
OUTPUT_DIR = Path("reports/behavior_relabeling_v2")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

FILES = {
    "Infil1": DATA_DIR / "Infil1-Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet",
    "Infil2": DATA_DIR / "Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet",
}

SAMPLE_PER_CLASS = 20_000
N_SPLITS = 5
RANDOM_STATE = 42

EXCLUDED_COLUMNS = {
    "Protocol", "Label", "target", "scenario", "role",
    "timestamp", "Timestamp", "Flow ID",
}


def safe_divide(a, b):
    """Division that handles zero denominators and invalid values."""
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)

    result = np.divide(
        a,
        b,
        out=np.full_like(a, np.nan, dtype=float),
        where=np.abs(b) > 1e-12,
    )

    result[~np.isfinite(result)] = np.nan
    return result


def add_engineered_features(X):
    """Create additional flow-behavior features without using labels."""

    X = X.copy()

    # Packet count ratios and asymmetry
    if {"Total Fwd Packets", "Total Backward Packets"}.issubset(X.columns):
        fwd = X["Total Fwd Packets"].to_numpy(dtype=float)
        bwd = X["Total Backward Packets"].to_numpy(dtype=float)

        X["FE_packet_count_ratio"] = safe_divide(fwd, bwd + 1)
        X["FE_packet_count_asymmetry"] = safe_divide(
            fwd - bwd, fwd + bwd
        )

    # Packet byte volume ratios and asymmetry
    if {
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
    }.issubset(X.columns):
        fwd_bytes = X["Total Length of Fwd Packets"].to_numpy(dtype=float)
        bwd_bytes = X["Total Length of Bwd Packets"].to_numpy(dtype=float)

        X["FE_byte_ratio"] = safe_divide(fwd_bytes, bwd_bytes + 1)
        X["FE_byte_asymmetry"] = safe_divide(
            fwd_bytes - bwd_bytes,
            fwd_bytes + bwd_bytes,
        )

    # Average packet size in both directions
    if {
        "Total Length of Fwd Packets",
        "Total Fwd Packets",
    }.issubset(X.columns):
        X["FE_fwd_avg_packet_size"] = safe_divide(
            X["Total Length of Fwd Packets"],
            X["Total Fwd Packets"],
        )

    if {
        "Total Length of Bwd Packets",
        "Total Backward Packets",
    }.issubset(X.columns):
        X["FE_bwd_avg_packet_size"] = safe_divide(
            X["Total Length of Bwd Packets"],
            X["Total Backward Packets"],
        )

    # Directional packet length comparison
    if {
        "Fwd Packet Length Mean",
        "Bwd Packet Length Mean",
    }.issubset(X.columns):
        fwd_mean = X["Fwd Packet Length Mean"].to_numpy(dtype=float)
        bwd_mean = X["Bwd Packet Length Mean"].to_numpy(dtype=float)

        X["FE_packet_length_ratio"] = safe_divide(
            fwd_mean, bwd_mean + 1
        )
        X["FE_packet_length_asymmetry"] = safe_divide(
            fwd_mean - bwd_mean,
            fwd_mean + bwd_mean,
        )

    # Directional packet rate comparison
    if {
        "Fwd Packets/s",
        "Bwd Packets/s",
    }.issubset(X.columns):
        fwd_rate = X["Fwd Packets/s"].to_numpy(dtype=float)
        bwd_rate = X["Bwd Packets/s"].to_numpy(dtype=float)

        X["FE_packet_rate_ratio"] = safe_divide(
            fwd_rate, bwd_rate + 1e-6
        )
        X["FE_packet_rate_asymmetry"] = safe_divide(
            fwd_rate - bwd_rate,
            fwd_rate + bwd_rate,
        )

    # Flow throughput consistency
    if {
        "Flow Bytes/s",
        "Flow Packets/s",
    }.issubset(X.columns):
        X["FE_bytes_per_packet"] = safe_divide(
            X["Flow Bytes/s"],
            X["Flow Packets/s"],
        )

    # Inter-arrival-time comparisons
    if {
        "Fwd IAT Mean",
        "Bwd IAT Mean",
    }.issubset(X.columns):
        fwd_iat = X["Fwd IAT Mean"].to_numpy(dtype=float)
        bwd_iat = X["Bwd IAT Mean"].to_numpy(dtype=float)

        X["FE_iat_mean_ratio"] = safe_divide(
            fwd_iat, bwd_iat + 1e-6
        )
        X["FE_iat_mean_asymmetry"] = safe_divide(
            fwd_iat - bwd_iat,
            fwd_iat + bwd_iat,
        )

    # Active/Idle behavior
    if {"Active Mean", "Idle Mean"}.issubset(X.columns):
        active = X["Active Mean"].to_numpy(dtype=float)
        idle = X["Idle Mean"].to_numpy(dtype=float)

        X["FE_active_idle_ratio"] = safe_divide(
            active, idle + 1
        )
        X["FE_active_idle_asymmetry"] = safe_divide(
            active - idle, active + idle
        )

    # Flow duration versus packet count
    if {"Flow Duration", "Total Fwd Packets", "Total Backward Packets"}.issubset(X.columns):
        duration = X["Flow Duration"].to_numpy(dtype=float)
        total_packets = (
            X["Total Fwd Packets"].to_numpy(dtype=float)
            + X["Total Backward Packets"].to_numpy(dtype=float)
        )

        X["FE_packets_per_duration"] = safe_divide(
            total_packets, duration
        )

    # Remove infinities; imputation will be fitted on training data only.
    X = X.replace([np.inf, -np.inf], np.nan)

    return X


def load_scenario(path):
    df = pd.read_parquet(path)

    labels = df["Label"].astype(str).str.strip().str.lower()

    udp_mask = df["Protocol"].eq(17)
    df = df.loc[udp_mask].copy()
    labels = labels.loc[df.index]

    df["target"] = labels.map({
        "benign": 0,
        "infilteration": 1,
        "infiltration": 1,
    })

    df = df.loc[df["target"].notna()].copy()
    df["target"] = df["target"].astype(int)

    numeric_columns = [
        col for col in df.select_dtypes(include=np.number).columns
        if col not in EXCLUDED_COLUMNS
    ]

    sampled = pd.concat(
        [
            group.sample(
                n=min(len(group), SAMPLE_PER_CLASS),
                random_state=RANDOM_STATE,
            )
            for _, group in df.groupby("target")
        ],
        ignore_index=True,
    )

    X_base = sampled[numeric_columns].replace(
        [np.inf, -np.inf], np.nan
    )

    X_engineered = add_engineered_features(X_base)

    y = sampled["target"].to_numpy()

    # Grouping is based on original features, before engineering.
    groups = pd.util.hash_pandas_object(
        X_base, index=False
    ).to_numpy()

    return X_base, X_engineered, y, groups


def build_models():
    return {
        "XGBoost": XGBClassifier(
            n_estimators=250,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=RANDOM_STATE,
            n_jobs=4,
            tree_method="hist",
        ),

        "CatBoost": CatBoostClassifier(
            iterations=500,
            depth=6,
            learning_rate=0.05,
            loss_function="Logloss",
            eval_metric="AUC",
            random_seed=RANDOM_STATE,
            verbose=False,
            allow_writing_files=False,
            thread_count=4,
            l2_leaf_reg=5,
        ),
    }


def calculate_metrics(y_true, probabilities):
    predictions = (probabilities >= 0.5).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()

    return {
        "accuracy": accuracy_score(y_true, predictions),
        "f1": f1_score(y_true, predictions, zero_division=0),
        "precision": precision_score(
            y_true, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_true, predictions, zero_division=0
        ),
        "fpr": fp / (fp + tn) if (fp + tn) else np.nan,
        "roc_auc": roc_auc_score(y_true, probabilities),
        "pr_auc": average_precision_score(y_true, probabilities),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def main():
    all_results = []

    for scenario, path in FILES.items():
        print(f"\n{'=' * 75}")
        print(f"SCENARIO: {scenario}")
        print(f"{'=' * 75}")

        X_base, X_engineered, y, groups = load_scenario(path)

        print(f"Rows: {len(X_base):,}")
        print(f"Baseline features: {X_base.shape[1]}")
        print(f"Engineered features: {X_engineered.shape[1]}")
        print(f"New features: {X_engineered.shape[1] - X_base.shape[1]}")

        splitter = GroupShuffleSplit(
            n_splits=N_SPLITS,
            test_size=0.20,
            random_state=RANDOM_STATE,
        )

        splits = list(splitter.split(X_base, y, groups))

        for split_number, (train_idx, val_idx) in enumerate(
            splits, start=1
        ):
            y_train = y[train_idx]
            y_val = y[val_idx]

            print(
                f"\nSplit {split_number}/{N_SPLITS}: "
                f"train={len(train_idx):,}, "
                f"validation={len(val_idx):,}"
            )

            for feature_set_name, X in [
                ("Baseline_76", X_base),
                ("Engineered", X_engineered),
            ]:
                X_train = X.iloc[train_idx]
                X_val = X.iloc[val_idx]

                imputer = SimpleImputer(
                    strategy="median",
                    keep_empty_features=True,
                )

                X_train_imp = imputer.fit_transform(X_train)
                X_val_imp = imputer.transform(X_val)

                for model_name, model in build_models().items():
                    print(
                        f"  {feature_set_name} | {model_name}",
                        flush=True,
                    )

                    model.fit(X_train_imp, y_train)

                    probabilities = model.predict_proba(
                        X_val_imp
                    )[:, 1]

                    metrics = calculate_metrics(
                        y_val, probabilities
                    )

                    all_results.append({
                        "scenario": scenario,
                        "split": split_number,
                        "feature_set": feature_set_name,
                        "model": model_name,
                        **metrics,
                    })

                    print(
                        f"    AUC={metrics['roc_auc']:.4f} | "
                        f"AP={metrics['pr_auc']:.4f} | "
                        f"F1={metrics['f1']:.4f} | "
                        f"Recall={metrics['recall']:.4f} | "
                        f"FPR={metrics['fpr']:.4f}"
                    )

    details = pd.DataFrame(all_results)

    details_path = (
        OUTPUT_DIR / "infiltration_feature_engineering_details.csv"
    )
    details.to_csv(details_path, index=False)

    metric_columns = [
        "accuracy", "f1", "precision", "recall",
        "fpr", "roc_auc", "pr_auc",
    ]

    summary = (
        details.groupby(
            ["scenario", "feature_set", "model"]
        )[metric_columns]
        .agg(["mean", "std"])
        .reset_index()
    )

    summary_path = (
        OUTPUT_DIR / "infiltration_feature_engineering_summary.csv"
    )
    summary.to_csv(summary_path, index=False)

    print("\n" + "=" * 75)
    print("FINAL FEATURE ENGINEERING COMPARISON")
    print("=" * 75)

    for scenario in FILES:
        print(f"\n{scenario}:")

        result = (
            details[details["scenario"] == scenario]
            .groupby(["feature_set", "model"])[metric_columns]
            .mean()
            .sort_values("roc_auc", ascending=False)
        )

        print(result.round(4).to_string())

    print("\nSaved:")
    print(details_path)
    print(summary_path)


if __name__ == "__main__":
    main()
