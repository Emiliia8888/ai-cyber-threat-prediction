from pathlib import Path

import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.compose import ColumnTransformer
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
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

DATA_DIR = Path.home() / "Desktop" / "CIC-IDS2017"
REPORT_DIR = Path("reports")
SEED = 42
CAP = 10_000


def load_file(filename):
    print(f"Loading {filename}...", flush=True)
    df = pd.read_parquet(DATA_DIR / filename)
    df.columns = df.columns.str.strip()
    df["Label"] = (
        df["Label"].astype(str).str.strip()
        .str.replace(r"\s+", " ", regex=True)
    )
    return df


def sample_per_label(df, cap=CAP, seed=SEED):
    parts = []
    for _, group in df.groupby("Label", sort=False):
        parts.append(
            group.sample(n=min(len(group), cap), random_state=seed)
        )
    return pd.concat(parts, ignore_index=True)


def clean_pair(train_df, other_df):
    X_train = train_df.drop(columns=["Label"]).copy()
    X_other = other_df.drop(columns=["Label"]).copy()
    X_other = X_other.reindex(columns=X_train.columns)

    X_train = X_train.replace([np.inf, -np.inf], np.nan)
    X_other = X_other.replace([np.inf, -np.inf], np.nan)

    non_negative = [
        "Fwd Header Length", "Fwd Seg Size Min", "Bwd Header Length",
        "Flow Duration", "Flow Packets/s", "Flow Bytes/s", "Fwd IAT Min",
    ]
    for col in non_negative:
        if col in X_train.columns:
            X_train.loc[X_train[col] < 0, col] = np.nan
            X_other.loc[X_other[col] < 0, col] = np.nan

    return X_train, X_other


def main():
    # Baseline training data: Monday to Wednesday.
    base_parts = []
    for filename in [
        "Benign-Monday-no-metadata.parquet",
        "Bruteforce-Tuesday-no-metadata.parquet",
        "DoS-Wednesday-no-metadata.parquet",
    ]:
        base_parts.append(load_file(filename))

    base_train = pd.concat(
        [sample_per_label(df) for df in base_parts],
        ignore_index=True,
    )

    # Split Friday Botnet file by label so neither Bot nor Benign
    # holdout rows are included in training.
    botnet_df = load_file("Botnet-Friday-no-metadata.parquet")
    botnet_train, botnet_holdout = train_test_split(
        botnet_df,
        test_size=0.30,
        random_state=SEED,
        stratify=botnet_df["Label"],
    )

    # Limit Friday Benign samples to keep the experiment manageable.
    botnet_train = sample_per_label(botnet_train)
    botnet_holdout = sample_per_label(botnet_holdout)

    train = pd.concat(
        [base_train, botnet_train],
        ignore_index=True,
    )

    # Separate held-out Botnet-file rows from other Friday attack families.
    ddos = sample_per_label(load_file("DDoS-Friday-no-metadata.parquet"))
    portscan = sample_per_label(load_file("Portscan-Friday-no-metadata.parquet"))

    test = pd.concat(
        [botnet_holdout, ddos, portscan],
        ignore_index=True,
    )

    y_train = (train["Label"] != "Benign").astype("int8")
    y_test = (test["Label"] != "Benign").astype("int8")

    print("\n=== DATA SPLIT ===")
    print("Training rows:", len(train))
    print("Test rows:", len(test))
    print("\nTraining labels:")
    print(train["Label"].value_counts().to_string())
    print("\nTest labels:")
    print(test["Label"].value_counts().to_string())

    X_train_df, X_test_df = clean_pair(train, test)

    categorical = X_train_df.select_dtypes(
        include=["object", "category", "bool"]
    ).columns.tolist()
    numeric = [c for c in X_train_df.columns if c not in categorical]

    transformers = []
    if numeric:
        transformers.append((
            "numeric",
            Pipeline([("imputer", SimpleImputer(strategy="median"))]),
            numeric,
        ))
    if categorical:
        transformers.append((
            "categorical",
            Pipeline([
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("onehot", OneHotEncoder(handle_unknown="ignore")),
            ]),
            categorical,
        ))

    prep = ColumnTransformer(transformers=transformers)
    X_train = prep.fit_transform(X_train_df)
    X_test = prep.transform(X_test_df)

    weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        scale_pos_weight=weight,
        random_state=SEED,
        n_jobs=-1,
        tree_method="hist",
    )

    print("\nTraining experimental model...", flush=True)
    model.fit(X_train, y_train)
    probabilities = model.predict_proba(X_test)[:, 1]

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Report per-family performance at two thresholds.
    labels = test["Label"].astype(str).to_numpy()
    family_rows = []

    for label in sorted(np.unique(labels)):
        mask = labels == label
        actual = y_test.to_numpy()[mask]
        p = probabilities[mask]

        row = {
            "label": label,
            "n": int(mask.sum()),
            "mean_probability": float(p.mean()),
            "median_probability": float(np.median(p)),
            "p90_probability": float(np.quantile(p, 0.90)),
        }

        for threshold in [0.001, 0.01, 0.05, 0.20, 0.50]:
            row[f"detected_pct_at_{threshold}"] = float(
                100 * np.mean(p >= threshold)
            )

        if len(np.unique(actual)) == 2:
            row["roc_auc"] = float(roc_auc_score(actual, p))
            row["average_precision"] = float(
                average_precision_score(actual, p)
            )

        family_rows.append(row)

    family_report = pd.DataFrame(family_rows)
    family_path = REPORT_DIR / "cic_botnet_training_experiment_families.csv"
    family_report.to_csv(family_path, index=False)

    # Overall results at the fixed 0.5 threshold.
    pred = (probabilities >= 0.5).astype("int8")
    tn, fp, fn, tp = confusion_matrix(
        y_test, pred, labels=[0, 1]
    ).ravel()

    summary = pd.DataFrame([{
        "train_rows": len(train),
        "test_rows": len(test),
        "accuracy_at_0.5": accuracy_score(y_test, pred),
        "macro_f1_at_0.5": f1_score(
            y_test, pred, average="macro", zero_division=0
        ),
        "attack_precision_at_0.5": precision_score(
            y_test, pred, zero_division=0
        ),
        "attack_recall_at_0.5": recall_score(
            y_test, pred, zero_division=0
        ),
        "roc_auc": roc_auc_score(y_test, probabilities),
        "average_precision": average_precision_score(
            y_test, probabilities
        ),
        "TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp),
    }])

    summary_path = REPORT_DIR / "cic_botnet_training_experiment_summary.csv"
    summary.to_csv(summary_path, index=False)

    print("\n=== FAMILY RESULTS ===")
    print(family_report.to_string(index=False))
    print("\n=== OVERALL RESULTS AT THRESHOLD 0.5 ===")
    print(summary.to_string(index=False))
    print("\nSaved reports:")
    print(family_path)
    print(summary_path)


if __name__ == "__main__":
    main()
