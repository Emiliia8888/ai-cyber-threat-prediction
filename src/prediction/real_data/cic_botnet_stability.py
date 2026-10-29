from pathlib import Path
import numpy as np
import pandas as pd

from xgboost import XGBClassifier
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

DATA_DIR = Path.home() / "Desktop" / "CIC-IDS2017"
REPORT_DIR = Path("reports")
CAP = 10_000
SEEDS = [7, 21, 42]


def load_file(filename):
    df = pd.read_parquet(DATA_DIR / filename)
    df.columns = df.columns.str.strip()
    df["Label"] = (
        df["Label"].astype(str).str.strip()
        .str.replace(r"\s+", " ", regex=True)
    )
    return df


def sample_per_label(df, cap, seed):
    parts = []
    for _, group in df.groupby("Label", sort=False):
        parts.append(
            group.sample(n=min(len(group), cap), random_state=seed)
        )
    return pd.concat(parts, ignore_index=True)


def clean_pair(train, test):
    X_train = train.drop(columns=["Label"]).copy()
    X_test = test.drop(columns=["Label"]).copy()
    X_test = X_test.reindex(columns=X_train.columns)

    X_train = X_train.replace([np.inf, -np.inf], np.nan)
    X_test = X_test.replace([np.inf, -np.inf], np.nan)

    non_negative = [
        "Fwd Header Length", "Fwd Seg Size Min", "Bwd Header Length",
        "Flow Duration", "Flow Packets/s", "Flow Bytes/s", "Fwd IAT Min",
    ]
    for col in non_negative:
        if col in X_train.columns:
            X_train.loc[X_train[col] < 0, col] = np.nan
            X_test.loc[X_test[col] < 0, col] = np.nan

    return X_train, X_test


def run_one(seed, base_parts, botnet_df, ddos_df, portscan_df):
    print(f"\n=== Seed {seed} ===", flush=True)

    base_train = pd.concat(
        [sample_per_label(df, CAP, seed) for df in base_parts],
        ignore_index=True,
    )

    bot_train, bot_test = train_test_split(
        botnet_df,
        test_size=0.30,
        random_state=seed,
        stratify=botnet_df["Label"],
    )

    bot_train = sample_per_label(bot_train, CAP, seed)
    bot_test = sample_per_label(bot_test, CAP, seed)

    train = pd.concat([base_train, bot_train], ignore_index=True)

    # Keep Friday DDoS and PortScan out of training.
    ddos = sample_per_label(ddos_df, CAP, seed)
    portscan = sample_per_label(portscan_df, CAP, seed)

    test = pd.concat([bot_test, ddos, portscan], ignore_index=True)

    y_train = (train["Label"] != "Benign").astype("int8")
    y_test = (test["Label"] != "Benign").astype("int8")

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
        random_state=seed,
        n_jobs=-1,
        tree_method="hist",
    )

    model.fit(X_train, y_train)
    probabilities = model.predict_proba(X_test)[:, 1]
    predicted = (probabilities >= 0.5).astype("int8")

    labels = test["Label"].astype(str).to_numpy()
    rows = []

    # Overall metrics.
    rows.append({
        "seed": seed,
        "label": "ALL",
        "n": len(test),
        "recall_at_0.5": recall_score(
            y_test, predicted, zero_division=0
        ),
        "precision_at_0.5": precision_score(
            y_test, predicted, zero_division=0
        ),
        "f1_at_0.5": f1_score(
            y_test, predicted, zero_division=0
        ),
        "accuracy_at_0.5": accuracy_score(y_test, predicted),
        "roc_auc": roc_auc_score(y_test, probabilities),
        "average_precision": average_precision_score(
            y_test, probabilities
        ),
    })

    for label in sorted(np.unique(labels)):
        mask = labels == label
        actual = y_test.to_numpy()[mask]
        p = probabilities[mask]
        pred = predicted[mask]

        rows.append({
            "seed": seed,
            "label": label,
            "n": int(mask.sum()),
            "recall_at_0.5": (
                float(np.mean(pred[actual == 1]))
                if np.any(actual == 1) else np.nan
            ),
            "false_positive_rate_at_0.5": (
                float(np.mean(pred[actual == 0]))
                if np.any(actual == 0) else np.nan
            ),
            "mean_probability": float(p.mean()),
            "median_probability": float(np.median(p)),
            "detected_pct_at_0.5": float(np.mean(p >= 0.5) * 100),
        })

    return rows


def main():
    print("Loading Monday-Wednesday training files...", flush=True)
    base_parts = [
        load_file("Benign-Monday-no-metadata.parquet"),
        load_file("Bruteforce-Tuesday-no-metadata.parquet"),
        load_file("DoS-Wednesday-no-metadata.parquet"),
    ]

    print("Loading Friday files...", flush=True)
    botnet_df = load_file("Botnet-Friday-no-metadata.parquet")
    ddos_df = load_file("DDoS-Friday-no-metadata.parquet")
    portscan_df = load_file("Portscan-Friday-no-metadata.parquet")

    all_rows = []
    for seed in SEEDS:
        all_rows.extend(
            run_one(seed, base_parts, botnet_df, ddos_df, portscan_df)
        )

    result = pd.DataFrame(all_rows)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / "cic_botnet_stability.csv"
    result.to_csv(out, index=False)

    print("\n=== STABILITY RESULTS ===")
    print(result.to_string(index=False))
    print(f"\nSaved: {out}")

    print("\n=== MEAN AND STANDARD DEVIATION BY LABEL ===")
    metrics = [
        "recall_at_0.5",
        "false_positive_rate_at_0.5",
        "accuracy_at_0.5",
        "roc_auc",
        "average_precision",
    ]
    available = [c for c in metrics if c in result.columns]
    summary = result.groupby("label")[available].agg(["mean", "std"])
    print(summary.to_string())


if __name__ == "__main__":
    main()
