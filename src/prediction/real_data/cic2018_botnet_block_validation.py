from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier

DATA_PATH = (
    Path.home()
    / "Desktop/CSE-CIC-IDS2018/"
    / "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet"
)

OUT_DIR = Path("reports/cic2018_block_validation")
OUT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading CIC-IDS2018...")
df = pd.read_parquet(DATA_PATH).reset_index(drop=True)
df = df[df["Label"].isin(["Benign", "Bot"])].reset_index(drop=True)

# Fixed contiguous split based on the observed label distribution.
train_df = df.iloc[:192896].copy()
test_df = df.iloc[192896:231476].copy()

print("\n=== BLOCK SPLIT ===")
print("Train:", len(train_df))
print(train_df["Label"].value_counts().to_dict())
print("Test:", len(test_df))
print(test_df["Label"].value_counts().to_dict())

X_train = train_df.drop(columns=["Label"])
X_test = test_df.drop(columns=["Label"])

y_train = train_df["Label"].eq("Bot").astype(int)
y_test = test_df["Label"].eq("Bot").astype(int)

# Apply the same negative-value cleanup policy used in the earlier
# CIC-IDS2017 experiment.
non_negative_features = [
    "Fwd Header Length",
    "Fwd Seg Size Min",
    "Bwd Header Length",
    "Flow Duration",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Fwd IAT Min",
]

X_train = X_train.replace([np.inf, -np.inf], np.nan)
X_test = X_test.replace([np.inf, -np.inf], np.nan)

for col in non_negative_features:
    if col in X_train.columns:
        X_train.loc[X_train[col] < 0, col] = np.nan
        X_test.loc[X_test[col] < 0, col] = np.nan

numeric_cols = X_train.select_dtypes(include=np.number).columns.tolist()
categorical_cols = [
    col for col in X_train.columns if col not in numeric_cols
]

preprocessor = ColumnTransformer(
    transformers=[
        (
            "num",
            SimpleImputer(strategy="median"),
            numeric_cols,
        ),
        (
            "cat",
            Pipeline(
                steps=[
                    ("imputer", SimpleImputer(strategy="most_frequent")),
                    ("encoder", OneHotEncoder(handle_unknown="ignore")),
                ]
            ),
            categorical_cols,
        ),
    ],
    remainder="drop",
)

print("\nFitting preprocessing on training block only...")
X_train_processed = preprocessor.fit_transform(X_train)
X_test_processed = preprocessor.transform(X_test)

negatives = int((y_train == 0).sum())
positives = int((y_train == 1).sum())

model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    scale_pos_weight=negatives / positives,
    random_state=42,
    n_jobs=-1,
    tree_method="hist",
)

print("Training on the earlier contiguous block...")
model.fit(X_train_processed, y_train)

probabilities = model.predict_proba(X_test_processed)[:, 1]

results = []
for threshold in [0.005, 0.01, 0.05, 0.2, 0.5]:
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    results.append(
        {
            "threshold": threshold,
            "precision": precision_score(
                y_test, predictions, zero_division=0
            ),
            "recall": recall_score(
                y_test, predictions, zero_division=0
            ),
            "f1": f1_score(y_test, predictions, zero_division=0),
            "fpr": fp / (fp + tn) if fp + tn else 0,
            "roc_auc": roc_auc_score(y_test, probabilities),
            "average_precision": average_precision_score(
                y_test, probabilities
            ),
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        }
    )

summary = pd.DataFrame(results)
summary.to_csv(OUT_DIR / "metrics.csv", index=False)

pd.DataFrame(
    {
        "actual_label": test_df["Label"].to_numpy(),
        "actual_attack": y_test.to_numpy(),
        "probability": probabilities,
    }
).to_csv(OUT_DIR / "predictions.csv", index=False)

print("\n=== CONTIGUOUS BLOCK TEST RESULTS ===")
print(summary.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
print("\nSaved:", OUT_DIR / "metrics.csv")
print("Saved:", OUT_DIR / "predictions.csv")
