import pandas as pd
import numpy as np

from pathlib import Path
from sklearn.ensemble import IsolationForest


# ============================================================
# FILE PATHS
# ============================================================

ROOT_DIR = Path(__file__).resolve().parents[1]

INPUT_FILE = ROOT_DIR / "data" / "traffic_features.csv"
OUTPUT_FILE = ROOT_DIR / "data" / "ml_detection_results.csv"


# ============================================================
# LOAD DATA
# ============================================================

print("Loading feature data...")

df = pd.read_csv(INPUT_FILE)

print(f"Records loaded: {len(df)}")


# ============================================================
# SELECT NUMERIC FEATURES
# ============================================================

excluded_columns = {
    "label",
    "classification",
    "ids_classification",
    "rule_classification",
    "anomaly_classification",
    "ml_classification"
}


numeric_columns = df.select_dtypes(
    include=np.number
).columns.tolist()


feature_columns = [
    column
    for column in numeric_columns
    if column not in excluded_columns
]


if not feature_columns:
    raise ValueError(
        "No numeric features were found for ML detection."
    )


print("\nML features:")

for column in feature_columns:
    print(f"- {column}")


# ============================================================
# HANDLE MISSING VALUES
# ============================================================

X = df[feature_columns].copy()

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

X = X.fillna(
    X.median(numeric_only=True)
)


# ============================================================
# TRAINING DATA
# ============================================================

# Prefer NORMAL synthetic records for training.
# This helps the model learn the expected baseline behavior.

if "label" in df.columns:

    normal_mask = (
        df["label"].astype(str).str.upper() == "NORMAL"
    )

    X_train = X[normal_mask]

else:

    print(
        "Ground-truth label column not found."
    )

    print(
        "Using all records as training data."
    )

    X_train = X


if len(X_train) < 20:

    print(
        "Warning: fewer than 20 normal training records."
    )

    print(
        "Using all available records for training."
    )

    X_train = X


print(
    f"\nTraining records: {len(X_train)}"
)


# ============================================================
# CREATE ISOLATION FOREST
# ============================================================

model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1
)


# ============================================================
# TRAIN MODEL
# ============================================================

print("\nTraining Isolation Forest...")

model.fit(X_train)

print("Model training completed.")


# ============================================================
# PREDICT ALL RECORDS
# ============================================================

predictions = model.predict(X)

decision_scores = model.decision_function(X)


# ============================================================
# CONVERT PREDICTIONS
# ============================================================

df["ml_prediction"] = predictions

df["ml_decision_score"] = decision_scores


df["ml_classification"] = np.where(
    predictions == -1,
    "SUSPICIOUS",
    "NORMAL"
)


# ============================================================
# CALCULATE ML RISK SCORE
# ============================================================

# Lower Isolation Forest decision scores indicate
# greater abnormality.

anomaly_strength = -decision_scores

minimum = anomaly_strength.min()
maximum = anomaly_strength.max()


if maximum == minimum:

    risk_scores = np.zeros(
        len(anomaly_strength)
    )

else:

    risk_scores = (
        (anomaly_strength - minimum)
        /
        (maximum - minimum)
    ) * 100


df["ml_risk_score"] = (
    risk_scores.round(2)
)


# ============================================================
# ML SEVERITY
# ============================================================

def assign_severity(risk):

    if risk >= 80:
        return "HIGH"

    elif risk >= 60:
        return "MEDIUM"

    elif risk >= 30:
        return "LOW"

    return "INFO"


df["ml_severity"] = (
    df["ml_risk_score"]
    .apply(assign_severity)
)


# ============================================================
# SAVE RESULTS
# ============================================================

df.to_csv(
    OUTPUT_FILE,
    index=False
)


print(
    f"\nML results saved to:"
)

print(
    OUTPUT_FILE
)


# ============================================================
# SUMMARY
# ============================================================

print("\n========================================")
print("      ML DETECTION SUMMARY")
print("========================================")

print(
    df["ml_classification"]
    .value_counts()
)

print("\nML Severity:")

print(
    df["ml_severity"]
    .value_counts()
)

print("\nML detection completed successfully.")