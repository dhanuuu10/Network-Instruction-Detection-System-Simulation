import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# FILE PATH
# ============================================================

INPUT_FILE = "data/ids_results.csv"


# ============================================================
# LOAD DATA
# ============================================================

print("Loading IDS results...")

df = pd.read_csv(INPUT_FILE)

print(f"Records loaded: {len(df)}")


# ============================================================
# PREPARE TRUE AND PREDICTED LABELS
# ============================================================

y_true = df["label"]

y_pred = df["ids_classification"]


# ============================================================
# CALCULATE PERFORMANCE METRICS
# ============================================================

accuracy = accuracy_score(
    y_true,
    y_pred
)

precision = precision_score(
    y_true,
    y_pred,
    average="weighted",
    zero_division=0
)

recall = recall_score(
    y_true,
    y_pred,
    average="weighted",
    zero_division=0
)

f1 = f1_score(
    y_true,
    y_pred,
    average="weighted",
    zero_division=0
)


# ============================================================
# DISPLAY METRICS
# ============================================================

print("\n========================================")
print("       IDS PERFORMANCE EVALUATION")
print("========================================")

print(
    f"Accuracy  : {accuracy:.4f}"
)

print(
    f"Precision : {precision:.4f}"
)

print(
    f"Recall    : {recall:.4f}"
)

print(
    f"F1-Score  : {f1:.4f}"
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

labels = [
    "NORMAL",
    "SUSPICIOUS",
    "POTENTIAL INTRUSION"
]

cm = confusion_matrix(
    y_true,
    y_pred,
    labels=labels
)


print("\n========================================")
print("           CONFUSION MATRIX")
print("========================================")

print(
    pd.DataFrame(
        cm,
        index=labels,
        columns=labels
    )
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n========================================")
print("         CLASSIFICATION REPORT")
print("========================================")

print(
    classification_report(
        y_true,
        y_pred,
        labels=labels,
        zero_division=0
    )
)


# ============================================================
# SAVE EVALUATION RESULTS
# ============================================================

metrics_data = {
    "metric": [
        "Accuracy",
        "Precision",
        "Recall",
        "F1-Score"
    ],
    "value": [
        accuracy,
        precision,
        recall,
        f1
    ]
}


metrics_df = pd.DataFrame(
    metrics_data
)


metrics_df.to_csv(
    "data/evaluation_metrics.csv",
    index=False
)


print(
    "\nEvaluation metrics saved to:"
)

print(
    "data/evaluation_metrics.csv"
)