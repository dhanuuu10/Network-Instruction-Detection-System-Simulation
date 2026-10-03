import pandas as pd
from pathlib import Path


# ==========================================
# NETWORK IDS RESULT VERIFICATION
# STEP 17B.3
# ==========================================

ROOT_DIR = Path(__file__).resolve().parents[1]

IDS_RESULTS_FILE = (
    ROOT_DIR / "data" / "ids_results.csv"
)


# ==========================================
# CHECK FILE
# ==========================================

if not IDS_RESULTS_FILE.exists():

    raise FileNotFoundError(
        f"IDS results file not found: {IDS_RESULTS_FILE}\n"
        "Please run src/ids_engine.py first."
    )


# ==========================================
# LOAD RESULTS
# ==========================================

df = pd.read_csv(
    IDS_RESULTS_FILE
)


print("========================================")
print("     IDS RESULTS VERIFICATION")
print("========================================")


print(
    f"\nTotal IDS records: {len(df)}"
)


# ==========================================
# REQUIRED COLUMNS
# ==========================================

required_columns = [
    "ids_classification",
    "ids_severity",
    "ids_risk_score",
    "ids_detection_method",
    "ids_reason",
    "ml_prediction",
    "ml_decision_score",
    "ml_classification",
    "ml_risk_score",
    "ml_severity"
]


# ==========================================
# CHECK COLUMNS
# ==========================================

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]


if missing_columns:

    print("\n❌ Missing columns:")

    for column in missing_columns:
        print(
            f"   - {column}"
        )

    raise ValueError(
        "IDS results verification failed."
    )


print(
    "\n✓ All required columns are present."
)


# ==========================================
# CHECK RECORD VALUES
# ==========================================

print(
    "\nIDS Classification:"
)

print(
    df[
        "ids_classification"
    ].value_counts()
)


print(
    "\nIDS Severity:"
)

print(
    df[
        "ids_severity"
    ].value_counts()
)


print(
    "\nDetection Methods:"
)

print(
    df[
        "ids_detection_method"
    ].value_counts()
)


# ==========================================
# CHECK RISK SCORES
# ==========================================

invalid_risk_scores = df[
    (df["ids_risk_score"] < 0)
    |
    (df["ids_risk_score"] > 100)
]


if len(invalid_risk_scores) > 0:

    raise ValueError(
        "Some IDS risk scores are outside 0-100."
    )


print(
    "\n✓ IDS risk scores are within 0-100."
)


# ==========================================
# CHECK ML RISK SCORES
# ==========================================

invalid_ml_scores = df[
    (df["ml_risk_score"] < 0)
    |
    (df["ml_risk_score"] > 100)
]


if len(invalid_ml_scores) > 0:

    raise ValueError(
        "Some ML risk scores are outside 0-100."
    )


print(
    "✓ ML risk scores are within 0-100."
)


# ==========================================
# CHECK DETECTION METHODS
# ==========================================

valid_methods = {
    "NONE",
    "RULE",
    "ANOMALY",
    "ML",
    "RULE + ML",
    "RULE + ANOMALY",
    "ANOMALY + ML",
    "RULE + ANOMALY + ML"
}


invalid_methods = set(
    df[
        "ids_detection_method"
    ].dropna().unique()
) - valid_methods


if invalid_methods:

    print(
        "\n⚠ Unknown detection methods:"
    )

    for method in sorted(
        invalid_methods
    ):

        print(
            f"   - {method}"
        )

else:

    print(
        "✓ Detection methods are valid."
    )


# ==========================================
# ML DETECTION SUMMARY
# ==========================================

ml_suspicious = (
    df[
        "ml_classification"
    ]
    .astype(str)
    .str.upper()
    .eq("SUSPICIOUS")
)


print(
    "\nML suspicious records:"
)

print(
    ml_suspicious.sum()
)


# ==========================================
# HIGH-RISK RECORDS
# ==========================================

high_risk = df[
    df["ids_risk_score"] >= 70
]


print(
    "\nHigh-risk IDS records:"
)

print(
    len(high_risk)
)


# ==========================================
# DISPLAY SAMPLE
# ==========================================

display_columns = [
    "ids_classification",
    "ids_severity",
    "ids_risk_score",
    "ids_detection_method",
    "ml_classification",
    "ml_risk_score"
]


print(
    "\nSample combined IDS results:"
)

print(
    df[
        display_columns
    ].head(10).to_string(
        index=False
    )
)


# ==========================================
# FINAL RESULT
# ==========================================

print(
    "\n========================================"
)

print(
    "       VERIFICATION SUCCESSFUL"
)

print(
    "========================================"
)

print(
    "\nRule + Anomaly + ML results are "
    "available in ids_results.csv."
)