import pandas as pd
from pathlib import Path


# ==========================================
# NETWORK IDS ENGINE
# STEP 17B.2
# Rule + Anomaly + ML Detection
# ==========================================

ROOT_DIR = Path(__file__).resolve().parents[1]


# ==========================================
# FILE PATHS
# ==========================================

RULE_FILE = ROOT_DIR / "data" / "rule_detection_results.csv"

ANOMALY_FILE = ROOT_DIR / "data" / "anomaly_detection_results.csv"

ML_RESULTS_FILE = ROOT_DIR / "data" / "ml_detection_results.csv"

OUTPUT_FILE = ROOT_DIR / "data" / "ids_results.csv"


# ==========================================
# LOAD DETECTION RESULTS
# ==========================================

def load_results():

    # Load rule-based detection results
    rule_data = pd.read_csv(
        RULE_FILE
    )

    # Load anomaly-based detection results
    anomaly_data = pd.read_csv(
        ANOMALY_FILE
    )

    # Load machine-learning detection results
    if not ML_RESULTS_FILE.exists():

        raise FileNotFoundError(
            f"ML results file not found: {ML_RESULTS_FILE}\n"
            "Please run src/ml_detector.py first."
        )

    ml_data = pd.read_csv(
        ML_RESULTS_FILE
    )

    return (
        rule_data,
        anomaly_data,
        ml_data
    )


# ==========================================
# COMBINE RULE + ANOMALY + ML DATA
# ==========================================

def combine_results(
    rule_data,
    anomaly_data,
    ml_data
):

    # -----------------------------
    # Required anomaly columns
    # -----------------------------

    anomaly_columns = [
        "anomaly_prediction",
        "anomaly_score",
        "anomaly_status"
    ]

    anomaly_data = anomaly_data[
        anomaly_columns
    ]


    # -----------------------------
    # Required ML columns
    # -----------------------------

    ml_columns = [
        "ml_prediction",
        "ml_decision_score",
        "ml_classification",
        "ml_risk_score",
        "ml_severity"
    ]

    missing_ml_columns = [
        column
        for column in ml_columns
        if column not in ml_data.columns
    ]

    if missing_ml_columns:

        raise ValueError(
            f"Missing ML columns: {missing_ml_columns}"
        )

    ml_data = ml_data[
        ml_columns
    ]


    # -----------------------------
    # Reset indexes
    # -----------------------------

    rule_data = rule_data.reset_index(
        drop=True
    )

    anomaly_data = anomaly_data.reset_index(
        drop=True
    )

    ml_data = ml_data.reset_index(
        drop=True
    )


    # -----------------------------
    # Check record counts
    # -----------------------------

    if not (
        len(rule_data)
        == len(anomaly_data)
        == len(ml_data)
    ):

        raise ValueError(
            "Rule, anomaly and ML datasets "
            "do not contain the same number of records."
        )


    # -----------------------------
    # Combine all detection data
    # -----------------------------

    combined_data = pd.concat(
        [
            rule_data,
            anomaly_data,
            ml_data
        ],
        axis=1
    )

    return combined_data


# ==========================================
# DETECTION METHOD
# ==========================================

def get_detection_method(
    rule_detected,
    anomaly_detected,
    ml_detected
):

    methods = []


    if rule_detected:

        methods.append(
            "RULE"
        )


    if anomaly_detected:

        methods.append(
            "ANOMALY"
        )


    if ml_detected:

        methods.append(
            "ML"
        )


    if not methods:

        return "NONE"


    return " + ".join(
        methods
    )


# ==========================================
# CALCULATE FINAL IDS RESULT
# ==========================================

def calculate_ids_result(row):

    # ======================================
    # INITIAL VALUES
    # ======================================

    rule_risk = int(
        row["rule_risk_score"]
    )

    ml_risk = float(
        row["ml_risk_score"]
    )


    # ======================================
    # DETECTION FLAGS
    # ======================================

    rule_detected = (
        rule_risk > 0
    )


    anomaly_detected = (
        str(
            row["anomaly_status"]
        ).upper()
        == "ANOMALY"
    )


    ml_detected = (
        str(
            row["ml_classification"]
        ).upper()
        == "SUSPICIOUS"
    )


    # ======================================
    # START FINAL RISK SCORE
    # ======================================

    risk_score = rule_risk


    # ======================================
    # REASONS
    # ======================================

    reasons = []


    # --------------------------------------
    # Rule detection
    # --------------------------------------

    if row["rule_reason"] != (
        "No suspicious rule matched"
    ):

        reasons.append(
            row["rule_reason"]
        )


    # --------------------------------------
    # Anomaly detection
    # --------------------------------------

    if anomaly_detected:

        risk_score += 30

        reasons.append(
            "Traffic pattern identified as anomalous"
        )


    # --------------------------------------
    # ML detection
    # --------------------------------------

    if ml_detected:

        # Add a controlled ML contribution.
        # The ML risk score ranges from 0-100.
        # We use 30% of that score.

        ml_contribution = int(
            ml_risk * 0.30
        )

        risk_score += ml_contribution

        reasons.append(
            "Machine-learning model identified suspicious traffic"
        )


    # ======================================
    # LIMIT RISK SCORE
    # ======================================

    risk_score = min(
        risk_score,
        100
    )


    # ======================================
    # FINAL CLASSIFICATION
    # ======================================

    detection_count = sum(
        [
            rule_detected,
            anomaly_detected,
            ml_detected
        ]
    )


    if detection_count >= 2:

        classification = (
            "POTENTIAL INTRUSION"
        )

    elif detection_count == 1:

        classification = (
            "SUSPICIOUS"
        )

    else:

        classification = (
            "NORMAL"
        )


    # ======================================
    # FINAL SEVERITY
    # ======================================

    if risk_score >= 80:

        severity = "CRITICAL"

    elif risk_score >= 60:

        severity = "HIGH"

    elif risk_score >= 30:

        severity = "MEDIUM"

    elif risk_score > 0:

        severity = "LOW"

    else:

        severity = "INFO"


    # ======================================
    # DETECTION METHOD
    # ======================================

    detection_method = get_detection_method(
        rule_detected,
        anomaly_detected,
        ml_detected
    )


    # ======================================
    # COMBINE REASONS
    # ======================================

    if reasons:

        reason = "; ".join(
            reasons
        )

    else:

        reason = (
            "No suspicious activity detected"
        )


    # ======================================
    # RETURN IDS RESULT
    # ======================================

    return pd.Series(
        [
            classification,
            severity,
            risk_score,
            detection_method,
            reason
        ]
    )


# ==========================================
# RUN IDS
# ==========================================

def run_ids(dataframe):

    results = dataframe.apply(
        calculate_ids_result,
        axis=1
    )


    results.columns = [
        "ids_classification",
        "ids_severity",
        "ids_risk_score",
        "ids_detection_method",
        "ids_reason"
    ]


    dataframe = pd.concat(
        [
            dataframe,
            results
        ],
        axis=1
    )


    return dataframe


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    print(
        "========================================"
    )

    print(
        "       NETWORK IDS ENGINE"
    )

    print(
        "   RULE + ANOMALY + ML DETECTION"
    )

    print(
        "========================================"
    )


    # ======================================
    # LOAD DATA
    # ======================================

    print(
        "\nLoading detection results..."
    )


    (
        rule_data,
        anomaly_data,
        ml_data
    ) = load_results()


    print(
        f"Rule records: {len(rule_data)}"
    )

    print(
        f"Anomaly records: {len(anomaly_data)}"
    )

    print(
        f"ML records: {len(ml_data)}"
    )


    # ======================================
    # COMBINE DATA
    # ======================================

    print(
        "\nCombining detection results..."
    )


    dataframe = combine_results(
        rule_data,
        anomaly_data,
        ml_data
    )


    print(
        f"Combined records: {len(dataframe)}"
    )


    # ======================================
    # RUN IDS
    # ======================================

    print(
        "\nRunning combined IDS..."
    )


    dataframe = run_ids(
        dataframe
    )


    # ======================================
    # SAVE RESULTS
    # ======================================

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False
    )


    # ======================================
    # DISPLAY SUMMARY
    # ======================================

    print(
        "\n========================================"
    )

    print(
        "       IDS PROCESSING COMPLETED"
    )

    print(
        "========================================"
    )


    print(
        f"\nResults saved to:"
    )

    print(
        OUTPUT_FILE
    )


    print(
        "\nClassification summary:"
    )

    print(
        dataframe[
            "ids_classification"
        ].value_counts()
    )


    print(
        "\nSeverity summary:"
    )

    print(
        dataframe[
            "ids_severity"
        ].value_counts()
    )


    print(
        "\nDetection method summary:"
    )

    print(
        dataframe[
            "ids_detection_method"
        ].value_counts()
    )


    print(
        "\nSample IDS results:"
    )

    print(
        dataframe[
            [
                "ids_classification",
                "ids_severity",
                "ids_risk_score",
                "ids_detection_method"
            ]
        ].head(10)
    )


# ==========================================
# PROGRAM ENTRY POINT
# ==========================================

if __name__ == "__main__":

    main()