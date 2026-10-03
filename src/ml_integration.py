import pandas as pd


# -----------------------------
# File paths
# -----------------------------

RULE_FILE = "data/rule_detection_results.csv"
ANOMALY_FILE = "data/anomaly_detection_results.csv"

OUTPUT_FILE = "data/ids_results.csv"


# -----------------------------
# Load detection results
# -----------------------------

def load_results():

    rule_data = pd.read_csv(
        RULE_FILE
    )

    anomaly_data = pd.read_csv(
        ANOMALY_FILE
    )

    return rule_data, anomaly_data


# -----------------------------
# Combine rule and anomaly data
# -----------------------------

def combine_results(
    rule_data,
    anomaly_data
):

    # Columns required from anomaly results
    anomaly_columns = [
        "anomaly_prediction",
        "anomaly_score",
        "anomaly_status"
    ]

    anomaly_data = anomaly_data[
        anomaly_columns
    ]

    combined_data = pd.concat(
        [
            rule_data.reset_index(drop=True),
            anomaly_data.reset_index(drop=True)
        ],
        axis=1
    )

    return combined_data


# -----------------------------
# Calculate final IDS result
# -----------------------------

def calculate_ids_result(row):

    # Start with rule-based risk
    risk_score = int(
        row["rule_risk_score"]
    )

    reasons = []

    # Add rule reason
    if row["rule_reason"] != (
        "No suspicious rule matched"
    ):

        reasons.append(
            row["rule_reason"]
        )

    # Add anomaly contribution
    if row["anomaly_status"] == "ANOMALY":

        risk_score += 30

        reasons.append(
            "Traffic pattern identified as anomalous"
        )

    # Limit score to 100
    risk_score = min(
        risk_score,
        100
    )

    # -----------------------------
    # Determine classification
    # -----------------------------

    if risk_score >= 70:

        classification = (
            "POTENTIAL INTRUSION"
        )

    elif risk_score >= 30:

        classification = "SUSPICIOUS"

    else:

        classification = "NORMAL"

    # -----------------------------
    # Determine severity
    # -----------------------------

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

    # -----------------------------
    # Combine reasons
    # -----------------------------

    if reasons:

        reason = "; ".join(
            reasons
        )

    else:

        reason = (
            "No suspicious activity detected"
        )

    return pd.Series(
        [
            classification,
            severity,
            risk_score,
            reason
        ]
    )


# -----------------------------
# Run IDS
# -----------------------------

def run_ids(dataframe):

    results = dataframe.apply(
        calculate_ids_result,
        axis=1
    )

    results.columns = [
        "ids_classification",
        "ids_severity",
        "ids_risk_score",
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


# -----------------------------
# Main program
# -----------------------------

def main():

    print(
        "Loading detection results..."
    )

    rule_data, anomaly_data = (
        load_results()
    )

    print(
        f"Rule records: {len(rule_data)}"
    )

    print(
        f"Anomaly records: {len(anomaly_data)}"
    )

    print(
        "\nCombining detection results..."
    )

    dataframe = combine_results(
        rule_data,
        anomaly_data
    )

    print(
        "Running combined IDS..."
    )

    dataframe = run_ids(
        dataframe
    )

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        "\nIDS processing completed."
    )

    print(
        f"Results saved to: {OUTPUT_FILE}"
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


# -----------------------------
# Program entry point
# -----------------------------

if __name__ == "__main__":
    main()