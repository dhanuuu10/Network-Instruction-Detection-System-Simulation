import pandas as pd


# -----------------------------
# File paths
# -----------------------------

INPUT_FILE = "data/traffic_features.csv"
OUTPUT_FILE = "data/rule_detection_results.csv"


# -----------------------------
# Detection thresholds
# -----------------------------

HIGH_PACKET_RATE = 500
HIGH_CONNECTION_RATE = 30
HIGH_BYTE_RATE = 100000

SUSPICIOUS_PORTS = [
    21,
    23,
    135,
    139,
    445,
    3389
]


# -----------------------------
# Load traffic data
# -----------------------------

def load_traffic_data():

    dataframe = pd.read_csv(INPUT_FILE)

    return dataframe


# -----------------------------
# Analyze one network flow
# -----------------------------

def analyze_flow(row):

    risk_score = 0

    reasons = []

    # Rule 1: High packet rate
    if row["packets_per_second"] > HIGH_PACKET_RATE:

        risk_score += 30

        reasons.append(
            "High packet rate"
        )

    # Rule 2: High connection rate
    if row["connections_per_second"] > HIGH_CONNECTION_RATE:

        risk_score += 30

        reasons.append(
            "High connection rate"
        )

    # Rule 3: High byte rate
    if row["bytes_per_second"] > HIGH_BYTE_RATE:

        risk_score += 20

        reasons.append(
            "High byte transfer rate"
        )

    # Rule 4: Suspicious destination port
    if row["destination_port"] in SUSPICIOUS_PORTS:

        risk_score += 20

        reasons.append(
            "Destination port requires investigation"
        )

    # -----------------------------
    # Determine classification
    # -----------------------------

    if risk_score >= 70:

        classification = "POTENTIAL INTRUSION"

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

        reason_text = "; ".join(reasons)

    else:

        reason_text = "No suspicious rule matched"

    return pd.Series(
        [
            classification,
            severity,
            risk_score,
            reason_text
        ]
    )


# -----------------------------
# Apply rules to all traffic
# -----------------------------

def apply_rules(dataframe):

    results = dataframe.apply(
        analyze_flow,
        axis=1
    )

    results.columns = [
        "rule_classification",
        "rule_severity",
        "rule_risk_score",
        "rule_reason"
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

    print("Loading traffic feature dataset...")

    dataframe = load_traffic_data()

    print(
        f"Loaded {len(dataframe)} records."
    )

    print("\nRunning rule-based detection...")

    dataframe = apply_rules(dataframe)

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        "\nRule-based detection completed."
    )

    print(
        f"Results saved to: {OUTPUT_FILE}"
    )

    print("\nClassification summary:")

    print(
        dataframe["rule_classification"].value_counts()
    )

    print("\nSeverity summary:")

    print(
        dataframe["rule_severity"].value_counts()
    )


# -----------------------------
# Program entry point
# -----------------------------

if __name__ == "__main__":
    main()