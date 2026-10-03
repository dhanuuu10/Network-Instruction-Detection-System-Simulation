import pandas as pd

from sklearn.ensemble import IsolationForest


# -----------------------------
# File paths
# -----------------------------

INPUT_FILE = "data/traffic_features.csv"
OUTPUT_FILE = "data/anomaly_detection_results.csv"


# -----------------------------
# Features used by the model
# -----------------------------

FEATURES = [
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "connections_per_second"
]


# -----------------------------
# Load traffic data
# -----------------------------

def load_traffic_data():

    dataframe = pd.read_csv(INPUT_FILE)

    return dataframe


# -----------------------------
# Train anomaly detector
# -----------------------------

def train_anomaly_detector(dataframe):

    model = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        random_state=42
    )

    model.fit(
        dataframe[FEATURES]
    )

    return model


# -----------------------------
# Detect anomalies
# -----------------------------

def detect_anomalies(dataframe, model):

    predictions = model.predict(
        dataframe[FEATURES]
    )

    anomaly_scores = model.decision_function(
        dataframe[FEATURES]
    )

    dataframe["anomaly_prediction"] = predictions

    dataframe["anomaly_score"] = anomaly_scores.round(4)

    dataframe["anomaly_status"] = dataframe[
        "anomaly_prediction"
    ].apply(
        lambda value:
        "ANOMALY" if value == -1 else "NORMAL"
    )

    return dataframe


# -----------------------------
# Save results
# -----------------------------

def save_results(dataframe):

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        f"\nResults saved to: {OUTPUT_FILE}"
    )


# -----------------------------
# Main program
# -----------------------------

def main():

    print("Loading traffic feature dataset...")

    dataframe = load_traffic_data()

    print(
        f"Loaded {len(dataframe)} records."
    )

    print("\nTraining Isolation Forest...")

    model = train_anomaly_detector(
        dataframe
    )

    print("Anomaly detector trained.")

    print("\nDetecting unusual traffic...")

    dataframe = detect_anomalies(
        dataframe,
        model
    )

    save_results(dataframe)

    print("\nAnomaly detection summary:")

    print(
        dataframe["anomaly_status"].value_counts()
    )

    print("\nSample anomaly results:")

    print(
        dataframe[
            [
                "source_ip",
                "destination_ip",
                "protocol",
                "anomaly_score",
                "anomaly_status"
            ]
        ].head(10)
    )


# -----------------------------
# Program entry point
# -----------------------------

if __name__ == "__main__":
    main()