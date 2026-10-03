import pandas as pd


# -----------------------------
# File paths
# -----------------------------

INPUT_FILE = "data/synthetic_traffic.csv"
OUTPUT_FILE = "data/traffic_features.csv"


# -----------------------------
# Load network traffic
# -----------------------------

def load_traffic_data():

    dataframe = pd.read_csv(INPUT_FILE)

    return dataframe


# -----------------------------
# Create security features
# -----------------------------

def create_features(dataframe):

    # Avoid division by zero
    dataframe["duration"] = dataframe["duration"].replace(0, 0.01)

    dataframe["packet_count"] = dataframe["packet_count"].replace(0, 1)

    # Packets transferred per second
    dataframe["packets_per_second"] = (
        dataframe["packet_count"] /
        dataframe["duration"]
    )

    # Bytes transferred per second
    dataframe["bytes_per_second"] = (
        dataframe["byte_count"] /
        dataframe["duration"]
    )

    # Average size of each packet
    dataframe["average_packet_size"] = (
        dataframe["byte_count"] /
        dataframe["packet_count"]
    )

    # Connections established per second
    dataframe["connections_per_second"] = (
        dataframe["connection_count"] /
        dataframe["duration"]
    )

    # Round calculated values
    dataframe["packets_per_second"] = (
        dataframe["packets_per_second"].round(2)
    )

    dataframe["bytes_per_second"] = (
        dataframe["bytes_per_second"].round(2)
    )

    dataframe["average_packet_size"] = (
        dataframe["average_packet_size"].round(2)
    )

    dataframe["connections_per_second"] = (
        dataframe["connections_per_second"].round(2)
    )

    return dataframe


# -----------------------------
# Save feature dataset
# -----------------------------

def save_features(dataframe):

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        f"\nFeature dataset saved to: {OUTPUT_FILE}"
    )


# -----------------------------
# Main program
# -----------------------------

def main():

    print("Loading network traffic...")

    dataframe = load_traffic_data()

    print(
        f"Loaded {len(dataframe)} network-flow records."
    )

    print("\nCreating security features...")

    dataframe = create_features(dataframe)

    print("\nFeature engineering completed.")

    print("\nNew features:")

    print(
        " - packets_per_second"
    )

    print(
        " - bytes_per_second"
    )

    print(
        " - average_packet_size"
    )

    print(
        " - connections_per_second"
    )

    save_features(dataframe)

    print("\nFeature dataset preview:")

    print(
        dataframe.head()
    )


# -----------------------------
# Program entry point
# -----------------------------

if __name__ == "__main__":
    main()