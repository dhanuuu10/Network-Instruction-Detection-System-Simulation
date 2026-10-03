import random
from datetime import datetime, timedelta

import pandas as pd


# -----------------------------
# Configuration
# -----------------------------

NORMAL_COUNT = 700
SUSPICIOUS_COUNT = 200
INTRUSION_COUNT = 100

OUTPUT_FILE = "data/synthetic_traffic.csv"


# -----------------------------
# Synthetic IP addresses
# -----------------------------

SOURCE_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.13",
    "192.168.1.14",
]

DESTINATION_IPS = [
    "192.168.1.20",
    "192.168.1.21",
    "192.168.1.22",
    "192.168.1.23",
]


# -----------------------------
# Generate timestamp
# -----------------------------

def generate_timestamp(start_time):
    random_seconds = random.randint(0, 3600)

    return start_time + timedelta(seconds=random_seconds)


# -----------------------------
# Generate normal traffic
# -----------------------------

def generate_normal_traffic(start_time):

    protocol = random.choice(["TCP", "UDP", "ICMP"])

    destination_ports = {
        "TCP": [80, 443, 22],
        "UDP": [53, 123],
        "ICMP": [0]
    }

    destination_port = random.choice(destination_ports[protocol])

    packet_count = random.randint(5, 100)

    byte_count = random.randint(500, 20000)

    duration = round(random.uniform(0.5, 10.0), 2)

    connection_count = random.randint(1, 5)

    return {
        "timestamp": generate_timestamp(start_time),
        "source_ip": random.choice(SOURCE_IPS),
        "destination_ip": random.choice(DESTINATION_IPS),
        "source_port": random.randint(1024, 65535),
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "connection_count": connection_count,
        "label": "NORMAL"
    }


# -----------------------------
# Generate suspicious traffic
# -----------------------------

def generate_suspicious_traffic(start_time):

    protocol = random.choice(["TCP", "UDP"])

    destination_port = random.choice(
        [21, 23, 25, 110, 135, 139, 445, 8080]
    )

    packet_count = random.randint(100, 500)

    byte_count = random.randint(20000, 100000)

    duration = round(random.uniform(0.1, 3.0), 2)

    connection_count = random.randint(10, 30)

    return {
        "timestamp": generate_timestamp(start_time),
        "source_ip": random.choice(SOURCE_IPS),
        "destination_ip": random.choice(DESTINATION_IPS),
        "source_port": random.randint(1024, 65535),
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "connection_count": connection_count,
        "label": "SUSPICIOUS"
    }


# -----------------------------
# Generate potential intrusion
# -----------------------------

def generate_intrusion_traffic(start_time):

    protocol = random.choice(["TCP", "UDP"])

    destination_port = random.choice(
        [22, 23, 135, 139, 445, 3389]
    )

    packet_count = random.randint(500, 2000)

    byte_count = random.randint(100000, 1000000)

    duration = round(random.uniform(0.01, 1.0), 2)

    connection_count = random.randint(30, 100)

    return {
        "timestamp": generate_timestamp(start_time),
        "source_ip": random.choice(SOURCE_IPS),
        "destination_ip": random.choice(DESTINATION_IPS),
        "source_port": random.randint(1024, 65535),
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "connection_count": connection_count,
        "label": "POTENTIAL INTRUSION"
    }


# -----------------------------
# Generate complete dataset
# -----------------------------

def generate_dataset():

    start_time = datetime.now()

    records = []

    # Normal traffic
    for _ in range(NORMAL_COUNT):
        records.append(
            generate_normal_traffic(start_time)
        )

    # Suspicious traffic
    for _ in range(SUSPICIOUS_COUNT):
        records.append(
            generate_suspicious_traffic(start_time)
        )

    # Potential intrusion traffic
    for _ in range(INTRUSION_COUNT):
        records.append(
            generate_intrusion_traffic(start_time)
        )

    # Convert records into DataFrame
    dataframe = pd.DataFrame(records)

    # Shuffle the records
    dataframe = dataframe.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    # Save dataset
    dataframe.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("Synthetic network traffic generated successfully.")

    print(f"Total records: {len(dataframe)}")

    print("\nClass distribution:")

    print(
        dataframe["label"].value_counts()
    )

    print(
        f"\nDataset saved to: {OUTPUT_FILE}"
    )


# -----------------------------
# Program entry point
# -----------------------------

if __name__ == "__main__":
    generate_dataset()