import pandas as pd

from database import create_database, insert_alert, get_alert_count


INPUT_FILE = "data/ids_results.csv"


def generate_alert_id(number):
    """
    Generate a unique alert ID.
    """

    return f"IDS-{number:05d}"


def determine_detection_method(row):
    """
    Determine how the event was detected.
    """

    rule_detected = row["rule_classification"] != "NORMAL"
    anomaly_detected = row["anomaly_status"] == "ANOMALY"

    if rule_detected and anomaly_detected:
        return "RULE + ANOMALY"

    elif rule_detected:
        return "RULE ENGINE"

    elif anomaly_detected:
        return "ANOMALY DETECTOR"

    else:
        return "NORMAL"


def process_alerts():

    print("Loading IDS results...")

    df = pd.read_csv(INPUT_FILE)

    print(f"IDS records loaded: {len(df)}")

    print("\nCreating database...")

    create_database()

    alert_number = 1
    alert_count = 0

    print("\nProcessing IDS events...")

    for _, row in df.iterrows():

        if row["ids_classification"] == "NORMAL":
            continue

        alert = {
            "alert_id": generate_alert_id(alert_number),
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "source_port": int(row["source_port"]),
            "destination_port": int(row["destination_port"]),
            "protocol": row["protocol"],
            "classification": row["ids_classification"],
            "severity": row["ids_severity"],
            "risk_score": int(row["ids_risk_score"]),
            "detection_method": determine_detection_method(row),
            "reason": row["ids_reason"],
            "status": "NEW"
        }

        insert_alert(alert)

        alert_number += 1
        alert_count += 1

    total_alerts = get_alert_count()

    print("\nAlert processing completed.")
    print(f"New alerts generated: {alert_count}")
    print(f"Total alerts in database: {total_alerts}")
    print("Database: data/ids_events.db")


if __name__ == "__main__":
    process_alerts()
