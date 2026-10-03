import sqlite3
import os
from datetime import datetime


DATABASE_PATH = "data/ids_events.db"
REPORT_DIRECTORY = "reports/incident_reports"


def generate_incident_report(alert):
    os.makedirs(REPORT_DIRECTORY, exist_ok=True)

    alert_id = alert[0]
    timestamp = alert[1]
    source_ip = alert[2]
    destination_ip = alert[3]
    source_port = alert[4]
    destination_port = alert[5]
    protocol = alert[6]
    classification = alert[7]
    severity = alert[8]
    risk_score = alert[9]
    detection_method = alert[10]
    reason = alert[11]
    status = alert[12]

    filename = f"{alert_id}_incident_report.txt"
    report_path = os.path.join(REPORT_DIRECTORY, filename)

    report = f"""
============================================================
             NETWORK INTRUSION DETECTION SYSTEM
                    INCIDENT REPORT
============================================================

REPORT INFORMATION
------------------------------------------------------------
Alert ID             : {alert_id}
Generated On         : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

ALERT DETAILS
------------------------------------------------------------
Event Timestamp      : {timestamp}
Classification       : {classification}
Severity             : {severity}
Risk Score           : {risk_score}/100
Detection Method     : {detection_method}
Alert Status         : {status}

NETWORK INFORMATION
------------------------------------------------------------
Source IP            : {source_ip}
Destination IP       : {destination_ip}
Source Port          : {source_port}
Destination Port     : {destination_port}
Protocol             : {protocol}

DETECTION REASON
------------------------------------------------------------
{reason}

ANALYST NOTES
------------------------------------------------------------
This incident was generated from a synthetic network
traffic simulation used for defensive cybersecurity
education and IDS evaluation.

The event should be investigated according to the
classification, severity, risk score, and detection
reason shown above.

RECOMMENDED INVESTIGATION ACTIONS
------------------------------------------------------------
1. Review the source and destination information.
2. Examine the detection reason.
3. Review related network events.
4. Validate whether the activity is expected or abnormal.
5. Record investigation findings.
6. Update the alert status after investigation.

============================================================
END OF INCIDENT REPORT
============================================================
"""

    with open(report_path, "w", encoding="utf-8") as file:
        file.write(report)

    return report_path


def get_alerts():
    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            alert_id,
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            classification,
            severity,
            risk_score,
            detection_method,
            reason,
            status
        FROM alerts
        WHERE classification != 'NORMAL'
        ORDER BY risk_score DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


def main():
    alerts = get_alerts()

    if not alerts:
        print("No alerts found in the database.")
        return

    print(f"Found {len(alerts)} alerts.")

    generated_count = 0

    for alert in alerts:
        report_path = generate_incident_report(alert)

        print(f"Report generated: {report_path}")

        generated_count += 1

    print()
    print(f"Successfully generated {generated_count} incident reports.")


if __name__ == "__main__":
    main()