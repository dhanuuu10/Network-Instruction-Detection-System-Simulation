import sqlite3
import os


DATABASE_PATH = "data/ids_events.db"


def create_database():
    """
    Create the SQLite database and alerts table.
    """

    os.makedirs("data", exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            classification TEXT,
            severity TEXT,
            risk_score INTEGER,
            detection_method TEXT,
            reason TEXT,
            status TEXT
        )
    """)

    connection.commit()
    connection.close()


def insert_alert(alert):
    """
    Insert one security alert into the database.
    """

    connection = sqlite3.connect(DATABASE_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO alerts (
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
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["alert_id"],
        alert["timestamp"],
        alert["source_ip"],
        alert["destination_ip"],
        alert["source_port"],
        alert["destination_port"],
        alert["protocol"],
        alert["classification"],
        alert["severity"],
        alert["risk_score"],
        alert["detection_method"],
        alert["reason"],
        alert["status"]
    ))

    connection.commit()
    connection.close()


def get_alert_count():
    """
    Return the total number of alerts.
    """

    connection = sqlite3.connect(DATABASE_PATH)

    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")

    count = cursor.fetchone()[0]

    connection.close()

    return count