import unittest
from pathlib import Path
import sqlite3


ROOT_DIR = Path(__file__).resolve().parents[1]
DATABASE_FILE = ROOT_DIR / "data" / "ids_events.db"


class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.assertTrue(
            DATABASE_FILE.exists(),
            "ids_events.db was not found."
        )

        self.connection = sqlite3.connect(DATABASE_FILE)
        self.cursor = self.connection.cursor()

    def tearDown(self):
        self.connection.close()

    def test_alerts_table_exists(self):
        self.cursor.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type='table'
            AND name='alerts'
        """)

        result = self.cursor.fetchone()

        self.assertIsNotNone(result)

    def test_alerts_table_has_records(self):
        self.cursor.execute(
            "SELECT COUNT(*) FROM alerts"
        )

        count = self.cursor.fetchone()[0]

        self.assertGreater(count, 0)

    def test_alert_table_columns(self):
        self.cursor.execute("PRAGMA table_info(alerts)")

        columns = [
            row[1]
            for row in self.cursor.fetchall()
        ]

        required_columns = [
            "alert_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "classification",
            "severity",
            "risk_score",
            "detection_method",
            "reason",
            "status"
        ]

        for column in required_columns:
            self.assertIn(column, columns)

    def test_alert_ids_format(self):
        self.cursor.execute(
            "SELECT alert_id FROM alerts"
        )

        alert_ids = self.cursor.fetchall()

        for alert_id in alert_ids:
            self.assertTrue(
                alert_id[0].startswith("IDS-")
            )


if __name__ == "__main__":
    unittest.main()
