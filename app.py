import streamlit as st
import pandas as pd
import sqlite3
import os
from pathlib import Path
from datetime import datetime
import plotly.express as px


# ============================================================
# NETWORK IDS - SOC DASHBOARD
# STEP 17C
# Rule + Anomaly + ML Detection
# ============================================================


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT_DIR = Path(__file__).resolve().parent

DATA_DIR = ROOT_DIR / "data"

REPORT_DIR = (
    ROOT_DIR
    / "reports"
    / "incident_reports"
)

IDS_RESULTS_FILE = (
    DATA_DIR
    / "ids_results.csv"
)

DATABASE_FILE = (
    DATA_DIR
    / "ids_events.db"
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Network IDS SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# TITLE
# ============================================================

st.title(
    "🛡️ Network Intrusion Detection System"
)

st.subheader(
    "SOC Monitoring & Security Event Dashboard"
)

st.caption(
    "Rule-Based + Anomaly-Based + Machine Learning Detection"
)


# ============================================================
# LOAD IDS RESULTS
# ============================================================

if not IDS_RESULTS_FILE.exists():

    st.error(
        "ids_results.csv was not found."
    )

    st.info(
        "Run: python src/ids_engine.py"
    )

    st.stop()


try:

    alerts = pd.read_csv(
        IDS_RESULTS_FILE
    )

except Exception as error:

    st.error(
        f"Unable to load IDS results: {error}"
    )

    st.stop()


# ============================================================
# BASIC DATA CLEANING
# ============================================================

alerts = alerts.copy()

alerts.columns = (
    alerts.columns
    .str.strip()
)


# ============================================================
# CONVERT NUMERIC COLUMNS
# ============================================================

numeric_columns = [
    "ids_risk_score",
    "ml_risk_score",
    "ml_prediction",
    "ml_decision_score",
    "anomaly_prediction",
    "anomaly_score",
    "rule_risk_score"
]


for column in numeric_columns:

    if column in alerts.columns:

        alerts[column] = pd.to_numeric(
            alerts[column],
            errors="coerce"
        )


# ============================================================
# DASHBOARD METRICS
# ============================================================

total_alerts = len(
    alerts
)


suspicious_alerts = 0

if "ids_classification" in alerts.columns:

    suspicious_alerts = len(
        alerts[
            alerts[
                "ids_classification"
            ]
            .astype(str)
            .str.upper()
            .isin(
                [
                    "SUSPICIOUS",
                    "POTENTIAL INTRUSION"
                ]
            )
        ]
    )


high_risk_alerts = 0

if "ids_risk_score" in alerts.columns:

    high_risk_alerts = len(
        alerts[
            alerts[
                "ids_risk_score"
            ]
            >= 70
        ]
    )


ml_suspicious = 0

if "ml_classification" in alerts.columns:

    ml_suspicious = len(
        alerts[
            alerts[
                "ml_classification"
            ]
            .astype(str)
            .str.upper()
            == "SUSPICIOUS"
        ]
    )


# ============================================================
# TOP METRICS
# ============================================================

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Total Records",
        total_alerts
    )


with col2:

    st.metric(
        "Suspicious / Intrusion",
        suspicious_alerts
    )


with col3:

    st.metric(
        "High Risk",
        high_risk_alerts
    )


with col4:

    st.metric(
        "ML Suspicious",
        ml_suspicious
    )


# ============================================================
# SECTION: IDS OVERVIEW
# ============================================================

st.divider()

st.header(
    "📊 IDS Overview"
)


overview_col1, overview_col2 = st.columns(2)


# ============================================================
# CLASSIFICATION CHART
# ============================================================

with overview_col1:

    if "ids_classification" in alerts.columns:

        classification_counts = (
            alerts[
                "ids_classification"
            ]
            .value_counts()
            .reset_index()
        )

        classification_counts.columns = [
            "Classification",
            "Count"
        ]

        fig = px.bar(
            classification_counts,
            x="Classification",
            y="Count",
            title="IDS Classification"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


# ============================================================
# SEVERITY CHART
# ============================================================

with overview_col2:

    if "ids_severity" in alerts.columns:

        severity_counts = (
            alerts[
                "ids_severity"
            ]
            .value_counts()
            .reset_index()
        )

        severity_counts.columns = [
            "Severity",
            "Count"
        ]

        fig = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            title="IDS Severity"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


# ============================================================
# DETECTION METHOD ANALYSIS
# ============================================================

st.divider()

st.header(
    "🔍 Detection Method Analysis"
)


if "ids_detection_method" in alerts.columns:

    method_counts = (
        alerts[
            "ids_detection_method"
        ]
        .value_counts()
        .reset_index()
    )

    method_counts.columns = [
        "Detection Method",
        "Count"
    ]


    method_col1, method_col2 = st.columns(2)


    with method_col1:

        fig = px.bar(
            method_counts,
            x="Detection Method",
            y="Count",
            title="Detection Method Distribution"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


    with method_col2:

        fig = px.pie(
            method_counts,
            names="Detection Method",
            values="Count",
            title="Detection Sources"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


# ============================================================
# MACHINE LEARNING ANALYSIS
# ============================================================

st.divider()

st.header(
    "🤖 Machine Learning Detection"
)


ml_col1, ml_col2 = st.columns(2)


# ============================================================
# ML CLASSIFICATION
# ============================================================

with ml_col1:

    if "ml_classification" in alerts.columns:

        ml_counts = (
            alerts[
                "ml_classification"
            ]
            .value_counts()
            .reset_index()
        )

        ml_counts.columns = [
            "ML Classification",
            "Count"
        ]

        fig = px.bar(
            ml_counts,
            x="ML Classification",
            y="Count",
            title="ML Classification"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


# ============================================================
# ML RISK SCORE
# ============================================================

with ml_col2:

    if "ml_risk_score" in alerts.columns:

        fig = px.histogram(
            alerts,
            x="ml_risk_score",
            nbins=20,
            title="ML Risk Score Distribution"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


# ============================================================
# ML SUMMARY
# ============================================================

if "ml_risk_score" in alerts.columns:

    average_ml_risk = alerts[
        "ml_risk_score"
    ].mean()

    maximum_ml_risk = alerts[
        "ml_risk_score"
    ].max()


    ml_metric1, ml_metric2 = st.columns(2)


    with ml_metric1:

        st.metric(
            "Average ML Risk",
            f"{average_ml_risk:.2f}"
        )


    with ml_metric2:

        st.metric(
            "Maximum ML Risk",
            f"{maximum_ml_risk:.2f}"
        )


# ============================================================
# RISK ANALYSIS
# ============================================================

st.divider()

st.header(
    "⚠️ Risk Analysis"
)


if "ids_risk_score" in alerts.columns:

    risk_col1, risk_col2 = st.columns(2)


    with risk_col1:

        fig = px.histogram(
            alerts,
            x="ids_risk_score",
            nbins=20,
            title="Final IDS Risk Score Distribution"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


    with risk_col2:

        top_risk = (
            alerts
            .sort_values(
                "ids_risk_score",
                ascending=False
            )
            .head(10)
        )


        display_columns = [
            column
            for column in [
                "ids_classification",
                "ids_severity",
                "ids_risk_score",
                "ids_detection_method"
            ]
            if column in top_risk.columns
        ]


        st.dataframe(
            top_risk[
                display_columns
            ],
            use_container_width=True
        )


# ============================================================
# ALERT INVESTIGATION
# ============================================================

st.divider()

st.header(
    "🔎 Alert Investigation"
)


if len(alerts) > 0:

    alert_ids = alerts.index.tolist()


    selected_alert_id = st.selectbox(
        "Select an alert to investigate:",
        alert_ids
    )


    selected_alert = alerts.loc[
        selected_alert_id
    ]


    # ------------------------------------------
    # Basic alert information
    # ------------------------------------------

    st.subheader(
        "Alert Details"
    )


    detail_columns = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "ids_classification",
        "ids_severity",
        "ids_risk_score",
        "ids_detection_method",
        "ids_reason"
    ]


    available_details = [
        column
        for column in detail_columns
        if column in alerts.columns
    ]


    details = (
        selected_alert[
            available_details
        ]
        .to_frame(
            "Value"
        )
    )


    st.dataframe(
        details,
        use_container_width=True
    )


    # ------------------------------------------
    # ML details
    # ------------------------------------------

    st.subheader(
        "🤖 ML Detection Details"
    )


    ml_detail_columns = [
        "ml_prediction",
        "ml_decision_score",
        "ml_classification",
        "ml_risk_score",
        "ml_severity"
    ]


    available_ml_details = [
        column
        for column in ml_detail_columns
        if column in alerts.columns
    ]


    if available_ml_details:

        st.dataframe(
            selected_alert[
                available_ml_details
            ]
            .to_frame(
                "Value"
            ),
            use_container_width=True
        )


# ============================================================
# INCIDENT REPORT GENERATOR
# ============================================================

st.divider()

st.header(
    "📄 Incident Report"
)


def create_incident_report(
    alert
):

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    alert_id = str(
        alert.name
    )


    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )


    report_filename = (
        f"{alert_id}_incident_report_"
        f"{timestamp}.txt"
    )


    report_path = (
        REPORT_DIR
        / report_filename
    )


    def get_value(
        column,
        default="N/A"
    ):

        if column in alert.index:

            value = alert[column]

            if pd.notna(value):

                return value

        return default


    report_text = f"""
============================================================
NETWORK INTRUSION DETECTION SYSTEM
SECURITY INCIDENT REPORT
============================================================

Report Generated:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

------------------------------------------------------------
ALERT INFORMATION
------------------------------------------------------------

Alert ID:
{alert_id}

Timestamp:
{get_value("timestamp")}

Classification:
{get_value("ids_classification")}

Severity:
{get_value("ids_severity")}

Risk Score:
{get_value("ids_risk_score")}

Detection Method:
{get_value("ids_detection_method")}

Reason:
{get_value("ids_reason")}

------------------------------------------------------------
NETWORK INFORMATION
------------------------------------------------------------

Source IP:
{get_value("source_ip")}

Destination IP:
{get_value("destination_ip")}

Source Port:
{get_value("source_port")}

Destination Port:
{get_value("destination_port")}

Protocol:
{get_value("protocol")}

------------------------------------------------------------
MACHINE LEARNING ANALYSIS
------------------------------------------------------------

ML Prediction:
{get_value("ml_prediction")}

ML Decision Score:
{get_value("ml_decision_score")}

ML Classification:
{get_value("ml_classification")}

ML Risk Score:
{get_value("ml_risk_score")}

ML Severity:
{get_value("ml_severity")}

------------------------------------------------------------
INVESTIGATION NOTES
------------------------------------------------------------

This report was generated by the local synthetic
Network Intrusion Detection System simulation.

The ML detector uses Isolation Forest for anomaly
identification on synthetic traffic data.

No live network traffic or real-world systems were
targeted by this project.

------------------------------------------------------------
END OF REPORT
------------------------------------------------------------
"""


    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as report_file:

        report_file.write(
            report_text
        )


    return (
        report_text,
        report_path
    )


if len(alerts) > 0:

    if st.button(
        "📄 Generate Incident Report"
    ):

        report_text, report_path = (
            create_incident_report(
                selected_alert
            )
        )


        st.success(
            "Incident report generated successfully."
        )


        st.download_button(
            label="⬇️ Download Incident Report",

            data=report_text,

            file_name=(
                f"{selected_alert_id}_"
                "incident_report.txt"
            ),

            mime="text/plain"
        )


# ============================================================
# RAW IDS DATA
# ============================================================

st.divider()

st.header(
    "📋 IDS Results"
)


with st.expander(
    "View complete IDS results"
):

    st.dataframe(
        alerts,
        use_container_width=True,
        height=500
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Network IDS Simulation | "
    "Synthetic defensive cybersecurity project | "
    "Rule + Anomaly + Machine Learning Detection"
)