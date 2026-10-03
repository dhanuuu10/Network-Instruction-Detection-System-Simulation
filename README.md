# 🛡️ Network Intrusion Detection System (IDS) Simulation

A defensive cybersecurity project that simulates network traffic,
detects suspicious network behavior, generates security alerts,
calculates risk scores, stores security events, and provides a
SOC-style monitoring dashboard.

---

## 📌 Project Overview

This project demonstrates the design and implementation of a
Network Intrusion Detection System using synthetic network-flow
records.

The system combines:

- Signature-based detection
- Rule-based detection
- Anomaly-based detection
- Network traffic analysis
- Risk scoring
- Alert generation
- Security event storage
- SOC-style investigation
- Incident report generation
- IDS performance evaluation
- Automated testing
- Interactive Streamlit dashboard

The project is designed for defensive cybersecurity education
and does not attack or scan public or third-party systems.

---

## 🎯 Objectives

The main objectives are to:

1. Generate synthetic network traffic.
2. Extract network-flow features.
3. Analyze source and destination information.
4. Analyze protocols and ports.
5. Detect suspicious traffic patterns.
6. Apply rule/signature-based detection.
7. Apply anomaly-based detection.
8. Generate security alerts.
9. Assign severity levels.
10. Calculate risk scores.
11. Store security events.
12. Provide SOC-style investigation capabilities.
13. Generate incident reports.
14. Evaluate IDS performance.
15. Provide automated tests.

---

## 🏗️ System Architecture

```text
Synthetic Traffic
       │
       ▼
Traffic Generator
       │
       ▼
Feature Engineering
       │
       ├───────────────┐
       ▼               ▼
 Rule Engine     Anomaly Detector
       │               │
       └───────┬───────┘
               ▼
          IDS Engine
               │
               ▼
          Alert Engine
               │
       ┌───────┴────────┐
       ▼                ▼
   SQLite DB       Performance
       │             Evaluation
       ▼
SOC Dashboard
       │
       ▼
Incident Reports