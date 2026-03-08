# BaselineIQ

**Insider Threat Detection Engine**

BaselineIQ is a lightweight, deployable User and Entity Behavior Analytics (UEBA) tool built for small-to-medium organizations. It learns what normal employee activity looks like and automatically flags high-risk deviations — such as mass file exfiltration at odd hours, unauthorized USB usage, or access to sensitive resources outside business hours — without requiring expensive commercial licenses.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Running BaselineIQ](#running-baselineiq)
- [Viewing the Dashboard](#viewing-the-dashboard)
- [Using Your Own Data](#using-your-own-data)
- [Understanding the Risk Report](#understanding-the-risk-report)
- [Alert Configuration](#alert-configuration)
- [Model Tuning](#model-tuning)
- [Project Structure](#project-structure)
- [Notes](#notes)
- [License](#license)

---

## Overview

Traditional security tools detect threats by matching known attack signatures. BaselineIQ takes a fundamentally different approach: it profiles each user's normal behavior over time and raises alerts only when that behavior changes significantly.

This means BaselineIQ can catch threats that signature-based tools miss entirely — including malicious insiders, compromised accounts, and data exfiltration attempts with no prior history.

| Attribute              | Detail                                      |
|------------------------|---------------------------------------------|
| Detection method       | Isolation Forest (unsupervised ML)          |
| Time-to-detection      | Minutes, not months                         |
| Dependencies           | Python 3.9+, three packages                 |
| Dashboard              | Static HTML — no server framework required  |
| Alert delivery         | Log file, SMTP, Slack, or SIEM webhook      |

---

## How It Works

BaselineIQ analyzes four behavioral signals per user event:

| Signal                  | What it measures                                               |
|-------------------------|----------------------------------------------------------------|
| Hour of day             | Whether activity occurs during normal business hours           |
| Files accessed          | Volume of files read or modified in a session                  |
| USB event               | Whether a removable storage device was connected               |
| Resource sensitivity    | How confidential the accessed resource is (0.0 to 1.0 scale)  |

The Isolation Forest algorithm trains on this data and assigns each event a risk score. Events that deviate significantly from established baselines receive higher scores and are classified as CRITICAL, HIGH, MEDIUM, or LOW risk.

---

## System Requirements

- Python 3.9 or later
- pip (Python package manager)
- A modern web browser (Chrome, Firefox, Edge)
- Operating system: Linux, macOS, or Windows

Verify your Python version:

```bash
python --version
```

---

## Installation

### Step 1 — Download the project

Clone the repository using Git:

```bash
git clone https://github.com/mdrahatrahmanakas/baselineiq.git
cd baselineiq
```

Or download the ZIP from the GitHub repository page and extract it:

```bash
unzip baselineiq.zip
cd baselineiq
```

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

This installs the following packages:

| Package       | Version   | Purpose                              |
|---------------|-----------|--------------------------------------|
| pandas        | >= 2.0    | Data loading and manipulation        |
| scikit-learn  | >= 1.3    | Isolation Forest model               |
| numpy         | >= 1.24   | Numerical operations                 |

---

## Running BaselineIQ

### Run the full pipeline

```bash
python main.py
```

This executes three stages in sequence:

1. **Data generation** — creates a synthetic activity log at `data/activity_log.csv` with realistic normal behavior and injected threat scenarios
2. **Anomaly detection** — trains the Isolation Forest model, scores every event, and writes the full risk report to `data/risk_report.json`
3. **Alert evaluation** — checks each flagged event against risk thresholds and writes alerts to `alerts/alert_log.txt`

Example output:

```
============================================================
  BaselineIQ — Insider Threat Detection Engine
============================================================

[1/3] Generating activity log data...
[baselineiq.data] Wrote 205 records to data/activity_log.csv

[2/3] Running anomaly detection...
[baselineiq.detector] Report saved to data/risk_report.json
[baselineiq.detector] 205 events analyzed — 21 threats detected (10.24% threat rate)

[3/3] Evaluating alerts...
  WARNING  [CRITICAL] Insider Threat Alert | User: alice.johnson | Risk Score: 0.3264
  WARNING  [CRITICAL] Insider Threat Alert | User: bob.carter    | Risk Score: 0.2577

============================================================
  Total Events Analyzed : 205
  Threats Detected      : 21
  Threat Rate           : 10.24%
============================================================
```

### Skip data generation (use existing log)

If you have already generated or supplied your own `data/activity_log.csv`, skip the generation step:

```bash
python main.py --skip-generate
```

---

## Viewing the Dashboard

BaselineIQ includes a fully static, zero-dependency risk dashboard. To view it, serve the project directory over HTTP:

```bash
python -m http.server 8000
```

Then open your browser and navigate to:

```
http://localhost:8000/dashboard.html
```

> Note: Opening `dashboard.html` directly via `file://` will fail in most browsers due to CORS restrictions on local JSON fetches. Always use the HTTP server command above.

### Dashboard panels

| Panel                        | Description                                                  |
|------------------------------|--------------------------------------------------------------|
| KPI strip                    | Total events, threats detected, threat rate, users monitored |
| Activity Scatter             | Hour of day vs. files accessed — normal vs. anomaly points   |
| Risk Score Distribution      | Histogram of all event risk scores by tier                   |
| Threat Events — Detail View  | Full table of flagged events with risk bars and tier labels  |
| Top Risk Users               | Ranked list of highest-risk identities                       |
| Anomaly Count per User       | Bar chart of flagged events per user                         |
| Alert Feed                   | Chronological list of all dispatched alerts                  |

---

## Using Your Own Data

Replace the synthetic data with real activity logs from your environment.

### Step 1 — Prepare your CSV

Create a file at `data/activity_log.csv` with the following columns:

| Column                 | Type   | Description                                                              |
|------------------------|--------|--------------------------------------------------------------------------|
| `event_id`             | int    | Unique row identifier (used as the index)                                |
| `user`                 | string | Username or User Principal Name (UPN), e.g. `john.smith`                |
| `hour_of_day`          | int    | Hour the activity occurred, 24-hour format (0-23)                        |
| `files_accessed`       | int    | Number of files read or modified in this session                         |
| `usb_event`            | int    | 1 if a USB storage device was connected during this session, 0 otherwise |
| `resource_sensitivity` | float  | Sensitivity score of the accessed resource, from 0.0 (public) to 1.0 (highly confidential) |

Example rows:

```csv
event_id,user,hour_of_day,files_accessed,usb_event,resource_sensitivity
0,alice.johnson,9,5,0,0.12
1,bob.carter,10,12,0,0.08
2,bob.carter,2,480,1,0.92
```

### Step 2 — Assign resource sensitivity scores

Map your file shares or folders to a sensitivity value:

| Resource type               | Suggested sensitivity value |
|-----------------------------|-----------------------------|
| Public intranet / wiki      | 0.0 – 0.1                   |
| General internal documents  | 0.1 – 0.3                   |
| HR or finance records       | 0.5 – 0.7                   |
| Legal or executive data     | 0.7 – 0.9                   |
| Credentials or source code  | 0.9 – 1.0                   |

### Step 3 — Run with your data

```bash
python main.py --skip-generate
```

### Ingestion in production environments

In a live deployment, populate `data/activity_log.csv` automatically by extracting from:

- Windows Security Event Logs (`Security.evtx`) via a scheduled Python ETL script
- Active Directory authentication logs
- VPN session records
- File server access logs via Filebeat or a similar log shipper

Schedule `python main.py --skip-generate` to run on a defined interval (every 5 to 15 minutes) using cron or a task scheduler.

---

## Understanding the Risk Report

After each run, `data/risk_report.json` contains:

```
summary             Total events, total threats, threat rate percentage
top_risky_users     Top 5 users ranked by maximum risk score
threat_events       Full details of every flagged anomaly
all_events          Every event with its risk score and classification
```

The `alerts/alert_log.txt` file is an append-only record of every alert dispatched, including timestamp, user, risk score, and event details.

---

## Alert Configuration

Risk thresholds are defined in `alerts.py`:

| Constant             | Default | Behavior                                                      |
|----------------------|---------|---------------------------------------------------------------|
| `CRITICAL_THRESHOLD` | 0.20    | Triggers a CRITICAL alert; recommended for immediate response |
| `HIGH_THRESHOLD`     | 0.10    | Triggers a HIGH alert; recommended for same-day review        |

### Integrating with external systems

Open `alerts.py` and replace the body of `send_alert()` with your delivery logic.

**SMTP (email):**

```python
import smtplib
from email.message import EmailMessage

def send_alert(event, level):
    msg = EmailMessage()
    msg['Subject'] = f'[{level}] BaselineIQ Alert — {event["user"]}'
    msg['From']    = 'baselineiq@your-org.com'
    msg['To']      = 'security@your-org.com'
    msg.set_content(f"Risk score: {event['risk_score']}\nDetails: {event}")
    with smtplib.SMTP('smtp.your-org.com') as s:
        s.send_message(msg)
```

**Slack webhook:**

```python
import urllib.request, json

def send_alert(event, level):
    payload = {"text": f"[{level}] BaselineIQ: {event['user']} — score {event['risk_score']}"}
    req = urllib.request.Request(
        'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req)
```

---

## Model Tuning

| Parameter       | File          | Default | Guidance                                                                                        |
|-----------------|---------------|---------|-------------------------------------------------------------------------------------------------|
| `CONTAMINATION` | `detector.py` | 0.10    | Expected proportion of anomalous events. Increase if too many false positives; decrease if threats are missed. |
| `n_estimators`  | `detector.py` | 200     | Number of trees in the forest. Higher values improve score stability at the cost of training time. |

---

## Project Structure

```
baselineiq/
  main.py               Pipeline entry point
  generate_data.py      Synthetic log generator / data ingestion layer
  detector.py           Isolation Forest model, scoring, and risk classification
  alerts.py             Threshold evaluation and alert dispatch
  dashboard.html        Static risk dashboard (HTML, CSS, JS — no framework)
  data/
    activity_log.csv    Input: user activity events
    risk_report.json    Output: scored events and threat summary
  alerts/
    alert_log.txt       Append-only alert history
  requirements.txt      Python dependencies
  LICENSE               MIT License
  README.md             This document
```

---

## Notes

BaselineIQ demonstrates the following capabilities:

- Unsupervised machine learning applied to a real security domain where labeled attack data is unavailable
- Feature engineering for behavioral signals across time, volume, device, and sensitivity dimensions
- Production pipeline architecture with ingestion, modeling, alerting, and visualization as independent, composable layers
- Minimal operational footprint: deployable on any machine with Python 3.9 and three packages, with no database or web framework required

---

## License

MIT License — Copyright (c) 2026 Md Rahat Rahman Akas. See [LICENSE](LICENSE) for full terms.
