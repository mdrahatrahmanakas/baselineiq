# BaselineIQ — Insider Threat Detection Engine

A lightweight insider threat detection tool that baselines normal employee activity and flags high-risk deviations using an unsupervised Isolation Forest model. Designed for small-to-medium organizations that need insider threat detection without costly commercial licenses.

---

## Overview

Traditional security tools look for known attack signatures. This tool takes the opposite approach: it learns what "normal" looks like for each user and alerts when behavior deviates significantly — such as mass file copying at 2 AM or repeated access to high-sensitivity resources outside of business hours.

**Detection method:** Isolation Forest (unsupervised anomaly detection)
**Time-to-detection:** Minutes, not months
**Deployment footprint:** Python 3.9+, three dependencies

---

## Architecture

```
baselineiq/
  generate_data.py    Simulates or ingests activity log data (CSV)
  detector.py         Trains Isolation Forest, scores all events, writes risk_report.json
  alerts.py           Evaluates scores against thresholds, dispatches alerts
  main.py             Orchestrates the full pipeline
  dashboard.html      Static HTML/JS risk dashboard (reads risk_report.json)
  data/
    activity_log.csv  Input: one row per user activity event
    risk_report.json  Output: scored events, user summaries, threat list
  alerts/
    alert_log.txt     Append-only log of dispatched alerts
  requirements.txt
```

---

## Features

- **Behavioral baseline** — learns normal working hours, file access volumes, and resource sensitivity patterns per-user corpus
- **Four-feature model** — hour of day, files accessed, USB events, resource sensitivity score
- **Risk classification** — CRITICAL / HIGH / MEDIUM / LOW tiers based on Isolation Forest decision function
- **Per-user aggregation** — max risk score, average risk score, and anomaly count per identity
- **Alert dispatch layer** — configurable thresholds; extend `send_alert()` to route to SMTP, Slack, or a SIEM webhook
- **Static dashboard** — zero-dependency HTML file; no server required after data generation

---

## Quickstart

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the full pipeline

```bash
python main.py
```

This will:
1. Generate a synthetic activity log (`data/activity_log.csv`)
2. Train the anomaly detection model and produce `data/risk_report.json`
3. Evaluate alert thresholds and write `alerts/alert_log.txt`

### 3. View the dashboard

Serve the project directory over HTTP and open `dashboard.html`:

```bash
python -m http.server 8000
# then open http://localhost:8000/dashboard.html
```

Opening `dashboard.html` directly via `file://` will block the JSON fetch in most browsers due to CORS policy. Use the HTTP server above.

---

## Using Your Own Data

Replace `data/activity_log.csv` with real log data and run with `--skip-generate`:

```bash
python main.py --skip-generate
```

The CSV must contain these columns:

| Column               | Type    | Description                                          |
|----------------------|---------|------------------------------------------------------|
| `event_id`           | int     | Unique row identifier (index)                        |
| `user`               | string  | Username or UPN                                      |
| `hour_of_day`        | int     | Hour the event occurred (0-23)                       |
| `files_accessed`     | int     | Number of files read or modified in this session     |
| `usb_event`          | int     | 1 if a USB device was plugged in, 0 otherwise        |
| `resource_sensitivity` | float | 0.0 (public) to 1.0 (highly confidential) — assign based on folder/share classification |

In a production environment, populate this file by tailing Windows Security Event Logs (`Security.evtx`), Active Directory authentication logs, or VPN session records using a log shipper such as Filebeat or a scheduled Python ETL script.

---

## Tuning

| Parameter           | Location         | Default | Notes                                                  |
|---------------------|------------------|---------|--------------------------------------------------------|
| `CONTAMINATION`     | `detector.py`    | `0.10`  | Expected fraction of anomalous records in the dataset  |
| `n_estimators`      | `detector.py`    | `200`   | More trees = more stable scores, slower training       |
| `CRITICAL_THRESHOLD`| `alerts.py`      | `0.20`  | Risk score above which CRITICAL alerts fire            |
| `HIGH_THRESHOLD`    | `alerts.py`      | `0.10`  | Risk score above which HIGH alerts fire                |

Raise `CONTAMINATION` if too many false positives appear. Lower thresholds if alerts are too sparse.

---

## Extending Alert Delivery

Open `alerts.py` and replace the body of `send_alert()` with your delivery logic:

```python
# SMTP example
import smtplib
from email.message import EmailMessage

def send_alert(event, level):
    msg = EmailMessage()
    msg['Subject'] = f'[{level}] Insider Threat Alert — {event["user"]}'
    msg['From']    = 'ueba@your-org.com'
    msg['To']      = 'security@your-org.com'
    msg.set_content(f"Risk score: {event['risk_score']}\nDetails: {event}")
    with smtplib.SMTP('smtp.your-org.com') as s:
        s.send_message(msg)
```

---

## Risk Scoring Reference

| Level    | Score Range   | Recommended Action                        |
|----------|---------------|-------------------------------------------|
| CRITICAL | >= 0.20       | Immediate investigation; consider session termination |
| HIGH     | 0.10 – 0.19   | Alert IT Security; review within 1 hour   |
| MEDIUM   | 0.00 – 0.09   | Log and monitor; no immediate action      |
| LOW      | < 0.00        | Normal behavior                            |

---

## Portfolio Notes

This project demonstrates:

- **Unsupervised machine learning** applied to a real security problem where labeled attack data is unavailable
- **Feature engineering** for behavioral signals (time, volume, sensitivity, device events)
- **Production pipeline design** — ingestion, modeling, alerting, and visualization as distinct, composable layers
- **Minimal dependencies** — deployable on any system with Python 3.9 and three packages

**Pitch summary:** A lightweight BaselineIQ engine that identifies insider threats without expensive licenses. Uses an unsupervised Isolation Forest model to baseline normal employee behavior and flags high-risk deviations — such as mass file copying at odd hours — reducing time-to-detection from months to minutes.

---

## License

MIT License — Copyright (c) 2026 Md Rahat Rahman Akas. See [LICENSE](LICENSE) for full terms.
