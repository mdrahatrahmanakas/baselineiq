# BaselineIQ

Insider threat detection engine for small and medium organizations. Learns normal employee behavior and flags anomalies — mass file copying, odd-hours access, unauthorized USB usage — without expensive commercial licenses.

---

## Requirements

- Python 3.9 or later
- pip

---

## Installation

```bash
git clone https://github.com/mdrahatrahmanakas/baselineiq.git
cd baselineiq
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

Run the full pipeline:

```bash
python main.py
```

View the dashboard:

```bash
python -m http.server 8000
# Open http://localhost:8000/dashboard.html
```

Use your own data instead of the synthetic log:

```bash
python main.py --skip-generate
```

---

## How It Works

Each user event is scored across four signals: hour of day, files accessed, USB activity, and resource sensitivity. An Isolation Forest model baselines normal behavior and flags deviations as CRITICAL, HIGH, MEDIUM, or LOW risk.

---

## Input Format

Place your log at `data/activity_log.csv` with these columns:

| Column                 | Type   | Description                              |
|------------------------|--------|------------------------------------------|
| `event_id`             | int    | Unique row index                         |
| `user`                 | string | Username, e.g. `john.smith`              |
| `hour_of_day`          | int    | Hour of activity (0-23)                  |
| `files_accessed`       | int    | Files read or modified                   |
| `usb_event`            | int    | 1 if USB device connected, 0 otherwise   |
| `resource_sensitivity` | float  | Resource confidentiality (0.0 to 1.0)    |

---

## Risk Levels

| Level    | Score    | Action                              |
|----------|----------|-------------------------------------|
| CRITICAL | >= 0.20  | Investigate immediately             |
| HIGH     | >= 0.10  | Review within the hour              |
| MEDIUM   | >= 0.00  | Monitor                             |
| LOW      | < 0.00   | Normal behavior                     |

---

## Alert Integration

Edit `send_alert()` in `alerts.py` to route alerts to email, Slack, or a SIEM webhook.

---

## License

MIT License — Copyright (c) 2026 Md Rahat Rahman Akas. See [LICENSE](LICENSE) for full terms.
