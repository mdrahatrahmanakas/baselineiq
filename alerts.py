"""
alerts.py
---------
Response layer: evaluates risk scores and dispatches alerts.
Extend send_alert() to integrate SMTP, Slack webhook, or SIEM forwarding.
"""

import json
import os
import logging
from datetime import datetime

REPORT_PATH = os.path.join(os.path.dirname(__file__), "data", "risk_report.json")
ALERT_LOG   = os.path.join(os.path.dirname(__file__), "alerts", "alert_log.txt")

CRITICAL_THRESHOLD = 0.20
HIGH_THRESHOLD     = 0.10

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
logger = logging.getLogger("baselineiq.alerts")


def load_report(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def send_alert(event: dict, level: str) -> None:
    """
    Dispatch point for alert delivery.
    Replace the log statement below with SMTP / Slack / webhook logic as needed.
    """
    message = (
        f"[{level}] Insider Threat Alert | "
        f"User: {event.get('user')} | "
        f"Risk Score: {event.get('risk_score')} | "
        f"Hour: {event.get('hour_of_day'):02d}:00 | "
        f"Files Accessed: {event.get('files_accessed')} | "
        f"USB Event: {'Yes' if event.get('usb_event') else 'No'} | "
        f"Sensitivity: {event.get('resource_sensitivity')}"
    )
    logger.warning(message)

    os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
    with open(ALERT_LOG, "a") as f:
        f.write(f"{datetime.utcnow().isoformat()}Z  {message}\n")


def evaluate(report: dict) -> int:
    dispatched = 0
    for event in report.get("threat_events", []):
        score = float(event.get("risk_score", 0))
        if score >= CRITICAL_THRESHOLD:
            send_alert(event, "CRITICAL")
            dispatched += 1
        elif score >= HIGH_THRESHOLD:
            send_alert(event, "HIGH")
            dispatched += 1
    return dispatched


def run() -> None:
    if not os.path.exists(REPORT_PATH):
        logger.error("Risk report not found. Run detector.py first.")
        return

    report = load_report(REPORT_PATH)
    count = evaluate(report)
    logger.info(f"Alert evaluation complete. {count} alert(s) dispatched.")


if __name__ == "__main__":
    run()
