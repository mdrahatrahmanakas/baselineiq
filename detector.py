"""
detector.py
-----------
Core BaselineIQ detection engine.
Trains an Isolation Forest on activity logs and produces a risk-scored report.
"""

import os
import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

FEATURES = ["hour_of_day", "files_accessed", "usb_event", "resource_sensitivity"]
CONTAMINATION = 0.10
RANDOM_SEED = 42

DATA_PATH    = os.path.join(os.path.dirname(__file__), "data", "activity_log.csv")
REPORT_PATH  = os.path.join(os.path.dirname(__file__), "data", "risk_report.json")


def load_data(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, index_col="event_id")
    if df.empty:
        raise ValueError("Activity log is empty. Run generate_data.py first.")
    return df


def train_and_score(df: pd.DataFrame) -> pd.DataFrame:
    X = df[FEATURES].copy()

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        contamination=CONTAMINATION,
        n_estimators=200,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    df = df.copy()
    df["anomaly_flag"]  = model.predict(X_scaled)          # -1 = anomaly, 1 = normal
    df["risk_score"]    = -model.decision_function(X_scaled)  # higher = riskier
    df["risk_score"]    = df["risk_score"].round(4)

    return df


def classify_risk(score: float) -> str:
    if score >= 0.20:
        return "CRITICAL"
    if score >= 0.10:
        return "HIGH"
    if score >= 0.00:
        return "MEDIUM"
    return "LOW"


def build_report(df: pd.DataFrame) -> dict:
    df = df.copy()
    df["risk_level"] = df["risk_score"].apply(classify_risk)

    threats = df[df["anomaly_flag"] == -1].copy()
    threats = threats.sort_values("risk_score", ascending=False)

    # Per-user aggregation
    user_summary = (
        df.groupby("user")
        .agg(
            total_events=("risk_score", "count"),
            avg_risk_score=("risk_score", "mean"),
            max_risk_score=("risk_score", "max"),
            anomaly_count=("anomaly_flag", lambda x: (x == -1).sum()),
        )
        .reset_index()
        .sort_values("max_risk_score", ascending=False)
    )
    user_summary["avg_risk_score"] = user_summary["avg_risk_score"].round(4)
    user_summary["max_risk_score"] = user_summary["max_risk_score"].round(4)

    report = {
        "summary": {
            "total_events":   int(len(df)),
            "total_threats":  int(len(threats)),
            "threat_rate_pct": round(len(threats) / len(df) * 100, 2),
        },
        "top_risky_users": user_summary.head(5).to_dict(orient="records"),
        "threat_events":   threats.reset_index().to_dict(orient="records"),
        "all_events":      df.reset_index().to_dict(orient="records"),
    }
    return report


def save_report(report: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[baselineiq.detector] Report saved to {path}")


def run() -> dict:
    df = load_data(DATA_PATH)
    scored_df = train_and_score(df)
    report = build_report(scored_df)
    save_report(report, REPORT_PATH)

    summary = report["summary"]
    print(
        f"[baselineiq.detector] {summary['total_events']} events analyzed — "
        f"{summary['total_threats']} threats detected "
        f"({summary['threat_rate_pct']}% threat rate)"
    )
    return report


if __name__ == "__main__":
    run()
