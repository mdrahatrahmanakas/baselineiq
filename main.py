"""
main.py
-------
Entry point. Runs the full BaselineIQ pipeline:
  1. Generate (or load) activity log data
  2. Detect anomalies with Isolation Forest
  3. Evaluate and dispatch alerts
"""

import argparse
import sys

import generate_data
import detector
import alerts


def parse_args():
    parser = argparse.ArgumentParser(
        description="BaselineIQ Insider Threat Detection Pipeline"
    )
    parser.add_argument(
        "--skip-generate",
        action="store_true",
        help="Skip data generation and use existing activity_log.csv",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print("=" * 60)
    print("  BaselineIQ — Insider Threat Detection Engine")
    print("=" * 60)

    if not args.skip_generate:
        print("\n[1/3] Generating activity log data...")
        generate_data.main()
    else:
        print("\n[1/3] Skipping data generation (--skip-generate flag set).")

    print("\n[2/3] Running anomaly detection...")
    report = detector.run()

    print("\n[3/3] Evaluating alerts...")
    alerts.run()

    print("\n" + "=" * 60)
    summary = report["summary"]
    print(f"  Total Events Analyzed : {summary['total_events']}")
    print(f"  Threats Detected      : {summary['total_threats']}")
    print(f"  Threat Rate           : {summary['threat_rate_pct']}%")
    print("=" * 60)
    print("\nPipeline complete. Open dashboard.html in a browser to review results.")
    print(f"Risk report: data/risk_report.json")
    print(f"Alert log  : alerts/alert_log.txt")


if __name__ == "__main__":
    main()
