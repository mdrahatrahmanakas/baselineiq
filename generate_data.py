"""
generate_data.py
----------------
Simulates realistic Windows Event Log activity for a small organization.
Produces a CSV used as input to the BaselineIQ detection engine.
"""

import pandas as pd
import numpy as np
import os

RANDOM_SEED = 42
rng = np.random.default_rng(RANDOM_SEED)

USERS = [
    "alice.johnson",
    "bob.carter",
    "carol.smith",
    "david.lee",
    "emma.wilson",
]

NUM_NORMAL_EVENTS = 200
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "data", "activity_log.csv")


def generate_normal_events():
    records = []
    for _ in range(NUM_NORMAL_EVENTS):
        user = rng.choice(USERS)
        hour = int(np.clip(rng.normal(loc=10.5, scale=2.0), 7, 18))
        files = int(np.clip(rng.normal(loc=10, scale=4), 1, 30))
        usb = int(rng.random() < 0.02)
        sensitivity = round(float(rng.beta(2, 8)), 3)
        records.append({
            "user": user,
            "hour_of_day": hour,
            "files_accessed": files,
            "usb_event": usb,
            "resource_sensitivity": sensitivity,
        })
    return records


def generate_anomalous_events():
    """Inject known insider-threat scenarios."""
    return [
        # Mass file exfiltration at 2 AM
        {"user": "bob.carter",      "hour_of_day": 2,  "files_accessed": 480, "usb_event": 1, "resource_sensitivity": 0.92},
        {"user": "bob.carter",      "hour_of_day": 3,  "files_accessed": 510, "usb_event": 1, "resource_sensitivity": 0.88},
        # Odd-hours access to sensitive resources
        {"user": "carol.smith",     "hour_of_day": 1,  "files_accessed": 5,   "usb_event": 0, "resource_sensitivity": 0.97},
        # Unusual USB activity during business hours
        {"user": "david.lee",       "hour_of_day": 14, "files_accessed": 320, "usb_event": 1, "resource_sensitivity": 0.85},
        # High-volume access to sensitive data
        {"user": "alice.johnson",   "hour_of_day": 22, "files_accessed": 600, "usb_event": 0, "resource_sensitivity": 0.91},
    ]


def main():
    records = generate_normal_events() + generate_anomalous_events()
    df = pd.DataFrame(records)
    df.index.name = "event_id"
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df.to_csv(OUTPUT_PATH)
    print(f"[baselineiq.data] Wrote {len(df)} records to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
