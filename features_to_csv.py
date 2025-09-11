import os
import sys
import json
import pandas as pd

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.USE_CREDENTIALS",
    "android.permission.WRITE_SETTINGS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG"
}

def json_to_row(json_file, label):
    with open(json_file, "r") as f:
        data = json.load(f)

    row = {
        "num_permissions": len(data.get("permissions", [])),
        "num_dangerous_permissions": sum(1 for p in data.get("permissions", []) if p in DANGEROUS_PERMISSIONS),
        "num_activities": len(data.get("activities", [])),
        "num_services": len(data.get("services", [])),
        "num_receivers": len(data.get("receivers", [])),
        "num_libraries": len(data.get("libraries", [])),
        "num_files": len(data.get("files", [])),
        "is_signed": int(data.get("is_signed", False)),
        "risk_score": data.get("risk_score", 0),
        "label": label
    }
    return row

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python features_to_csv.py <output_csv> <json1>:<label> <json2>:<label> ...")
        sys.exit(1)

    output_csv = sys.argv[1]
    rows = []

    for arg in sys.argv[2:]:
        try:
            file_path, label = arg.split(":")
            rows.append(json_to_row(file_path, int(label)))
        except Exception as e:
            print(f"Error processing {arg}: {e}")

    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)
    print(f"✅ Features saved to {output_csv}")
