import json
import pandas as pd
import joblib
import sys

# same dangerous permissions set as before
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

def json_to_features(json_file):
    with open(json_file, "r") as f:
        data = json.load(f)

    row = {
        "num_permissions": len(data.get("permissions", [])),
        "num_dangerous_permissions": sum(1 for p in data.get("permissions", []) if p in DANGEROUS_PERMISSIONS),
        "num_activities": len(data.get("activities", [])),
        "num_services": len(data.get("services", [])),
        "num_receivers": len(data.get("receivers", [])),
        "is_signed": int(data.get("is_signed", False)),
        "risk_score": data.get("risk_score", 0),
    }
    return pd.DataFrame([row])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python predict.py <json_file>")
        sys.exit(1)

    json_file = sys.argv[1]

    # load trained model
    model = joblib.load("apk_detector.pkl")

    # convert json -> features -> predict
    X = json_to_features(json_file)
    prediction = model.predict(X)[0]
    proba = model.predict_proba(X)[0]

    print(f"\n🔎 Analyzing: {json_file}")
    print(f"Prediction: {'FAKE/MALICIOUS' if prediction == 1 else 'LEGIT'}")
    print(f"Confidence → Legit: {proba[0]*100:.2f}% | Fake: {proba[1]*100:.2f}%\n")
