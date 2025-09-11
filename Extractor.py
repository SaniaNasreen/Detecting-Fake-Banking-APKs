from androguard.core.apk import APK
import os
import sys
import json
import joblib
import pandas as pd

# List of dangerous permissions
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

# Load ML model (if available)
MODEL_PATH = "apk_detector.pkl"
ml_model = None
if os.path.exists(MODEL_PATH):
    ml_model = joblib.load(MODEL_PATH)


def extract_apk_features(apk_path):
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    
    apk = APK(apk_path)

    features = {
        "app_name": apk.get_app_name(),
        "package_name": apk.get_package(),
        "version_code": apk.get_androidversion_code(),
        "version_name": apk.get_androidversion_name(),
        "main_activity": apk.get_main_activity(),
        "activities": apk.get_activities(),
        "services": apk.get_services(),
        "receivers": apk.get_receivers(),
        "providers": apk.get_providers(),
        "permissions": apk.get_permissions(),
        "libraries": apk.get_libraries(),
        "files": apk.get_files(),
        "is_signed": apk.is_signed(),
    }

    # Certificates
    certs = []
    try:
        if hasattr(apk, "get_certificates"):
            raw_certs = apk.get_certificates()
            if raw_certs:
                for c in raw_certs:
                    try:
                        certs.append({
                            "subject": str(c.subject),
                            "issuer": str(c.issuer),
                            "serial_number": str(c.serial_number)
                        })
                    except Exception as ce:
                        certs.append(f"Partial certificate read failed: {ce}")
        elif hasattr(apk, "get_certificates_der"):
            certs = [cert.decode("utf-8", errors="ignore") for cert in apk.get_certificates_der()]
        elif hasattr(apk, "get_signature_names"):
            certs = apk.get_signature_names()
    except Exception as e:
        certs = [f"Certificate extraction failed: {e}"]

    features["certificates"] = certs

    # Risk scoring
    score, reasons = score_apk(features)
    features["risk_score"] = score
    features["suspicious_reasons"] = reasons

    return features


def score_apk(features):
    score = 0
    reasons = []

    # Dangerous permissions
    for perm in features["permissions"]:
        if perm in DANGEROUS_PERMISSIONS:
            score += 2
            reasons.append(f"Dangerous permission: {perm}")

    # Unsigned app
    if not features["is_signed"]:
        score += 3
        reasons.append("App is not signed (suspicious).")

    # Package name heuristic
    pkg = features["package_name"].lower()
    if "bank" in pkg and "official" not in pkg:
        score += 2
        reasons.append("Package name contains 'bank' but not marked official.")

    # Too many activities
    if len(features["activities"]) > 50:
        score += 1
        reasons.append("Unusually high number of activities (possible obfuscation).")

    return score, reasons


def predict_with_model(features):
    """Use ML model if available"""
    if ml_model is None:
        return None, None

    row = {
        "num_permissions": len(features.get("permissions", [])),
        "num_dangerous_permissions": sum(1 for p in features.get("permissions", []) if p in DANGEROUS_PERMISSIONS),
        "num_activities": len(features.get("activities", [])),
        "num_services": len(features.get("services", [])),
        "num_receivers": len(features.get("receivers", [])),
        "is_signed": int(features.get("is_signed", False)),
        "risk_score": features.get("risk_score", 0),
    }
    df = pd.DataFrame([row])
    prediction = ml_model.predict(df)[0]
    proba = ml_model.predict_proba(df)[0]
    return prediction, proba


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extractor.py <apk_file>")
        sys.exit(1)

    apk_file = sys.argv[1]

    try:
        data = extract_apk_features(apk_file)
        print(json.dumps(data, indent=4))

        # Heuristic verdict
        if data["risk_score"] >= 5:
            print("\n⚠️ WARNING: This APK is likely malicious/fake!\n")
        elif 1 <= data["risk_score"] < 5:
            print("\n⚠️ CAUTION: This APK shows suspicious behavior. Review carefully.\n")
        else:
            print("\n✅ This APK looks safe (based on static analysis).\n")

        # ML verdict
        if ml_model:
            prediction, proba = predict_with_model(data)
            if prediction == 1:
                print(f"🔥 ML Verdict: FAKE/MALICIOUS (Confidence Fake: {proba[1]*100:.2f}%)\n")
            else:
                print(f"✅ ML Verdict: LEGIT (Confidence Legit: {proba[0]*100:.2f}%)\n")
        else:
            print("⚠️ ML model not found. Train it first using train_model.py.\n")

    except Exception as e:
        print(f"Error: {e}")
