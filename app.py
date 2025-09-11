import streamlit as st
import os
import json
import joblib
from extractor import extract_apk_info

# Load trained model
MODEL_PATH = "models/apk_detector.pkl"
model = joblib.load(MODEL_PATH)

st.title("📱 APK Fake/Legit Detector")
st.write("Upload an APK file and let’s check if it’s **Legit** or **Fake** using static analysis + ML 🚀")

uploaded_file = st.file_uploader("Choose an APK file", type=["apk"])

if uploaded_file is not None:
    # Save temporarily
    apk_path = os.path.join("temp.apk")
    with open(apk_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    # Extract features
    st.info("Extracting features...")
    features = extract_apk_info(apk_path)

    # Convert features to ML-ready format (binary indicators, counts, etc.)
    feature_vector = [
        len(features.get("permissions", [])),
        len(features.get("activities", [])),
        len(features.get("services", [])),
        len(features.get("receivers", [])),
        int(features.get("is_signed", False)),
    ]

    # Predict
    prediction = model.predict([feature_vector])[0]
    label = "✅ Legit APK" if prediction == 0 else "⚠️ Fake APK Detected!"

    st.subheader("Result:")
    st.success(label) if prediction == 0 else st.error(label)

    # Show raw extracted info
    with st.expander("🔎 See Extracted APK Info"):
        st.json(features)
