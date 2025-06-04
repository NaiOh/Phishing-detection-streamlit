import streamlit as st
import joblib
import pandas as pd
import numpy as np
from main import extract_features, FEATURE_COLUMNS

# Load the trained model
model = joblib.load("phishing_model.pkl")

# UI
st.title("🔐 URL Phishing Detection")
st.write("Enter a URL below to check if it's **Legitimate** or **Phishing** using a trained machine learning model.")

# Input URL
url = st.text_input("Enter a URL:")

if st.button("Check URL"):
    if url:
        try:
            # Extract features and predict
            features = extract_features(url)
            features_df = pd.DataFrame([features], columns=FEATURE_COLUMNS)

            prediction = model.predict(features_df)
            result = "✅ Legitimate" if prediction[0] == "legitimate" else "🚨 Phishing"

            st.success(f"The URL is classified as: **{result}**")
        except Exception as e:
            st.error(f"An error occurred while processing the URL: {e}")
    else:
        st.warning("Please enter a valid URL.")
