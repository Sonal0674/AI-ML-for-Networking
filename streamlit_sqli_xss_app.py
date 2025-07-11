
import streamlit as st
import pandas as pd
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Sample dataset
data = {
    'payload': [
        "SELECT * FROM users WHERE username = 'admin' --",
        "<script>alert('XSS')</script>",
        "https://example.com/index.html",
        "admin' OR '1'='1",
        "https://secure-login.com/login?user=guest",
        "<img src=x onerror=alert(1)>",
        "DROP TABLE students",
        "Nice article about AI!",
        "admin' --",
        "Good content, thanks!"
    ],
    'label': [1, 1, 0, 1, 0, 1, 1, 0, 1, 0]  # 1: malicious, 0: benign
}

df = pd.DataFrame(data)

# Feature extraction
def extract_features(payload):
    return {
        'length': len(payload),
        'num_special_chars': len(re.findall(r'[^\w\s]', payload)),
        'num_keywords': len(re.findall(r"(select|drop|script|alert|or|--)", payload, re.IGNORECASE)),
        'has_http': int("http" in payload or "https" in payload)
    }

features_df = df['payload'].apply(lambda x: pd.Series(extract_features(x)))
features_df['label'] = df['label']

# Train model
X = features_df.drop('label', axis=1)
y = features_df['label']
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X, y)

# Streamlit UI
st.title("🔐 SQLi & XSS Payload Detection")
st.write("Enter an HTTP payload to detect whether it is **malicious (SQLi/XSS)** or **benign** using ML.")

user_input = st.text_area("Enter HTTP Payload", height=150)

if st.button("Analyze"):
    if user_input:
        input_features = extract_features(user_input)
        input_df = pd.DataFrame([input_features])
        prediction = rf.predict(input_df)[0]
        result = "🚨 Malicious (SQLi/XSS Detected)" if prediction == 1 else "✅ Benign Payload"
        st.subheader("Result:")
        st.success(result if prediction == 0 else result)
    else:
        st.warning("Please enter a payload to analyze.")
