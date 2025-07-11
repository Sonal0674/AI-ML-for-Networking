# 🔐 SQLi & XSS Payload Detection using Machine Learning

This project is a lightweight **Streamlit-based web application** that detects whether a given HTTP payload is **malicious** (e.g., SQL injection or Cross-site Scripting) or **benign** using a simple **Random Forest** machine learning model.

## 🚀 Features

- Real-time detection of malicious payloads.
- Identifies potential SQL injection (`SQLi`) and Cross-site Scripting (`XSS`) patterns.
- Uses handcrafted features extracted from the payload string.
- Built with `Streamlit`, `Pandas`, `scikit-learn`.

---

## 🧠 How It Works

1. A small, labeled dataset of payloads is used to train a **Random Forest Classifier**.
2. For each payload, the following features are extracted:
   - `length`: Total number of characters in the payload.
   - `num_special_chars`: Count of special characters.
   - `num_keywords`: Occurrence of suspicious keywords (`select`, `drop`, `script`, etc.).
   - `has_http`: Checks for presence of HTTP/HTTPS links.
3. The trained model predicts whether the input is **malicious** (`1`) or **benign** (`0`).
4. User enters a payload via a text area, and the app provides a prediction result.

---

## 🛠️ Tech Stack

- Python 🐍
- Streamlit 🌐
- scikit-learn 🎯
- Pandas 📊
- Regex (re) 🔍

---

## 💡 Example Payloads

| Payload                              | Label (Malicious=1, Benign=0) |
|--------------------------------------|-------------------------------|
| `SELECT * FROM users WHERE...`       | 1                             |
| `<script>alert('XSS')</script>`      | 1                             |
| `https://example.com/index.html`     | 0                             |
| `admin' OR '1'='1`                   | 1                             |
| `Nice article about AI!`            | 0                             |

---

## 🔧 Setup Instructions

1. **Clone this repository**
   ```bash
   git clone https://github.com/your-username/sqlxss-detector.git
   cd sqlxss-detector
