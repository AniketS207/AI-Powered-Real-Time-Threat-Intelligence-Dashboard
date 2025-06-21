# 🛡️ Threat Intelligence Aggregator + Visualizer

A Streamlit-based web app that fetches and visualizes threat intelligence for IP addresses using multiple APIs including VirusTotal, AbuseIPDB, and AlienVault OTX. Users can input IPs manually or via file upload and download aggregated threat reports.

---

## 🚀 Features

- 🔍 Input IPs manually or upload `.txt` / `.csv` files
- 📡 Supports multiple APIs: VirusTotal, AbuseIPDB, AlienVault OTX
- 📊 Displays threat metrics: country, ASN, reputation, scores, and more
- 🟥🟨🟩 Status indicators based on API data
- 🔐 Secure API key management via `.env` or manual entry
- 📤 Export results as downloadable `.csv` file
- 🖥️ Streamlit dashboard with modern wide layout
- 🔄 Easy to extend with more APIs (e.g., GreyNoise, Shodan)

---

## 🛠️ Tech Stack

- Python 3.x
- Streamlit
- Requests
- python-dotenv

---

📦 Installation

git clone https://github.com/<your-username>/threat-intel-visualizer.git
cd threat-intel-visualizer
python -m venv .venv
source .venv/bin/activate  (Linux/macOS)
.\.venv\Scripts\activate    (Windows)

pip install -r requirements.txt

---

▶️ Running the App

streamlit run app.py

