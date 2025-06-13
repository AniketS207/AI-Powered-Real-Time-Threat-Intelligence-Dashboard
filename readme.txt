# 🛡️Threat Intelligence Aggregator + Visualizer

A Streamlit-based web app that fetches threat intelligence data on IP addresses using the VirusTotal v3 API. Users can upload or input IPs manually and visualize risk indicators in real-time.

---

## 🚀 Features

- 🔍 Input IPs manually or upload `.txt` / `.csv` files
- 📡 Fetches threat data from VirusTotal API
- 🟥🟨🟩 Status indicators: malicious, suspicious, clean
- 📊 Displays threat metrics: country, ASN, malicious count, etc.
- 🔐 Secure API key management via `.env` or sidebar input
- 📤 Export all results as downloadable `.csv` file
- 🖥️ Streamlit dashboard with modern, wide layout


## 🛠️ Tech Stack

- Python 3.x
- Streamlit
- Requests
- python-dotenv

---

## 📦 Installation

```bash
git clone https://github.com/<your-username>/virustotal-threat-intel-dashboard.git
cd virustotal-threat-intel-dashboard
python -m venv .venv
.\.venv\Scripts\activate  # Windows
pip install -r requirements.txt
