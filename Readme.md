# 🛡️ AI-Powered Threat Intelligence Aggregator & Visualizer

A real-time, interactive threat intelligence dashboard built with **Streamlit**. This tool aggregates and visualizes threat data for IP addresses using APIs like **VirusTotal**, **AbuseIPDB**, and **AlienVault OTX**, enriched with **AI risk classification**, **email alerts**, and **SQLite-based historical logging**.

---

## 🚀 Key Features

- 🔎 **IP Input Options**  
  Enter IP addresses manually or upload `.txt` / `.csv` files for bulk scanning.

- 🧠 **AI Risk Classification**  
  Uses a trained ML model to classify threat level (e.g., High / Medium / Low).

- 🧰 **Multi-Source Threat Intelligence**  
  Fetch data from:
  - [VirusTotal](https://www.virustotal.com/)
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [AlienVault OTX](https://otx.alienvault.com/)

- 📊 **Real-Time Threat Visualization**  
  Dynamic charts for threat distribution by country and type.

- 🔐 **Secure API Key Handling**  
  Store API keys in `.env` or input manually via sidebar.

- 📧 **Email Alert System**  
  Sends alerts via SMTP when critical threats are detected (e.g., Abuse Score > 90).

- 📂 **SQLite Logging**  
  All analyzed reports are stored in a local database for historical review.

- 📄 **Exportable Reports**  
  Download all scan results as a `.csv` file.

- 💻 **Modular & Scalable Codebase**  
  Easily extendable to other data sources like GreyNoise, Shodan, Censys, etc.

---

## 🛠️ Tech Stack

- **Python 3.x**
- **Streamlit**
- **Scikit-learn** (for AI)
- **Requests**
- **Plotly**
- **python-dotenv**
- **SQLite3**

---

## 📦 Installation

```bash
git clone https://github.com/<your-username>/threat-intel-visualizer.git
cd threat-intel-visualizer

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate     # Linux/macOS
.\.venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Running the App

```bash
streamlit run app.py
```

Then open the browser at `http://localhost:8501`

---

## 🔧 Optional Configuration (.env)

Create a `.env` file for secure API and email credentials:

```env
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_otx_key

EMAIL_FROM=your_gmail@gmail.com
EMAIL_TO=recipient@gmail.com
EMAIL_PASS=your_gmail_app_password
```

---

## 🔹 Coming Soon

- Telegram alerts
- Anomaly detection
- MongoDB sync
- Dashboard filtering/search

---

## 📊 Sample Threat IPs to Test

```text
45.129.2.59
185.38.175.132
222.186.30.120
23.154.177.4
121.148.236.5
193.106.191.35
