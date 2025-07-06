# 🛡️ AI-Powered Real-Time Threat Intelligence Dashboard

A real-time, interactive cyber threat intelligence dashboard built using **Streamlit** and powered by **AI**, offering deep IP threat analysis from multiple open-source feeds. It leverages **VirusTotal**, **AbuseIPDB**, and **AlienVault OTX**, enriched by a **machine learning risk model**, **automated email alerting**, and **SQLite logging**. Built for threat hunters, analysts, and cybersecurity enthusiasts.



## 🚀 Key Features

* 🔎 **Flexible IP Input**
  * Enter IPs manually or upload `.txt` / `.csv` files for bulk scanning.

* 🧠 **AI-Powered Risk Prediction**
  * Uses a trained Random Forest model to classify IPs into `Low`, `Medium`, or `High` risk.

* 🌐 **Multi-Source Threat Intelligence**
  * Pulls data from:
    * **AbuseIPDB** – abuse score, ISP, country
    * **VirusTotal** – AV engine verdicts & behavior
    * **AlienVault OTX** – community threat intelligence

* 📧 **Real-Time Email Alerts**
  * Sends SMTP alerts when high-risk IPs are detected (`Abuse Score > 0` or `Malicious > 0`).

* 📊 **Interactive Dashboards**
  * Charts for country-based threats, malicious/suspicious activity, and risk classification.

* 📄 **PDF + CSV Export**
  * Export reports with both raw results and visual threat summaries.

* 🗃️ **SQLite Logging**
  * All scans are logged and viewable within the Streamlit dashboard.

* 🔐 **Secure Key Handling**
  * API keys can be securely loaded from `.env` or entered at runtime.

* ⚙️ **Scalable & Modular Architecture**
  * Easily extend with more feeds like Shodan, Censys, GreyNoise, etc.



## 🛠️ Tech Stack

* **Python 3.x**
* **Streamlit** – UI & interactivity
* **Scikit-learn** – AI model for threat classification
* **Plotly / Pandas** – Visualization
* **Requests** – API consumption
* **SQLite3** – Local data storage
* **smtplib** – SMTP alerting
* **python-dotenv** – API key & credential management



## 📦 Installation

git clone https://github.com/<your-username>/ai-threat-intel-dashboard.git
cd ai-threat-intel-dashboard

python -m venv .venv
source .venv/bin/activate  # macOS/Linux
.\.venv\Scripts\activate   # Windows

pip install -r requirements.txt



## ▶️ Run the App

streamlit run app.py



## 🔐 .env Configuration (Optional)

Create a .env file for API keys and SMTP credentials:

VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_otx_api_key

EMAIL_FROM=you@gmail.com
EMAIL_TO=you@gmail.com
EMAIL_PASS=your_gmail_app_password



## 📊 Sample IPs to Test

185.220.101.1
45.129.2.59
193.106.191.35
23.154.177.4
222.186.30.120
121.148.236.5


## 🔮 Coming Soon

* 📲 Telegram alert integration
* ⚠️ Anomaly detection using unsupervised ML
* ☁️ Cloud dashboard + MongoDB sync
* 🔎 IOC filtering, search, and tagging



## 🧠 Author

**AniketS207**
Cybersecurity Enthusiast | Threat Hunter | SOC Analyst (Aspirant)


## 📜 License

MIT License – feel free to fork and extend.
