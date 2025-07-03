# 🛡️ AI-Powered Real-Time Threat Intelligence Dashboard

A real-time, interactive cyber threat intelligence dashboard built using **Streamlit** and powered by **AI**, providing in-depth analysis of IP addresses through multiple public threat feeds. The tool combines data from **AbuseIPDB**, **AlienVault OTX**, and **VirusTotal**, enriched with **machine learning-based threat classification**, **automated email alerts**, and **SQLite-based logging** for historical tracking.

---

## 🚀 Key Features

* 🔎 **Flexible IP Input**

  * Enter IPs manually or upload `.txt` / `.csv` files for bulk scanning.

* 🧠 **AI Threat Classification**

  * Uses a trained ML model (e.g., Random Forest) to predict threat levels: `Low`, `Medium`, or `High`.

* 🌐 **Multi-Source Threat Feed Aggregation**

  * **AbuseIPDB**: Reputation and abuse confidence
  * **AlienVault OTX**: Community-powered IOCs
  * **VirusTotal**: Antivirus and behavioral engine reports

* 📊 **Real-Time Threat Visualization**

  * Interactive charts showing risk levels, country distribution, and threat categories.

* 🔐 **Secure API Key Management**

  * Store keys in `.env` file or input securely via Streamlit sidebar.

* 📧 **Automated Email Alerts**

  * Sends real-time SMTP alerts when high-risk IPs (e.g., abuse score > 90) are detected.

* 🗃️ **SQLite-Based Logging**

  * Stores results locally for future reference and auditability.

* 📄 **Export Results**

  * Download threat analysis reports as `.csv`.

* 🧰 **Modular & Extensible Codebase**

  * Easily extend with other threat intelligence APIs (Shodan, GreyNoise, Censys, etc.)

---

## 🛠️ Tech Stack

* **Python 3.x**
* **Streamlit** – Frontend UI
* **Requests** – API integration
* **Scikit-learn** – AI risk model
* **Plotly / Pandas** – Visualization
* **SQLite3** – Local data logging
* **python-dotenv** – Secure API key management
* **smtplib** – Email alerting

---

## 📦 Installation

```bash
git clone https://github.com/<your-username>/ai-threat-intel-dashboard.git
cd ai-threat-intel-dashboard

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
.\.venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Run the App

```bash
streamlit run app.py
```

Visit: [http://localhost:8501](http://localhost:8501)

---

## 🔐 .env Configuration (Optional)

Create a `.env` file for your API keys and email credentials:

```env
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_otx_key

EMAIL_FROM=you@gmail.com
EMAIL_TO=you@gmail.com
EMAIL_PASS=your_gmail_app_password
```

---

## 📊 Sample IPs to Test

```text
45.129.2.59
185.38.175.132
222.186.30.120
23.154.177.4
121.148.236.5
193.106.191.35
```

---

## 🔮 Coming Soon

* 📲 Telegram alert integration
* ⚠️ Anomaly detection using unsupervised ML
* ☁️ Cloud dashboard + MongoDB sync
* 🔎 IOC filtering, search, and tagging

---

## 🧠 Author

**Aniket Sinha**
Cybersecurity Enthusiast | Threat Hunter | SOC Analyst (Aspirant)

---

## 📜 License

MIT License – feel free to fork and extend.
