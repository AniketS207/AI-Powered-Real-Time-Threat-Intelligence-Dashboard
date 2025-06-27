# 🛡️ AI-Powered Threat Intelligence Aggregator & Visualizer

A real-time, interactive threat intelligence dashboard built with **Streamlit**. This tool aggregates and visualizes threat data for IP addresses using APIs like **VirusTotal**, **AbuseIPDB**, and **AlienVault OTX**, enabling analysts to make informed decisions quickly.

---

## 🚀 Key Features

- 🔎 **IP Input Options**  
  Enter IP addresses manually or upload `.txt` / `.csv` files for bulk scanning.

- 🧠 **Multi-Source Threat Intelligence**  
  Fetch data from:
  - [VirusTotal](https://www.virustotal.com/)
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [AlienVault OTX](https://otx.alienvault.com/)

- 📈 **Real-Time Threat Visualization**  
  View enriched metadata: country, ASN, threat categories, confidence scores, and more.

- 🔐 **Secure API Key Handling**  
  Store keys safely in `.env` or input them manually in-app.

- 📤 **Exportable Reports**  
  Download aggregated results as a `.csv` file.

- 💡 **Modular & Scalable**  
  Easily plug in more sources (e.g., GreyNoise, Shodan, Censys) to expand intelligence coverage.

- 🖥️ **Modern Streamlit UI**  
  Responsive, wide-layout dashboard for seamless threat monitoring.

---

## 🛠️ Tech Stack

- **Python 3.x**
- **Streamlit**
- **Requests**
- **python-dotenv**

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
