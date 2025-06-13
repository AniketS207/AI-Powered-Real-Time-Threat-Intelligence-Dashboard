import streamlit as st
import requests
import csv
import io
import os
from dotenv import load_dotenv

# Set Streamlit config
st.set_page_config(page_title="Threat Intelligence Aggregator + Visualizer", layout="wide")

# Load environment variables
load_dotenv()
api_key = st.sidebar.text_input("🔐 API Key (leave blank to use .env)", type="password")
if not api_key:
    api_key = os.getenv("VT_API_KEY")

# UI Header
st.title("🛡️ Threat Intelligence Aggregator + Visualizer")
st.markdown("""
This app aggregates threat intelligence for IP addresses using public APIs like VirusTotal.
More sources will be added soon (e.g., AbuseIPDB, AlienVault OTX).
""")

# Sidebar input
st.sidebar.header("🔍 Input IP Addresses")
ip_input = st.sidebar.text_area("Enter IPs (one per line)")
uploaded_file = st.sidebar.file_uploader("Or upload a .txt or .csv file", type=["txt", "csv"])
limit = st.sidebar.slider("Max IPs to analyze", 1, 50, 10)

# Process input
ip_list = []
if ip_input:
    ip_list = [ip.strip() for ip in ip_input.splitlines() if ip.strip()]
elif uploaded_file:
    content = uploaded_file.read().decode("utf-8").splitlines()
    ip_list = [line.strip() for line in content if line.strip()]
ip_list = ip_list[:limit]

# Lookup Function (VirusTotal for now)
def get_ip_report_from_virustotal(api_key, ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

# Display Results
results = []
if api_key and ip_list:
    st.subheader("📊 Aggregated Threat Intelligence Reports")
    for ip in ip_list:
        report = get_ip_report_from_virustotal(api_key, ip)
        if report:
            attr = report["data"]["attributes"]
            country = attr.get("country", "N/A")
            asn = attr.get("asn", "N/A")
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            status_icon = "🟥" if malicious > 0 else "🟨" if suspicious > 0 else "🟩"
            st.markdown(f"""
**{status_icon} {ip}**
- Country: `{country}`
- ASN: `{asn}`
- Malicious: **{malicious}**
- Suspicious: **{suspicious}**
""")
            results.append({
                "IP": ip,
                "Country": country,
                "ASN": asn,
                "Malicious": malicious,
                "Suspicious": suspicious
            })

    # Download CSV
    if results:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
        st.download_button(
            label="⬇️ Download Results as CSV",
            data=output.getvalue(),
            file_name="threat_intel_results.csv",
            mime="text/csv"
        )
else:
    st.info("👉 Enter IPs and provide an API key or define it in a `.env` file.")
