import streamlit as st
import requests
import csv
import io
import os
from dotenv import load_dotenv

st.set_page_config(page_title="VirusTotal IP Scanner", layout="wide")

# ---- Load environment variables ----
load_dotenv()
api_key = st.sidebar.text_input("🔐 VirusTotal API Key (leave blank to use .env)", type="password")
if not api_key:
    api_key = os.getenv("VT_API_KEY")

# ---- Streamlit UI Setup ----
st.title("🛡️ VirusTotal IP Threat Intelligence")

st.markdown("""
This app checks IP addresses using VirusTotal's API to determine if they are malicious or suspicious.
""")

# ---- Sidebar Inputs ----
st.sidebar.header("🔍 IP Address Input")
ip_input = st.sidebar.text_area("Enter IPs (one per line)")
uploaded_file = st.sidebar.file_uploader("Or upload .txt/.csv file with IPs", type=["txt", "csv"])
limit = st.sidebar.slider("Max IPs to scan", 1, 50, 10)

# ---- Process IP List ----
ip_list = []
if ip_input:
    ip_list = [ip.strip() for ip in ip_input.splitlines() if ip.strip()]
elif uploaded_file:
    content = uploaded_file.read().decode("utf-8").splitlines()
    ip_list = [line.strip() for line in content if line.strip()]
ip_list = ip_list[:limit]

# ---- VirusTotal Lookup Function ----
def get_virustotal_ip_report(api_key, ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# ---- Output Section ----
results = []

if api_key and ip_list:
    st.subheader("🧪 VirusTotal IP Reports")
    for ip in ip_list:
        report = get_virustotal_ip_report(api_key, ip)
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

    # ---- Download CSV ----
    if results:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
        st.download_button(
            label="⬇️ Download Results as CSV",
            data=output.getvalue(),
            file_name="virustotal_  s.csv",
            mime="text/csv"
        )
else:
    st.info("👉 Enter IPs and provide your VirusTotal API key or define it in a `.env` file.")
