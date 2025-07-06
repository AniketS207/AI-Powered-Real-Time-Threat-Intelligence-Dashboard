import streamlit as st
import requests
import csv
import io
import os
import joblib
import plotly.express as px
import pandas as pd
from dotenv import load_dotenv
import alert_manager
from db_manager import init_db, save_report, get_all_reports
from report_generator import export_pdf_report
from intel_utils import get_virustotal, get_abuseipdb, get_otx, get_hybrid_report, api_function_map

st.set_page_config(page_title="🛡️ AI Threat Intelligence Dashboard", layout="wide")
load_dotenv()
init_db()

@st.cache_resource
def load_model():
    return joblib.load("rf_threat_model.pkl")

rf_model = load_model()
st.sidebar.success("✅ AI Model Loaded")

if "results" not in st.session_state:
    st.session_state.results = []
if "pdf_ready" not in st.session_state:
    st.session_state.pdf_ready = False
if "csv_data" not in st.session_state:
    st.session_state.csv_data = ""
if "title_shown" not in st.session_state:
    st.session_state.title_shown = False

if not st.session_state.title_shown:
    st.title("🛡️ AI-Powered Real-Time Threat Intelligence Dashboard")
    st.session_state.title_shown = True

api_key_env_map = {
    "VirusTotal": "VT_API_KEY",
    "AbuseIPDB": "ABUSEIPDB_API_KEY",
    "AlienVault OTX": "OTX_API_KEY"
}

with st.sidebar.form("input_form"):
    st.header("🔧 Configuration")
    api_choice = st.selectbox("Select Threat Intelligence API", [
        "Hybrid Fallback", "VirusTotal", "AbuseIPDB", "AlienVault OTX"
    ])
    user_api_key = st.text_input("🔐 API Key (leave blank to use .env)", type="password")

    st.header("🔍 Input IP Addresses")
    ip_input = st.text_area("Enter IPs (one per line)")
    uploaded_file = st.file_uploader("Or upload .txt/.csv", type=["txt", "csv"])
    limit = st.slider("Max IPs to analyze", 1, 50, 10)

    fetch_btn = st.form_submit_button("🚀 Fetch Threat Reports")

ip_list = []
if ip_input:
    ip_list = [ip.strip() for ip in ip_input.splitlines() if ip.strip()]
elif uploaded_file:
    content = uploaded_file.read().decode("utf-8").splitlines()
    ip_list = [line.strip() for line in content if line.strip()]
ip_list = ip_list[:limit]

def run_analysis(ip_list):
    results = []
    api_keys = {
        "VirusTotal": os.getenv("VT_API_KEY"),
        "AbuseIPDB": os.getenv("ABUSEIPDB_API_KEY"),
        "AlienVault OTX": os.getenv("OTX_API_KEY")
    }

    for ip in ip_list:
        try:
            if api_choice == "Hybrid Fallback":
                report = get_hybrid_report(ip, api_keys, user_key=user_api_key)
            else:
                key = user_api_key if user_api_key else os.getenv(api_key_env_map.get(api_choice, ""))
                report = api_function_map[api_choice](ip, key)

            if not report:
                continue

            features_df = pd.DataFrame([{
                "Malicious": report.get("Malicious", 0) or 0,
                "Suspicious": report.get("Suspicious", 0) or 0,
                "Abuse Confidence": report.get("Abuse Confidence", 0) or 0,
                "Reputation": report.get("Reputation", 0) or 0
            }])

            try:
                risk = rf_model.predict(features_df)[0]
                report["AI Risk"] = risk
            except:
                report["AI Risk"] = "Error"

            try:
                if report.get("Abuse Confidence", 0) > 0 or report.get("Malicious", 0) > 0:
                    alert_manager.send_email_alert(report['IP'], report)
                    st.success(f"✅ Email alert sent for: {report['IP']}")
            except Exception as e:
                st.error(f"❌ Failed to send email for {report['IP']}: {str(e)}")

            save_report(report)
            results.append(report)
        except Exception as e:
            st.error(f"Error processing {ip}: {e}")
            continue
    return results

def render_visualizations():
    df = pd.DataFrame(st.session_state.results)

    if "Country" in df.columns:
        country_counts = df["Country"].value_counts().reset_index()
        country_counts.columns = ["Country", "Count"]
        bar_fig = px.bar(country_counts, x="Country", y="Count", title="🌍 Top Threat Source Countries",
                         color="Count", color_continuous_scale="reds")
        st.plotly_chart(bar_fig, use_container_width=True)

    if "Malicious" in df.columns and "Suspicious" in df.columns:
        threat_summary = pd.DataFrame({
            "Threat Type": ["Malicious", "Suspicious"],
            "Count": [df["Malicious"].sum(), df["Suspicious"].sum()]
        })
        line_fig = px.line(threat_summary, x="Threat Type", y="Count", markers=True,
                           title="📈 Threat Detection Summary")
        st.plotly_chart(line_fig, use_container_width=True)

    with st.expander("📂 View Stored Reports"):
        stored = get_all_reports()
        if stored:
            df_hist = pd.DataFrame(stored, columns=["ID", "IP", "Abuse", "Malicious", "AI Risk", "Source", "Timestamp"])
            st.dataframe(df_hist)
        else:
            st.info("No historical data found.")

if fetch_btn and ip_list:
    st.session_state.results = run_analysis(ip_list)
    if st.session_state.results:
        # Save CSV once
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=st.session_state.results[0].keys())
        writer.writeheader()
        writer.writerows(st.session_state.results)
        st.session_state.csv_data = output.getvalue()

        # Save PDF once
        sample_report = st.session_state.results[0]
        chart_data = {
            "Abuse Score": sample_report.get("Abuse Confidence", 0),
            "Malicious": sample_report.get("Malicious", 0),
            "Suspicious": sample_report.get("Suspicious", 0),
            "Reputation": sample_report.get("Reputation", 0)
        }
        export_pdf_report(sample_report, chart_data)
        st.session_state.pdf_ready = True

if st.session_state.results:
    st.subheader("📊 Threat Reports")
    for report in st.session_state.results:
        st.markdown(f"### 🔎 {report['IP']}")
        for k, v in report.items():
            if k != "IP":
                st.markdown(f"- **{k}**: `{v}`")
    render_visualizations()

    # Only show after results are ready
    if st.session_state.pdf_ready:
        with open("Threat_Report.pdf", "rb") as pdf_file:
            st.download_button("⬇️ Download PDF Report", data=pdf_file, file_name="Threat_Report.pdf", mime="application/pdf")

    if st.session_state.csv_data:
        st.download_button("⬇️ Download CSV", st.session_state.csv_data, "threat_reports.csv", "text/csv")
    