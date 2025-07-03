# alert_manager.py

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

EMAIL_FROM = os.getenv("EMAIL_FROM")
EMAIL_TO = os.getenv("EMAIL_TO")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def check_alerts(report):
    ip = report.get("IP")
    abuse = report.get("Abuse Confidence", 0)
    malicious = report.get("Malicious", 0)

    # Define alert condition
    if abuse >= 90 or malicious >= 80:
        msg = (
            f"🚨 Threat Alert 🚨\n"
            f"IP: {ip}\n"
            f"Abuse Score: {abuse}\n"
            f"Malicious: {malicious}\n"
            f"AI Risk: {report.get('AI Risk', 'N/A')}\n"
            f"Source: {report.get('Source', 'Unknown')}"
        )
        if EMAIL_FROM and EMAIL_TO and EMAIL_PASS:
            send_email_alert(ip, msg)

def send_email_alert(ip, message):
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg["Subject"] = f"🚨 Threat Alert: {ip}"

        body = f"{message}\n\n⚠️ A potential threat has been detected from IP: {ip}. Please investigate immediately."
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_FROM, EMAIL_PASS)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()
        print(f"[✔] Email alert sent for {ip}")
    except Exception as e:
        print("Email alert failed:", e)