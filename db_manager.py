import sqlite3
from datetime import datetime
import os

DB_FILE = "threat_reports.db"

# Initialize DB & Table
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            abuse_confidence INTEGER,
            malicious INTEGER,
            ai_risk TEXT,
            source TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

# Insert Report
def save_report(report):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO threat_reports (ip, abuse_confidence, malicious, ai_risk, source, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        report.get("IP"),
        report.get("Abuse Confidence", 0),
        report.get("Malicious", 0),
        report.get("AI Risk", "N/A"),
        report.get("Source", "Unknown"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

# Optional: Fetch All Reports
def get_all_reports():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM threat_reports ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return rows
