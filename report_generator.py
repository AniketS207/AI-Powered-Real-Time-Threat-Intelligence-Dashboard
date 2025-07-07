from fpdf import FPDF
import matplotlib.pyplot as plt
import os

def export_pdf_report(ip_data, chart_data, filename="Threat_Report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Incident Report - AI Threat Detection", ln=True, align="C")

    pdf.ln(10)
    pdf.set_font("Arial", size=12)

    for key, value in ip_data.items():
        # Rename 'AI Risk' to 'Risk' for display purposes
        if key == "AI Risk":
            key = "Risk"
        try:
            text_value = str(value)
        except Exception:
            text_value = "Error"
        pdf.cell(0, 10, f"{key}: {text_value}", ln=True)

    # Chart generation
    plt.figure(figsize=(4, 3))
    labels = list(chart_data.keys())
    values = list(chart_data.values())
    plt.bar(labels, values, color="tomato")
    chart_path = "chart.png"
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()

    # Add chart to PDF
    pdf.image(chart_path, x=30, y=None, w=150)
    os.remove(chart_path)

    # Save PDF
    pdf.output(filename)
