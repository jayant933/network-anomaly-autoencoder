"""
reports.py

Generates downloadable PDF and CSV reports of detected flows.
PDF uses reportlab. Install: pip install reportlab
"""

import csv
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


def generate_csv_report(flows, stats):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Time", "Source", "Destination", "Protocol", "Reconstruction Error", "Verdict"])
    for f in flows:
        writer.writerow([f["time"], f["src"], f["dst"], f["proto"], f["error"], f["tag"]])
    writer.writerow([])
    writer.writerow(["Summary"])
    for tag, count in stats.items():
        writer.writerow([tag, count])
    return buf.getvalue().encode("utf-8")


def generate_pdf_report(flows, stats):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("NetGuard AI &mdash; Network Anomaly Report", styles["Title"]))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Spacer(1, 14))

    elements.append(Paragraph("Summary", styles["Heading2"]))
    summary_data = [["Verdict", "Count"]] + [[k, str(v)] for k, v in stats.items()]
    summary_table = Table(summary_data, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7b5cff")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Recent Flows", styles["Heading2"]))
    flow_data = [["Time", "Source", "Destination", "Proto", "Error", "Verdict"]]
    for f in flows[:100]:
        flow_data.append([f["time"], f["src"], f["dst"], f["proto"], str(f["error"]), f["tag"]])
    flow_table = Table(flow_data, hAlign="LEFT", repeatRows=1)
    flow_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#35d0ff")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
    ]))
    elements.append(flow_table)

    doc.build(elements)
    buf.seek(0)
    return buf.getvalue()