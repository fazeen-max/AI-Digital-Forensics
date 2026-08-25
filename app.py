from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from asyncio import events
import json
from datetime import datetime

from flask import Flask, render_template,request,redirect, url_for, session, send_file
import pandas as pd
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "analysis")))
from analysis.investigation_engine import load_data, analyze_events

app = Flask(__name__)
app.secret_key = "ai-digital-forensics-secret-key"


@app.route("/")
def dashboard():
    logs, model = load_data()
    events = analyze_events(logs, model)

    total_events = len(events)

    normal_count = (
        events["final_threat"] == "NORMAL"
    ).sum()

    suspicious_count = (
        events["final_threat"] == "SUSPICIOUS"
    ).sum()

    malicious_count = (
        events["final_threat"] == "MALICIOUS"
    ).sum()

    return render_template(
        "dashboard.html",
        events=events.to_dict("records"),
        total_events=total_events,
        normal_count=normal_count,
        suspicious_count=suspicious_count,
        malicious_count=malicious_count
    )
@app.route("/upload")
def upload_page():
    return render_template("upload.html")


def save_investigation_history(
    filename,
    total_events,
    normal_count,
    suspicious_count,
    malicious_count
):

    history_file = os.path.join(
        "history",
        "investigations.json"
    )

    with open(history_file, "r", encoding="utf-8") as file:
        history = json.load(file)

    investigation = {
        "filename": filename,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_events": total_events,
        "normal": normal_count,
        "suspicious": suspicious_count,
        "malicious": malicious_count
    }

    history.append(investigation)

    with open(history_file, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=4)


@app.route("/history")
def history_page():

    history_file = os.path.join(
        "history",
        "investigations.json"
    )

    with open(history_file, "r", encoding="utf-8") as file:
        history = json.load(file)

    return render_template(
        "history.html",
        history=history
    )
@app.route("/report")
def report_page():

    report_data = session.get("report_data")

    if not report_data:
        return "No investigation report available. Please analyze evidence first."

    events = report_data["events"]

    normal_count = sum(
        1 for event in events
        if event["final_threat"] == "NORMAL"
    )

    suspicious_count = sum(
        1 for event in events
        if event["final_threat"] == "SUSPICIOUS"
    )

    malicious_count = sum(
        1 for event in events
        if event["final_threat"] == "MALICIOUS"
    )

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30
    )

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            "AI DIGITAL FORENSICS",
            styles["Title"]
        )
    )

    story.append(
        Paragraph(
            "Investigation Report",
            styles["Heading2"]
        )
    )

    story.append(Spacer(1, 15))

    summary_data = [
        ["Evidence File", report_data["filename"]],
        ["Total Events", str(len(events))],
        ["Normal", str(normal_count)],
        ["Suspicious", str(suspicious_count)],
        ["Malicious", str(malicious_count)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[140, 350]
    )

    summary_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("PADDING", (0, 0), (-1, -1), 6)
        ])
    )

    story.append(summary_table)

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Detailed Investigation Findings",
            styles["Heading2"]
        )
    )

    story.append(Spacer(1, 10))

    table_data = [
        [
            "Time",
            "User",
            "IP",
            "Event",
            "Threat",
            "Confidence"
        ]
    ]

    for event in events:

        table_data.append([
            str(event.get("timestamp", "")),
            str(event.get("username", "")),
            str(event.get("source_ip", "")),
            str(event.get("event_type", "")),
            str(event.get("final_threat", "")),
            f'{event.get("ai_confidence", 0):.2f}%'
        ])

    findings_table = Table(
        table_data,
        repeatRows=1,
        colWidths=[70, 60, 75, 75, 70, 65]
    )

    findings_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4)
        ])
    )

    story.append(findings_table)

    document.build(story)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="forensic_investigation_report.pdf",
        mimetype="application/pdf"
    )
@app.route("/analyze", methods=["POST"])
def analyze_upload():

    uploaded_file = request.files.get("file")

    if not uploaded_file or uploaded_file.filename == "":
        return redirect(url_for("upload_page"))

    file_path = os.path.join("uploads", uploaded_file.filename)

    uploaded_file.save(file_path)

    try:
        df = pd.read_csv(file_path)

        required_columns = [
            "timestamp",
            "username",
            "source_ip",
            "event_type"
        ]

        missing_columns = [
            column
            for column in required_columns
            if column not in df.columns
        ]

        if missing_columns:
            return (
                "Invalid security log format. "
                "Missing columns: "
                + ", ".join(missing_columns)
            )

        logs, model = load_data(file_path)

        events = analyze_events(logs, model)

        event_records = events.to_dict(orient="records")
        session["report_data"] = {
    "filename": uploaded_file.filename,
    "events": event_records
}

        normal_count = sum(
            1
            for event in event_records
            if event["final_threat"] == "NORMAL"
        )

        suspicious_count = sum(
            1
            for event in event_records
            if event["final_threat"] == "SUSPICIOUS"
        )

        malicious_count = sum(
            1
            for event in event_records
            if event["final_threat"] == "MALICIOUS"
        )
        save_investigation_history(
    uploaded_file.filename,
    len(event_records),
    normal_count,
    suspicious_count,
    malicious_count
)

        return render_template(
            "results.html",
            events=event_records,
            total_events=len(event_records),
            normal_count=normal_count,
            suspicious_count=suspicious_count,
            malicious_count=malicious_count
        )

    except Exception as error:
        return f"Unable to analyze evidence: {error}"


if __name__ == "__main__":
    app.run(debug=True)