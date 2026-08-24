from asyncio import events

from flask import Flask, render_template,request,redirect, url_for
import pandas as pd
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "analysis")))
from analysis.investigation_engine import load_data, analyze_events

app = Flask(__name__)


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