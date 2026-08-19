from flask import Flask, render_template
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


if __name__ == "__main__":
    app.run(debug=True)