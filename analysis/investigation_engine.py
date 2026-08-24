import pandas as pd
import joblib

CSV_PATH = "dataset/security_logs.csv"
MODEL_PATH = "models/threat_classifier.pkl"


def load_data(csv_path=CSV_PATH):
    logs = pd.read_csv(csv_path)
    model = joblib.load(MODEL_PATH)

    return logs, model


def prepare_events(logs):
    events = logs.copy()

    # Count failed login attempts for each source IP.
    failed_logins = (
        events["event_type"].eq("LOGIN")
        & events["status"].eq("FAILED")
    )

    events["failed_attempts"] = (
        events["source_ip"]
        .where(failed_logins)
        .groupby(events["source_ip"])
        .transform("count")
        .fillna(0)
        .astype(int)
    )

    # Mark privilege changes.
    events["privilege_change"] = (
        events["event_type"]
        .eq("PRIVILEGE_CHANGE")
        .astype(int)
    )

    return events


def apply_forensic_rules(event, ai_prediction):
    """
    Combine AI prediction with deterministic forensic rules.
    """

    threat = ai_prediction
    reasons = []

    # Rule 1: Multiple failed login attempts.
    if event["event_type"] == "LOGIN" and event["status"] == "FAILED":
        if event["failed_attempts"] >= 6:
            threat = "MALICIOUS"
            reasons.append("High number of failed login attempts")

        elif event["failed_attempts"] >= 3:
            if threat == "NORMAL":
                threat = "SUSPICIOUS"

            reasons.append("Repeated failed login attempts")

        else:
            if threat == "NORMAL":
                threat = "SUSPICIOUS"

            reasons.append("Failed login attempt")

    # Rule 2: Unknown user attempting access.
    if event["username"] == "unknown":
        if threat == "NORMAL":
            threat = "SUSPICIOUS"

        reasons.append("Unknown user account")

    # Rule 3: Privilege escalation.
    if event["privilege_change"] == 1:
        if threat == "NORMAL":
            threat = "SUSPICIOUS"

        reasons.append("Privilege change detected")

    return threat, reasons


def analyze_events(logs, model):
    events = prepare_events(logs)

    model_features = [
        "event_type",
        "username",
        "source_ip",
        "status",
        "failed_attempts",
        "privilege_change"
    ]

    predictions = model.predict(events[model_features])
    probabilities = model.predict_proba(events[model_features])

    final_predictions = []
    reasons_list = []
    confidence_list = []

    for index, event in events.iterrows():

        ai_prediction = predictions[index]

        ai_confidence = round(
            max(probabilities[index]) * 100,
            2
        )

        final_prediction, reasons = apply_forensic_rules(
            event,
            ai_prediction
        )

        final_predictions.append(final_prediction)
        reasons_list.append(
            "; ".join(reasons)
            if reasons
            else "No suspicious indicators detected"
        )
        confidence_list.append(ai_confidence)

    events["ai_prediction"] = predictions
    events["final_threat"] = final_predictions
    events["ai_confidence"] = confidence_list
    events["forensic_reasons"] = reasons_list

    return events


def display_results(events):
    print("\n=== AI DIGITAL FORENSICS INVESTIGATION ===\n")

    print(f"Total events analyzed: {len(events)}")

    threat_counts = events["final_threat"].value_counts()

    print("\nFinal Threat Summary:")

    for threat in ["NORMAL", "SUSPICIOUS", "MALICIOUS"]:
        count = threat_counts.get(threat, 0)
        print(f"  {threat}: {count}")

    print("\nDetailed Investigation Results:\n")

    for index, event in events.iterrows():

        print(
            f"[{index + 1}] "
            f"{event['timestamp']} | "
            f"{event['username']} | "
            f"{event['source_ip']} | "
            f"{event['event_type']} | "
            f"AI: {event['ai_prediction']} | "
            f"FINAL: {event['final_threat']} | "
            f"Confidence: {event['ai_confidence']:.2f}%"
        )

        print(
            f"    Reason: {event['forensic_reasons']}"
        )


def main():
    try:
        logs, model = load_data()

        events = analyze_events(logs, model)

        display_results(events)

    except FileNotFoundError as error:
        print(f"File not found: {error}")

    except Exception as error:
        print(f"Investigation error: {error}")


if __name__ == "__main__":
    main()