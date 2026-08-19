import pandas as pd
import joblib

MODEL_PATH = "models/threat_classifier.pkl"


def predict_events():
    model = joblib.load(MODEL_PATH)

    test_events = pd.DataFrame([
        {
            "event_type": "LOGIN",
            "username": "new_user",
            "source_ip": "192.168.1.90",
            "status": "SUCCESS",
            "failed_attempts": 0,
            "privilege_change": 0
        },
        {
            "event_type": "LOGIN",
            "username": "admin",
            "source_ip": "192.168.1.91",
            "status": "FAILED",
            "failed_attempts": 4,
            "privilege_change": 0
        },
        {
            "event_type": "LOGIN",
            "username": "unknown",
            "source_ip": "203.0.113.90",
            "status": "FAILED",
            "failed_attempts": 9,
            "privilege_change": 0
        },
        {
            "event_type": "PRIVILEGE_CHANGE",
            "username": "new_user",
            "source_ip": "192.168.1.92",
            "status": "ADMIN_GRANTED",
            "failed_attempts": 0,
            "privilege_change": 1
        }
    ])

    predictions = model.predict(test_events)
    probabilities = model.predict_proba(test_events)

    print("\n=== AI Threat Predictions ===\n")

    for index, prediction in enumerate(predictions):
        confidence = max(probabilities[index]) * 100

        print(
            f"Event {index + 1}: "
            f"{prediction} "
            f"(Confidence: {confidence:.2f}%)"
        )


if __name__ == "__main__":
    predict_events()