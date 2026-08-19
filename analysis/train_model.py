import pandas as pd
import joblib

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


DATA_PATH = "dataset/threat_training.csv"
MODEL_PATH = "models/threat_classifier.pkl"


def train_model():
    print("Loading training data...")

    data = pd.read_csv(DATA_PATH)

    X = data.drop("label", axis=1)
    y = data["label"]

    categorical_features = [
        "event_type",
        "username",
        "source_ip",
        "status"
    ]

    numeric_features = [
        "failed_attempts",
        "privilege_change"
    ]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                categorical_features
            ),
            (
                "numeric",
                "passthrough",
                numeric_features
            )
        ]
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", model)
        ]
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    print("Training AI threat classifier...")

    pipeline.fit(X_train, y_train)

    predictions = pipeline.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print("\n=== Model Evaluation ===")
    print(f"Accuracy: {accuracy:.2%}")

    print("\nClassification Report:")
    print(classification_report(y_test, predictions, zero_division=0))

    joblib.dump(pipeline, MODEL_PATH)

    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    train_model()