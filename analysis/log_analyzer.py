import pandas as pd

CSV_PATH = "dataset/security_logs.csv"


def load_logs():
    """Load security logs from the CSV dataset."""
    try:
        logs = pd.read_csv(CSV_PATH)
        return logs
    except FileNotFoundError:
        print("Error: security_logs.csv was not found.")
        return None


def analyze_logs(logs):
    """Analyze logs and identify suspicious activity."""
    if logs is None or logs.empty:
        print("No logs available for analysis.")
        return

    print("\n=== AI Digital Forensics - Log Analysis ===\n")

    print(f"Total events: {len(logs)}")

    failed_logins = logs[
        (logs["event_type"] == "LOGIN") &
        (logs["status"] == "FAILED")
    ]

    print(f"Failed login attempts: {len(failed_logins)}")

    suspicious_ips = (
        failed_logins["source_ip"]
        .value_counts()
    )

    print("\nSuspicious login sources:")

    found_suspicious = False

    for ip, count in suspicious_ips.items():
        if count >= 3:
            print(f"  [ALERT] {ip} -> {count} failed login attempts")
            found_suspicious = True

    if not found_suspicious:
        print("  No suspicious login activity detected.")

    print("\nPrivilege changes:")

    privilege_changes = logs[
        logs["event_type"] == "PRIVILEGE_CHANGE"
    ]

    if privilege_changes.empty:
        print("  No privilege changes detected.")
    else:
        for _, event in privilege_changes.iterrows():
            print(
                f"  [ALERT] User '{event['username']}' "
                f"received status: {event['status']}"
            )


if __name__ == "__main__":
    logs = load_logs()
    analyze_logs(logs)