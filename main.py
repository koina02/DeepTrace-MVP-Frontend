
from fraud_detection import load_sample_data, train_model, detect_fraud

def run_fraud_detection():
    print("[*] Starting AI-based fraud detection...\n")

    # Load and train
    data = load_sample_data()
    model = train_model(data)

    # Detect anomalies
    results = detect_fraud(model, data)

    # Display results
    for index, row in results.iterrows():
        status = "ALERT: Possible Fraud" if row['result'] == -1 else "Normal"
        print(f"[{status}] Entry {index + 1} -> Login: {row['login_attempts']}, "
              f"File Access: {row['file_access_count']}, Suspicious Keywords: {row['suspicious_keywords']}")
    print("\n[*] Fraud detection completed.")

if __name__ == "__main__":
    run_fraud_detection()
