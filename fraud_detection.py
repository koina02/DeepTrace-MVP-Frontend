from sklearn.ensemble import IsolationForest
import pandas as pd

# Dummy model for testing - Replace this with actual forensic data in production
def load_sample_data():
    data = {
        'login_attempts': [2, 3, 1, 20, 2],
        'file_access_count': [5, 6, 4, 50, 5],
        'suspicious_keywords': [0, 0, 0, 1, 0]
    }
    return pd.DataFrame(data)

def train_model(data):
    model = IsolationForest(n_estimators=100, contamination=0.1)
    model.fit(data)
    return model

def detect_fraud(model, new_data):
    prediction = model.predict(new_data)
    # -1 means anomaly (possible fraud), 1 is clean
    new_data['result'] = prediction
    return new_data
