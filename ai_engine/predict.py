import joblib

model = joblib.load("models/firewall_model.pkl")

def predict_threat(input_data):
    prob = model.predict_proba(input_data)[0]
    score = max(prob)

    if score > 0.9:
        return "BLOCK"
    elif score > 0.7:
        return "ALERT"
    else:
        return "ALLOW"