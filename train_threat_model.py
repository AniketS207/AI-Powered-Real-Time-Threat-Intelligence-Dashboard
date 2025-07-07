import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

# Load dataset
df = pd.read_csv("ip_threat_data.csv")

# Drop non-numeric and unnecessary columns
df = df[["Malicious", "Suspicious", "Abuse Confidence", "Reputation", "Risk"]]

# Optional: drop rows with all zero threat features
df = df[~((df["Malicious"] == 0) & (df["Suspicious"] == 0) & (df["Abuse Confidence"] == 0) & (df["Reputation"] == 0))]

# Encode risk levels: Low=0, Medium=1, High=2
risk_map = {"Low": 0, "Medium": 1, "High": 2}
df["Risk"] = df["Risk"].map(risk_map)

# Features and target
X = df.drop("Risk", axis=1)
y = df["Risk"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)

# Train the Random Forest model
model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "rf_threat_model.pkl")

print("✅ Model trained and saved as rf_threat_model.pkl")
