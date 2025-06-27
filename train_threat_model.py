import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Load and preprocess
df = pd.read_csv("ip_threat_data.csv")

# Drop non-numeric columns
X = df.drop(["ip_address", "risk"], axis=1)
y = df["risk"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "rf_threat_model.pkl")

print("✅ Model trained and saved as rf_threat_model.pkl")