import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import pickle
import os

# 1) Load dataset
CSV_PATH = r"C:\Users\sabni\Desktop\DV\cybersecurity_intrusion_data.csv"  # put correct path if different
df = pd.read_csv(CSV_PATH)

print("Shape:", df.shape)
print(df.head())

# 2) Basic cleaning / column names (match Kaggle description)
# If your CSV columns are slightly different, do: print(df.columns) and adjust here.
# Expected columns from Kaggle page: [web:10]
# session_id, network_packet_size, protocol_type, login_attempts,
# session_duration, encryption_used, ip_reputation_score,
# failed_logins, browser_type, unusual_time_access, attack_detected

# Drop session_id if present (not needed for prediction)
if "session_id" in df.columns:
    df = df.drop(columns=["session_id"])

# Target column
TARGET_COL = "attack_detected"
y = df[TARGET_COL].astype(int)
X = df.drop(columns=[TARGET_COL])

print("Features:", X.columns.tolist())

# 3) Identify numeric and categorical features
numeric_features = [
    "network_packet_size",
    "login_attempts",
    "session_duration",
    "failed_logins",
    "unusual_time_access",
    "ip_reputation_score",
]

# Some columns are categorical: protocol_type, encryption_used, browser_type
categorical_features = []
for col in ["protocol_type", "encryption_used", "browser_type"]:
    if col in X.columns:
        categorical_features.append(col)

print("Numeric features:", numeric_features)
print("Categorical features:", categorical_features)

# 4) Preprocessing: scale numerics, one-hot encode categoricals
numeric_transformer = StandardScaler()
categorical_transformer = OneHotEncoder(handle_unknown="ignore")

preprocessor = ColumnTransformer(
    transformers=[
        ("num", numeric_transformer, numeric_features),
        ("cat", categorical_transformer, categorical_features),
    ]
)

# 5) Model: Random Forest
rf_clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"  # helpful for imbalanced attacks
)

# 6) Full pipeline: preprocessing + model
clf = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("model", rf_clf),
    ]
)

# 7) Train / test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Train size:", X_train.shape, "Test size:", X_test.shape)

# 8) Fit model
clf.fit(X_train, y_train)

# 9) Evaluate
y_pred = clf.predict(X_test)
y_proba = clf.predict_proba(X_test)[:, 1]

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

auc = roc_auc_score(y_test, y_proba)
print(f"ROC-AUC: {auc:.4f}")

# 10) Save pipeline as a single .pkl (preprocessing + model together)
os.makedirs("artifacts", exist_ok=True)
MODEL_PATH = os.path.join("artifacts", "cyber_rf_pipeline.pkl")

with open(MODEL_PATH, "wb") as f:
    pickle.dump(clf, f)

print(f"✅ Saved full pipeline (preprocessing + RF) to {MODEL_PATH}")
