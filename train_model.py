import pandas as pd
import pickle

from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from features import extract_features, FEATURE_COLUMNS

# -----------------------------
# LOAD DATA
# -----------------------------
with open("datasets/phishing.txt") as f:
    phishing_urls = [x.strip() for x in f.readlines()]

with open("datasets/legit.txt") as f:
    legit_urls = [x.strip() for x in f.readlines()]

# -----------------------------
# BUILD DATAFRAME
# -----------------------------
rows = []

for url in phishing_urls:
    rows.append(extract_features(url) + [0])

for url in legit_urls:
    rows.append(extract_features(url) + [1])

columns = FEATURE_COLUMNS + ["label"]


df = pd.DataFrame(rows, columns=columns)

# -----------------------------
# SPLIT
# -----------------------------
X = df[FEATURE_COLUMNS]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------
# TRAIN MODEL
# -----------------------------
model = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss"
)

model.fit(X_train, y_train)

# -----------------------------
# EVALUATE
# -----------------------------
preds = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, preds))

print(classification_report(y_test, preds))

# -----------------------------
# SAVE MODEL
# -----------------------------
pickle.dump(model, open("model.pkl", "wb"))

print("New model.pkl generated")