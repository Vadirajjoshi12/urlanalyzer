import pandas as pd
import pickle
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, confusion_matrix, ConfusionMatrixDisplay, classification_report

# Load dataset
df = pd.read_csv("dataset.csv")

# Clean byte values
def clean_value(x):
    x = str(x)
    if x.startswith("b'") and x.endswith("'"):
        x = x[2:-1]
    return int(x)

df = df.apply(lambda col: col.map(clean_value))

# Split
X = df.drop("Result", axis=1)
y = df["Result"]

# Load model
model = pickle.load(open("model.pkl", "rb"))

# Predict
y_pred = model.predict(X)

# Metrics
print("\nAccuracy:", accuracy_score(y, y_pred))
print("\nClassification Report:\n", classification_report(y, y_pred))

# Confusion Matrix
cm = confusion_matrix(y, y_pred)

disp = ConfusionMatrixDisplay(confusion_matrix=cm)
disp.plot()
plt.title("Confusion Matrix")
plt.show()
labels = ["Correct", "Incorrect"]
values = [sum(y == y_pred), sum(y != y_pred)]

plt.figure()
plt.bar(labels, values)
plt.title("Prediction Accuracy Distribution")
plt.show()