import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import os
# Load the data


data = pd.read_csv('data/cc.csv')
print(data.head())

# Scale the 'Amount' feature
scaler = StandardScaler()
data['Amount_Scaled'] = scaler.fit_transform(data[['Amount']])

# Remove rows with missing or infinite values
data = data.replace([np.inf, -np.inf], np.nan)
data = data.dropna()


X = data.drop('Class', axis=1)
y = data['Class']

# Split the data into training and testing sets
X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)

# Initialize the Isolation Forest model
model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)

# Fit the model
model.fit(X_train)

# Predict anomalies
y_pred = model.predict(X_test)
print(f"Before: {y_pred}")
# Convert predictions: 1 for normal, -1 for anomaly
y_pred = np.where(y_pred == 1, 0, 1)  # 0 for normal, 1 for fraud
print(f"After: {y_pred}")
# Get the true labels for the test set
y_test = y.loc[X_test.index]

# Compute the confusion matrix
conf_matrix = confusion_matrix(y_test, y_pred)
print(conf_matrix)

# Display classification report
print(classification_report(y_test, y_pred))

# Plot the confusion matrix
plt.figure(figsize=(6, 6))
sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Normal', 'Fraud'], yticklabels=['Normal', 'Fraud'])
plt.title('Confusion Matrix - Isolation Forest for Fraud Detection')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()