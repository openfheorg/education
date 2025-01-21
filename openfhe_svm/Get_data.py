from ucimlrepo import fetch_ucirepo 
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np
import os

SEED = 42
np.random.seed(SEED)

# Create data directory if it doesn't exist
os.makedirs('data', exist_ok=True)

# Fetch dataset 
credit_approval = fetch_ucirepo(id=27) 

# Select only 4 numerical features (for simplicity)
vars = credit_approval.variables
cont_features = vars[vars['type'] == 'Continuous']['name'].values[0:4]

print("\nSelected features:", cont_features)

# Filter the X data (Dropping NA's)
X = credit_approval.data.features[cont_features].dropna()

# Drop y lines that were na in X
y = credit_approval.data.targets.loc[X.index]

# Print original data info
print("\nOriginal data shape:", X.shape)
print("Features:", X.columns.tolist())

# Replace + by 1 and - by 0
y = y.replace({'+': 1, '-': -1})

# Standardize X with StandardScaler
scaler = StandardScaler()
X = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)

# Print standardization stats
print("\nStandardization results:")
for col in X.columns:
    print(f"{col}: mean={X[col].mean():.3f}, std={X[col].std():.3f}")

# Save full data
X.to_csv('data/credit_approval.csv', index=False)
y.to_csv('data/credit_approval_target.csv', index=False)

# Split data into train and test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=SEED)

# Save train and test data
X_train.to_csv('data/credit_approval_train.csv', index=False)
y_train.to_csv('data/credit_approval_target_train.csv', index=False)
X_test.to_csv('data/credit_approval_test.csv', index=False)
y_test.to_csv('data/credit_approval_target_test.csv', index=False)

print("\nSaved files:")
print(f"Training samples: {X_train.shape[0]}")
print(f"Testing samples: {X_test.shape[0]}")
print(f"Number of features: {X_train.shape[1]}")
