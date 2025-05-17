from ucimlrepo import fetch_ucirepo 
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import pandas as pd
SEED = 42

# Fetch dataset 
credit_approval = fetch_ucirepo(id=27) 

# Select only 4 numerical features (for simplicity)
vars = credit_approval.variables
cont_features = vars[vars['type'] == 'Continuous']['name'].values[0:4]
# Filter the X data (Dropping NA's)
X = credit_approval.data.features[cont_features].dropna()
# Drop y lines that were na in X
y = credit_approval.data.targets.loc[X.index]
# Replace + by 1 and - by 0
y = y.replace({'+': 1, '-': -1})
# Standardize X with StandardScaler
scaler = StandardScaler()
X = pd.DataFrame(scaler.fit_transform(X))


# Save full data
X.to_csv('data/credit_approval.csv', index=False)
y.to_csv('data/credit_approval_target.csv', index=False)

# Split data into train and test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.20, random_state = SEED)

# Save train and test data
X_train.to_csv('data/credit_approval_train.csv', index=False)
y_train.to_csv('data/credit_approval_target_train.csv', index=False)
# Saving just the first line for inference
X_test.head(1).to_csv('data/credit_approval_test.csv', index=False)
y_test.head(1).to_csv('data/credit_approval_target_test.csv', index=False)