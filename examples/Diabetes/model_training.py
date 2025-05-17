import pandas as pd
import numpy as np
import time
import os
import concurrent.futures
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Ensure required directories exist
os.makedirs("models", exist_ok=True)
os.makedirs("data", exist_ok=True)

# -------------------------------
# Load the data from the Pima Indian Diabetes dataset (PIDD.csv)
# -------------------------------
DATASET_FILENAME = "PIDD.csv"  # Make sure this file exists in your working directory

def load_dataset(filename):
    """
    Loads the diabetes dataset from CSV, label-encodes categorical columns,
    and returns features and labels. Assumes the target column is 'Outcome'.
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Dataset file '{filename}' not found.")
    
    df = pd.read_csv(filename)
    
    # Print first few rows
    print("\nFirst few rows of the dataset:")
    print(df.head())
    
    # Total number of columns (features + target)
    print(f"\nTotal number of columns in dataset: {df.shape[1]}")
    
    # Assume the target column is 'Outcome'
    target_column = "Outcome"
    print(f"\nUsing '{target_column}' as the target column.")
    
    # Separate features and target
    features = df.drop(columns=[target_column])
    labels = df[target_column]
    
    print(f"\nTotal number of feature columns: {features.shape[1]}")
    
    # Identify numeric and categorical features
    numeric_features = features.select_dtypes(include=[np.number]).columns.tolist()
    categorical_features = features.select_dtypes(include=['object']).columns.tolist()
    
    print(f"\nNumeric features: {numeric_features}")
    print(f"\nCategorical features: {categorical_features}\n")
    
    # Standardize numeric features
    scaler = StandardScaler()
    numeric_data = features[numeric_features]
    standardized_data = scaler.fit_transform(numeric_data)
    standardized_df = pd.DataFrame(standardized_data, columns=numeric_features)
    
    print("Standardization results:")
    for col in numeric_features:
        mean_val = standardized_df[col].mean()
        std_val = standardized_df[col].std()
        print(f"{col}: mean={mean_val:.3f}, std={std_val:.3f}")
    
    return features, labels

# -------------------------------
# Model Training using SVM
# -------------------------------
print("---- Starting Models Training ----")

print("Starting SVM Linear")
svc_linear = SVC(kernel='linear')
# Load the diabetes dataset from PIDD.csv
features, labels = load_dataset("PIDD.csv")
# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
# Standardize the features
scaler = StandardScaler()
X_train = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns)
X_test = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)
svc_linear.fit(X_train, y_train.values.ravel())
print("SVM Linear Completed")

print("Starting SVM Polynomial")
svc_poly = SVC(kernel='poly', degree=3, gamma=2)
svc_poly.fit(X_train, y_train.values.ravel())
print("SVM Poly Completed")

print("---- Model Training Completed! ----")

# -------------------------------
# Decision Function Evaluation
# -------------------------------
decision_function_linear = svc_linear.decision_function(X_test)
ytestscore_linear = decision_function_linear[0]

decision_function_poly = svc_poly.decision_function(X_test)
ytestscore_poly = decision_function_poly[0]

# -------------------------------
# Saving Results
# -------------------------------
# Save linear SVM parameters and test score
np.savetxt("models/diabetes_weights.txt", svc_linear.coef_)
np.savetxt("models/diabetes_intercept.txt", svc_linear.intercept_)
np.savetxt("data/diabetes_ytestscore_linear.txt", [ytestscore_linear])

# Save polynomial SVM parameters and test score
np.savetxt("models/diabetes_dual_coef.txt", svc_poly.dual_coef_)
np.savetxt("models/diabetes_support_vectors.txt", svc_poly.support_vectors_)
np.savetxt("models/diabetes_intercept_poly.txt", svc_poly.intercept_)
np.savetxt("data/diabetes_ytestscore_poly.txt", [ytestscore_poly])

