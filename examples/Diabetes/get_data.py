import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

DATASET_FILENAME = "PIDD.csv"  # Ensure your Pima Indian Diabetes dataset is named PIDD.csv

def main():
    # Load dataset
    df = pd.read_csv(DATASET_FILENAME)
    
    # Print first few rows of the dataset
    print("\nFirst few rows of the dataset:")
    print(df.head())
    
    # Total number of columns (features + target)
    total_columns = df.shape[1]
    print(f"\nTotal number of columns in dataset: {total_columns}")
    
    # Assume the target variable is "Outcome"
    target_column = "Outcome"
    print(f"\nUsing '{target_column}' as the target column.")
    
    # Separate features and labels
    features = df.drop(columns=[target_column])
    labels = df[target_column]
    
    print(f"\nTotal number of features in dataset: {features.shape[1]}")
    
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
    
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
    
    print("\nData processing completed successfully!\n")
    print("Saved files:")
    print(f"Training samples: {X_train.shape[0]}")
    print(f"Testing samples: {X_test.shape[0]}")
    print(f"Number of selected features: {features.shape[1]}")

if __name__ == "__main__":
    main()

