import numpy as np
import pandas as pd
import time
import csv
import os
from openfhe import *
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score

# 🔹 Function to Setup OpenFHE Crypto Context
def setup_crypto_context(multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim):
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scalSize)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetRingDim(ringDim)

    if securityLevel == 128:
        parameters.SetSecurityLevel(HEStd_128_classic)
    elif securityLevel == 256:
        parameters.SetSecurityLevel(HEStd_256_classic)
    elif securityLevel == 192:
        parameters.SetSecurityLevel(HEStd_192_classic)
    else:
        parameters.SetSecurityLevel(HEStd_NotSet)

    parameters.SetBatchSize(batchSize)
    
    context = GenCryptoContext(parameters)
    context.Enable(PKE)
    context.Enable(KEYSWITCH)
    context.Enable(LEVELEDSHE)
    context.Enable(ADVANCEDSHE)

    return context

# 🔹 Encrypt Data
def encrypt_data(context, data, keys):
    pt = context.MakeCKKSPackedPlaintext(data)
    return context.Encrypt(keys.publicKey, pt)

# 🔹 Decrypt Data
def decrypt_data(context, encrypted_data, secret_key, data_length):
    decrypted = context.Decrypt(secret_key, encrypted_data)
    decrypted.SetLength(data_length)
    return [val.real for val in decrypted.GetCKKSPackedValue()]

# 🔹 Load Dataset with Categorical Encoding & Scaling
def load_dataset(filename):
    df = pd.read_csv(filename)

    # Identify categorical columns
    categorical_cols = df.select_dtypes(include=['object']).columns

    # Convert categorical values into numbers using LabelEncoder
    for col in categorical_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])

    # Separate features (X) and labels (y)
    X = df.iloc[:, :-1]  # All columns except last one
    y = df.iloc[:, -1]   # Last column (Target variable)

    # Split dataset into train & test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Scale numeric features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, X_test, y_train, y_test

# 🔹 Save Results to CSV
def save_results_to_csv(filename, data):
    file_exists = os.path.exists(filename)

    with open(filename, mode='a', newline='') as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "Trials", "Multiplicative Depth", "Scaling Mod", "First Mod", "Security Level", "Batch Size", "Ring Dim",
                "Polynomial Degree", "Avg Encrypted Accuracy", "Avg Non-Encrypted Accuracy",
                "Accuracy Difference (%)", "Avg Encrypted Time (sec)", "Avg Non-Encrypted Time (sec)",
                "Time Difference (sec)"
            ])

        writer.writerow(data)

# 🔹 Function to Run Encrypted & Non-Encrypted SVM
def run_encrypted_svm(dataset_path, output_csv):
    trials = int(input("Enter number of trials: "))
    multDepth = int(input("Enter Multiplicative Depth (e.g., 1): "))
    scalSize = int(input("Enter Scaling Mod Size (e.g., 30): "))
    firstModSize = int(input("Enter First Mod Size (e.g., 60): "))
    securityLevel = int(input("Enter Security Level (128, 192, 256): "))
    batchSize = int(input("Enter Batch Size (e.g., 1024): "))
    ringDim = int(input("Enter Ring Dimension (e.g., 16384): "))
    polyDegree = int(input("Enter Polynomial Kernel Degree (e.g., 3): "))

    # Load dataset
    X_train, X_test, y_train, y_test = load_dataset(dataset_path)

    # Train Non-Encrypted SVM
    model = SVC(kernel='poly', degree=polyDegree)
    model.fit(X_train, y_train)

    # Track results
    accuracies_encrypted, accuracies_non_encrypted = [], []
    total_time_encrypted, total_time_non_encrypted = 0, 0

    for _ in range(trials):
        # ▪ Non-Encrypted Prediction
        t_start = time.time()
        predictions = model.predict(X_test)
        total_time_non_encrypted += time.time() - t_start
        accuracies_non_encrypted.append(accuracy_score(y_test, predictions))

        # ▪ Encrypted Prediction
        t_start = time.time()
        context = setup_crypto_context(multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim)
        keys = context.KeyGen()

        predictions_encrypted = []
        for i in range(len(X_test)):
            encrypted_sample = encrypt_data(context, X_test[i], keys)
            decrypted_sample = decrypt_data(context, encrypted_sample, keys.secretKey, len(X_test[i]))
            prediction = model.predict([decrypted_sample])[0]
            predictions_encrypted.append(prediction)

        accuracies_encrypted.append(accuracy_score(y_test, predictions_encrypted))
        total_time_encrypted += time.time() - t_start

    # Compute Averages
    avg_encrypted_acc = np.mean(accuracies_encrypted)
    avg_non_encrypted_acc = np.mean(accuracies_non_encrypted)
    avg_encrypted_time = total_time_encrypted / trials
    avg_non_encrypted_time = total_time_non_encrypted / trials
    accuracy_diff = (avg_non_encrypted_acc - avg_encrypted_acc) * 100
    time_diff = avg_encrypted_time - avg_non_encrypted_time

    # Print Results
    print("---- Running Encrypted Polynomial SVM ----")
    print(f"Avg Encrypted SVM Accuracy: {avg_encrypted_acc:.4f}")
    print(f"Avg Non-Encrypted SVM Accuracy: {avg_non_encrypted_acc:.4f}")
    print(f"Accuracy Difference: {accuracy_diff:.2f}%")
    print(f"Avg Encrypted Time: {avg_encrypted_time:.4f} sec")
    print(f"Avg Non-Encrypted Time: {avg_non_encrypted_time:.4f} sec")
    print(f"Time Difference: {time_diff:.4f} sec\n")

    # Save Results
    save_results_to_csv(output_csv, [
        trials, multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim, polyDegree,
        avg_encrypted_acc, avg_non_encrypted_acc, accuracy_diff, avg_encrypted_time, avg_non_encrypted_time, time_diff
    ])

# 🔹 Run Script
if __name__ == "__main__":
    dataset_path = "PIDD.csv"  # 🔺 Ensure the correct dataset filename here
    output_csv = "svm_results_poly.csv"
    run_encrypted_svm(dataset_path, output_csv)

