import numpy as np
import time
import csv
import os
from openfhe import *
from sklearn import datasets
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score

def setup_crypto_context(multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim):
    """Sets up the OpenFHE crypto context with user-defined parameters."""
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

def encrypt_data(context, data, keys):
    """Encrypts data using OpenFHE's CKKSPacked encoding."""
    pt = context.MakeCKKSPackedPlaintext(data)
    encrypted_data = context.Encrypt(keys.publicKey, pt)
    return encrypted_data

def decrypt_data(context, encrypted_data, secret_key, data_length):
    """Decrypts encrypted data back to plaintext values."""
    decrypted = context.Decrypt(secret_key, encrypted_data)
    decrypted.SetLength(data_length)
    return [val.real for val in decrypted.GetCKKSPackedValue()]

def save_results_to_csv(filename, data):
    """Saves experiment results to a CSV file, ensuring headers are included."""
    file_exists = os.path.exists(filename)

    with open(filename, mode='a', newline='') as file:
        writer = csv.writer(file)

        # Write header if file does not exist
        if not file_exists:
            writer.writerow([
                "Trials", "Multiplicative Depth", "Scaling Mod", "First Mod", "Security Level", "Batch Size", "Ring Dim",
                "Polynomial Degree", "Avg Encrypted Accuracy", "Avg Non-Encrypted Accuracy",
                "Accuracy Difference (%)", "Avg Encrypted Time (sec)", "Avg Non-Encrypted Time (sec)",
                "Time Difference (sec)"
            ])

        writer.writerow(data)

def test_openfhe_encryption():
    """Tests OpenFHE encryption and decryption."""
    context = setup_crypto_context(1, 30, 60, 128, 1024, 16384)
    keys = context.KeyGen()
    context.EvalMultKeyGen(keys.secretKey)
    context.EvalSumKeyGen(keys.secretKey)

    test_data = [1.5, 2.0, 3.5]
    encrypted = encrypt_data(context, test_data, keys)
    decrypted_values = decrypt_data(context, encrypted, keys.secretKey, len(test_data))

    print("---- Testing OpenFHE Encryption ----")
    print(f"Original data: {test_data}")
    print(f"Decrypted values (real part): {decrypted_values}\n")

def run_encrypted_svm():
    """Runs an encrypted Polynomial SVM with user-defined parameters."""
    
    # 🔹 User Input for Parameters
    trials = int(input("Enter number of trials: "))
    multDepth = int(input("Enter Multiplicative Depth (e.g., 1): "))
    scalSize = int(input("Enter Scaling Mod Size (e.g., 30): "))
    firstModSize = int(input("Enter First Mod Size (e.g., 60): "))
    securityLevel = int(input("Enter Security Level (128, 192, 256): "))
    batchSize = int(input("Enter Batch Size (e.g., 1024): "))
    ringDim = int(input("Enter Ring Dimension (e.g., 16384): "))
    polyDegree = int(input("Enter Polynomial Kernel Degree (e.g., 3): "))

    # 🔹 Load Dataset & Preprocess
    iris = datasets.load_iris()
    X = StandardScaler().fit_transform(iris.data)
    y = iris.target

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 🔹 Train Non-Encrypted SVM
    model = SVC(kernel='poly', degree=polyDegree)
    model.fit(X_train, y_train)

    # 🔹 Track Accuracy & Time
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

    # 🔹 Compute Averages
    avg_encrypted_acc = np.mean(accuracies_encrypted)
    avg_non_encrypted_acc = np.mean(accuracies_non_encrypted)
    avg_encrypted_time = total_time_encrypted / trials
    avg_non_encrypted_time = total_time_non_encrypted / trials
    accuracy_diff = (avg_non_encrypted_acc - avg_encrypted_acc) * 100  # Convert to percentage
    time_diff = avg_encrypted_time - avg_non_encrypted_time  # Time difference in seconds

    # 🔹 Print Results
    print("---- Running Encrypted Polynomial SVM ----")
    print(f"Avg Encrypted SVM Accuracy: {avg_encrypted_acc:.4f}")
    print(f"Avg Non-Encrypted SVM Accuracy: {avg_non_encrypted_acc:.4f}")
    print(f"Accuracy Difference: {accuracy_diff:.2f}%")
    print(f"Avg Encrypted Time: {avg_encrypted_time:.4f} sec")
    print(f"Avg Non-Encrypted Time: {avg_non_encrypted_time:.4f} sec")
    print(f"Time Difference: {time_diff:.4f} sec\n")

    # 🔹 Save to CSV
    csv_filename = "svm_results_poly.csv"
    save_results_to_csv(csv_filename, [
        trials, multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim, polyDegree,
        avg_encrypted_acc, avg_non_encrypted_acc, accuracy_diff, avg_encrypted_time, avg_non_encrypted_time, time_diff
    ])

def main():
    test_openfhe_encryption()
    run_encrypted_svm()

if __name__ == "__main__":
    main()

