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

CSV_FILENAME = "svm_results_linear.csv"

def get_user_input():
    """Prompts user for encryption and SVM parameters."""
    trials = int(input("Enter number of trials: "))
    multDepth = int(input("Enter Multiplicative Depth (e.g., 1): "))
    scalSize = int(input("Enter Scaling Mod Size (e.g., 30): "))
    firstModSize = int(input("Enter First Mod Size (e.g., 60): "))
    securityLevel = int(input("Enter Security Level (128, 192, 256): "))
    batchSize = int(input("Enter Batch Size (e.g., 1024): "))
    ringDim = int(input("Enter Ring Dimension (e.g., 16384): "))
    return trials, multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim

def setup_crypto_context(multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim):
    """Sets up the OpenFHE crypto context with user-specified parameters."""
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

def test_openfhe_encryption():
    """Tests OpenFHE encryption and decryption."""
    print("---- Testing OpenFHE Encryption ----")
    context = setup_crypto_context(1, 30, 60, 128, 1024, 16384)
    keys = context.KeyGen()
    context.EvalMultKeyGen(keys.secretKey)
    context.EvalSumKeyGen(keys.secretKey)
    
    test_data = [1.5, 2.0, 3.5]
    print(f"Original data: {test_data}")
    
    encrypted = encrypt_data(context, test_data, keys)
    decrypted = context.Decrypt(keys.secretKey, encrypted)
    decrypted.SetLength(len(test_data))
    real_values = [val.real for val in decrypted.GetCKKSPackedValue()]
    print(f"Decrypted values (real part): {real_values}")

def save_results_to_csv(results, filename=CSV_FILENAME):
    """Saves SVM results to a CSV file, including parameters and metrics."""
    file_exists = os.path.isfile(filename)
    
    with open(filename, mode='a', newline='') as file:
        fieldnames = [
            "Trials", "Multiplicative Depth", "Scaling Mod Size", "First Mod Size",
            "Security Level", "Batch Size", "Ring Dimension",
            "Avg Encrypted SVM Accuracy", "Avg Non-Encrypted SVM Accuracy",
            "Accuracy Difference (%)",
            "Avg Encrypted Time (sec)", "Avg Non-Encrypted Time (sec)",
            "Time Difference (sec)"
        ]
        
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        
        # Write header if file does not exist
        if not file_exists:
            writer.writeheader()
        
        # Write results
        writer.writerow(results)

def run_encrypted_linear_svm(trials, multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim):
    """Runs encrypted Linear SVM classification using OpenFHE and saves results."""
    print("---- Running Encrypted Linear SVM ----")
    
    iris = datasets.load_iris()
    X = StandardScaler().fit_transform(iris.data)
    y = iris.target
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = SVC(kernel='linear')
    model.fit(X_train, y_train)
    
    accuracies_encrypted, accuracies_non_encrypted = [], []
    total_time_encrypted, total_time_non_encrypted = 0, 0
    
    for _ in range(trials):
        # Non-encrypted SVM prediction
        t_start = time.time()
        predictions = model.predict(X_test)
        accuracies_non_encrypted.append(accuracy_score(y_test, predictions))
        total_time_non_encrypted += time.time() - t_start
        
        # Encrypted SVM prediction
        t_start = time.time()
        context = setup_crypto_context(multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim)
        keys = context.KeyGen()
        
        predictions_encrypted = []
        for i in range(len(X_test)):
            encrypted_sample = encrypt_data(context, X_test[i], keys)
            decrypted_sample = context.Decrypt(keys.secretKey, encrypted_sample)
            decrypted_sample.SetLength(len(X_test[i]))
            real_values = [val.real for val in decrypted_sample.GetCKKSPackedValue()]
            prediction = model.predict([real_values])
            predictions_encrypted.append(prediction[0])
        
        accuracies_encrypted.append(accuracy_score(y_test, predictions_encrypted))
        total_time_encrypted += time.time() - t_start
    
    avg_encrypted_acc = np.mean(accuracies_encrypted)
    avg_non_encrypted_acc = np.mean(accuracies_non_encrypted)
    accuracy_difference = (avg_non_encrypted_acc - avg_encrypted_acc) * 100
    avg_encrypted_time = total_time_encrypted / trials
    avg_non_encrypted_time = total_time_non_encrypted / trials
    time_difference = avg_encrypted_time - avg_non_encrypted_time
    
    print(f"Avg Encrypted SVM Accuracy: {avg_encrypted_acc:.4f}")
    print(f"Avg Non-Encrypted SVM Accuracy: {avg_non_encrypted_acc:.4f}")
    print(f"Accuracy Difference: {accuracy_difference:.2f}%")
    print(f"Avg Encrypted Time: {avg_encrypted_time:.4f} sec")
    print(f"Avg Non-Encrypted Time: {avg_non_encrypted_time:.4f} sec")
    print(f"Time Difference: {time_difference:.4f} sec")

    # Save results
    results = {
        "Trials": trials,
        "Multiplicative Depth": multDepth,
        "Scaling Mod Size": scalSize,
        "First Mod Size": firstModSize,
        "Security Level": securityLevel,
        "Batch Size": batchSize,
        "Ring Dimension": ringDim,
        "Avg Encrypted SVM Accuracy": avg_encrypted_acc,
        "Avg Non-Encrypted SVM Accuracy": avg_non_encrypted_acc,
        "Accuracy Difference (%)": accuracy_difference,
        "Avg Encrypted Time (sec)": avg_encrypted_time,
        "Avg Non-Encrypted Time (sec)": avg_non_encrypted_time,
        "Time Difference (sec)": time_difference
    }
    save_results_to_csv(results)

def main():
    test_openfhe_encryption()
    
    trials, multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim = get_user_input()
    
    run_encrypted_linear_svm(trials, multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim)

if __name__ == "__main__":
    main()

