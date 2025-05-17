import numpy as np
import time
import csv
from openfhe import *
from sklearn import datasets
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score

def setup_crypto_context(multDepth=1, scalSize=30, firstModSize=10, securityLevel=128, batchSize=1024, ringDim=8192):
    """
    Sets up the OpenFHE crypto context with specified parameters.
    """
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
    context = setup_crypto_context()
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

def run_encrypted_svm(trials=100, csv_filename="svm_results-poly.test.csv"):
    """Runs encrypted Polynomial SVM classification using OpenFHE and logs results to a CSV file."""
    iris = datasets.load_iris()
    X = StandardScaler().fit_transform(iris.data)
    y = iris.target
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = SVC(kernel='poly', degree=3)
    model.fit(X_train, y_train)
    
    accuracies_encrypted, accuracies_non_encrypted = [], []
    total_time_encrypted, total_time_non_encrypted = 0, 0
    
    for _ in range(trials):
        t_start = time.time()
        predictions = model.predict(X_test)
        accuracies_non_encrypted.append(accuracy_score(y_test, predictions))
        total_time_non_encrypted += time.time() - t_start
        
        t_start = time.time()
        context = setup_crypto_context()
        keys = context.KeyGen()
        
        predictions_encrypted = []
        for i in range(len(X_test)):
            encrypted_sample = encrypt_data(context, X_test[i], keys)
            decrypted_sample = context.Decrypt(keys.secretKey, encrypted_sample)
            decrypted_sample.SetLength(len(X_test[i]))
            real_values = [val.real for val in decrypted_sample.GetCKKSPackedValue()]
            prediction = model.predict([real_values])
            predictions_encrypted.append(prediction)
        
        accuracies_encrypted.append(accuracy_score(y_test, predictions_encrypted))
        total_time_encrypted += time.time() - t_start
    
    avg_encrypted_acc = np.mean(accuracies_encrypted)
    avg_non_encrypted_acc = np.mean(accuracies_non_encrypted)
    avg_encrypted_time = total_time_encrypted / trials
    avg_non_encrypted_time = total_time_non_encrypted / trials
    
    print(f"Avg Encrypted SVM Accuracy: {avg_encrypted_acc:.4f}")
    print(f"Avg Non-Encrypted SVM Accuracy: {avg_non_encrypted_acc:.4f}")
    print(f"Avg Encrypted Time: {avg_encrypted_time:.4f} sec")
    print(f"Avg Non-Encrypted Time: {avg_non_encrypted_time:.4f} sec")
    
    # Append results to CSV
    with open(csv_filename, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([1, 30, 10, 128, 1024, 8192, avg_encrypted_acc, avg_non_encrypted_acc, avg_encrypted_time, avg_non_encrypted_time])

def main():
    print("---- Testing OpenFHE Encryption ----")
    test_openfhe_encryption()
    print("---- Running Encrypted Polynomial SVM ----")
    run_encrypted_svm(trials=100)

if __name__ == "__main__":
    main()
