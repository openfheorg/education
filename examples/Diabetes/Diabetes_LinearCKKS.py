import numpy as np
import pandas as pd
import time
import os
import concurrent.futures
from openfhe import *
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score

# Output file for results
EXCEL_FILE = "Diabetes-LinearCKKS.xlsx"
DATASET_FILENAME = "PIDD.csv"  # Diabetes dataset

def setup_crypto_context_ckks(multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim):
    """
    Creates a CKKS crypto context with user-defined parameters.
    CKKS supports approximate arithmetic on real numbers.
    """
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scalSize)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetRingDim(ringDim)

    if securityLevel == 128:
        parameters.SetSecurityLevel(HEStd_128_classic)
    elif securityLevel == 192:
        parameters.SetSecurityLevel(HEStd_192_classic)
    elif securityLevel == 256:
        parameters.SetSecurityLevel(HEStd_256_classic)
    else:
        parameters.SetSecurityLevel(HEStd_NotSet)

    parameters.SetBatchSize(batchSize)
    context = GenCryptoContext(parameters)
    context.Enable(PKE)         # Public Key Encryption
    context.Enable(KEYSWITCH)   # Key switching
    context.Enable(LEVELEDSHE)  # Leveled SHE
    context.Enable(ADVANCEDSHE) # Advanced SHE
    return context

def load_dataset():
    """
    Loads the Pima Indian Diabetes dataset from CSV, label-encodes categorical columns,
    and returns features and labels.
    
    Assumes the target variable is the last column.
    """
    if not os.path.exists(DATASET_FILENAME):
        raise FileNotFoundError(f"Dataset file '{DATASET_FILENAME}' not found.")

    data = pd.read_csv(DATASET_FILENAME)
    print(f"CSV has {data.shape[1]} total columns (including the target).")
    
    # Assume the last column is the target variable
    target_column = data.columns[-1]
    print(f"Using '{target_column}' as the target column.")

    for col in data.select_dtypes(include=['object']).columns:
        data[col] = LabelEncoder().fit_transform(data[col])

    # In this example, we assume that after dropping the target column,
    # the feature set should contain 11 features. If the dataset structure is different,
    # adjust the slicing accordingly.
    features = data.drop(target_column, axis=1).iloc[:, :11]
    labels = data[target_column]

    print(f"- Dataset loaded successfully! Total features used: {features.shape[1]}")
    return features, labels

def get_user_input():
    """
    Prompts the user for hyperparameters and returns them.
    """
    trials = int(input("Enter number of trials: "))
    multDepth = int(input("Enter Multiplicative Depth (MD) (e.g., 1): "))
    scalSize = int(input("Enter Scaling Mod Size (SS) (e.g., 30): "))
    firstModSize = int(input("Enter First Mod Size (FM) (e.g., 60): "))
    securityLevel = int(input("Enter Security Level (SL) (128, 192, 256): "))
    batchSize = int(input("Enter Batch Size (BS) (e.g., 4096): "))
    ringDim = int(input("Enter Ring Dimension (RD) (e.g., 8192 or 16384): "))
    max_test_samples = int(input("Enter the number of test samples to use (0 for all): "))
    return trials, multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim, max_test_samples

def encrypted_prediction(sample, model, context, keys):
    """
    Encrypt -> Decrypt -> Predict for one sample using CKKS.
    """
    pt = context.MakeCKKSPackedPlaintext(sample)
    encrypted = context.Encrypt(keys.publicKey, pt)
    decrypted_pt = context.Decrypt(keys.secretKey, encrypted)
    decrypted_pt.SetLength(len(sample))
    real_values = [val.real for val in decrypted_pt.GetCKKSPackedValue()]
    return model.predict([real_values])[0]

def save_results_to_excel(results):
    """
    Saves exactly one row of results to Excel (overwriting previous).
    Results should be a list of tuples with columns:
    [MD, SS, FM, SL, BS, RD, AEA, NEA, AET, ANT, Scale up]
    """
    df = pd.DataFrame(results, columns=[
        "MD", "SS", "FM", "SL", "BS", "RD",
        "AEA", "NEA", "AET", "ANT", "Scale up"
    ])
    df.to_excel(EXCEL_FILE, index=False)

def run_encrypted_linear_svm(trials, multDepth, scalSize, firstModSize,
                             securityLevel, batchSize, ringDim, max_test_samples):
    """
    Runs an encrypted Linear SVM (CKKS) with 3 significant figures,
    printing the Scale up (AET/ANT) ratio as a decimal, and saves one row to Excel.
    """
    print("---- Running Encrypted Linear SVM (CKKS) ----")
    X, y = load_dataset()
    X = StandardScaler().fit_transform(X)
    print(f"Total dataset samples: {len(X)}")
    print(f"Total features: {X.shape[1]}")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    if max_test_samples > 0 and len(X_test) > max_test_samples:
        print(f"Limiting test set to {max_test_samples} samples.")
        X_test = X_test[:max_test_samples]
        y_test = y_test[:max_test_samples]

    model = SVC(kernel='linear')
    model.fit(X_train, y_train)

    accuracies_encrypted = []
    accuracies_non_encrypted = []
    total_time_encrypted = 0.0
    total_time_non_encrypted = 0.0

    for _ in range(trials):
        # Non-encrypted prediction
        t_start = time.time()
        predictions_plain = model.predict(X_test)
        total_time_non_encrypted += time.time() - t_start
        accuracies_non_encrypted.append(accuracy_score(y_test, predictions_plain))

        # Encrypted prediction using CKKS
        t_start = time.time()
        context = setup_crypto_context_ckks(multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim)
        keys = context.KeyGen()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(encrypted_prediction, sample, model, context, keys): i
                for i, sample in enumerate(X_test)
            }
            predictions_encrypted_list = [future.result() for future in concurrent.futures.as_completed(futures)]

        accuracies_encrypted.append(accuracy_score(y_test, predictions_encrypted_list))
        total_time_encrypted += time.time() - t_start

    avg_encrypted_acc = np.mean(accuracies_encrypted)
    avg_non_encrypted_acc = np.mean(accuracies_non_encrypted)
    avg_encrypted_time = total_time_encrypted / trials
    avg_non_encrypted_time = total_time_non_encrypted / trials
    scale_up = avg_encrypted_time / avg_non_encrypted_time if avg_non_encrypted_time != 0 else float('inf')

    print("\n---- Final Results ----")
    print(f"Avg Encrypted SVM Accuracy (AEA): {avg_encrypted_acc:.3g}")
    print(f"Avg Non-Encrypted SVM Accuracy (NEA): {avg_non_encrypted_acc:.3g}")
    print(f"Avg Encrypted Time (AET): {avg_encrypted_time:.3g} sec")
    print(f"Avg Non-Encrypted Time (ANT): {avg_non_encrypted_time:.3g} sec")
    print(f"Scale up (AET/ANT): {scale_up:.3f}\n")

    aea_str = f"{avg_encrypted_acc:.3g}"
    nea_str = f"{avg_non_encrypted_acc:.3g}"
    aet_str = f"{avg_encrypted_time:.3g}"
    ant_str = f"{avg_non_encrypted_time:.3g}"
    scale_str = f"{scale_up:.3f}"

    results = [(
        multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim,
        aea_str, nea_str, aet_str, ant_str, scale_str
    )]
    save_results_to_excel(results)

def main():
    trials, multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim, max_test_samples = get_user_input()
    run_encrypted_linear_svm(trials, multDepth, scalSize, firstModSize, securityLevel, batchSize, ringDim, max_test_samples)

if __name__ == "__main__":
    main()

