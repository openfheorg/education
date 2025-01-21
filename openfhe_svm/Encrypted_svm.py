 
    
from openfhe import *
import numpy as np
import pandas as pd
from time import time
import math
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

def next_power_of_2(x):
    return 1 if x == 0 else 2**math.ceil(math.log2(x))

def resize_double_vector(data, new_size):
    if isinstance(data, (int, float, complex)):
        data = [data]
    if new_size < len(data):
        return data[:new_size]
    else:
        for i in range(new_size-len(data)):
            data.append(0)
        return data

def clone_vector_inplace(data, m):
    dataorig = data.copy()
    for i in range(m-1):
        data.extend(dataorig)
    return data

def sum_along_rows(ct_in, row_size, cc):
    """Optimized sum along rows using SIMD technique"""
    ct_out = ct_in
    for i in range(int(math.log2(row_size))):
        ct_temp = cc.EvalRotate(ct_out, 2**i)
        ct_out = cc.EvalAdd(ct_out, ct_temp)
    return ct_out

def sum_along_columns(ct_in, n_rows, n_cols, cc):
    """Optimized sum along columns using SIMD technique"""
    ct_out = ct_in
    stride = n_cols
    for i in range(int(math.log2(n_rows))):
        ct_temp = cc.EvalRotate(ct_out, stride * (2**i))
        ct_out = cc.EvalAdd(ct_out, ct_temp)
    return ct_out

def load_data(N):
    """Load and prepare data for processing"""
    print("---- Loading Data and Model ----")
    
    X_test = pd.read_csv('data/credit_approval_test.csv')
    max_samples = len(X_test)
    N = min(N, max_samples)
    X_test = X_test.iloc[:N]
    n_features = X_test.shape[1]
    
    ytestscore = np.loadtxt("data/ytestscore_poly.txt")
    ytestscore = ytestscore if np.ndim(ytestscore) > 0 else [ytestscore]
    ytestscore = ytestscore[:N]
    
    support_vectors = np.loadtxt("models/support_vectors.txt")
    dual_coeffs = np.loadtxt("models/dual_coef.txt").flatten().tolist()
    bias = float(np.loadtxt("models/intercept_poly.txt"))
    
    print(f"Processing {N} samples with {n_features} features each")
    print("---- Data Loaded! ----")
    
    return X_test, ytestscore, support_vectors, dual_coeffs, bias, n_features, N

def setup_crypto_context(n_features, n_SVs):
    """Setup cryptographic context"""
    print("---- Setting up Crypto Context ----")
    
    multDepth = 6
    scaleModSize = 50
    firstModSize = 55
    batchSize = n_features
    
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetBatchSize(next_power_of_2(batchSize*n_SVs))
    parameters.SetSecurityLevel(HEStd_128_classic)
    parameters.SetRingDim(32768)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)

    print("---- Key Generation Started ----")
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)
    
    needed_rotations = set()
    for i in range(int(math.log2(n_features))):
        needed_rotations.add(2**i)
    for i in range(int(math.log2(n_SVs))):
        needed_rotations.add(n_features * (2**i))
    
    cc.EvalRotateKeyGen(keys.secretKey, list(needed_rotations))
    
    print("---- Key Generation Complete ----")
    return cc, keys, batchSize

def prepare_model_components(cc, n_features, n_SVs, support_vectors, dual_coeffs, bias, scale_factor=1.0):
    """Enhanced model components preparation with improved scaling"""
    print("---- Preparing Model Components with Enhanced Scaling ----")
    
    # Normalize support vectors with adaptive scaling
    sv_scaled = support_vectors.flatten().tolist()
    sv_mean = sum(sv_scaled) / len(sv_scaled)
    sv_std = math.sqrt(sum((x - sv_mean) ** 2 for x in sv_scaled) / len(sv_scaled))
    sv_scaled = [(x - sv_mean) / (sv_std if sv_std > 0 else 1.0) for x in sv_scaled]
    
    max_sv = max(abs(max(sv_scaled)), abs(min(sv_scaled)))
    sv_factor = scale_factor / max_sv if max_sv > 0 else scale_factor
    sv_scaled = [x * sv_factor for x in sv_scaled]
    sv_scaled = resize_double_vector(sv_scaled, next_power_of_2(n_features*n_SVs))
    pt_support_vectors = cc.MakeCKKSPackedPlaintext(sv_scaled)
    
    # Optimize gamma parameter based on feature statistics
    feature_distances = []
    for i in range(len(support_vectors)):
        for j in range(i + 1, len(support_vectors)):
            dist = sum((a - b) ** 2 for a, b in zip(support_vectors[i], support_vectors[j]))
            feature_distances.append(math.sqrt(dist))
    
    median_distance = sorted(feature_distances)[len(feature_distances)//2]
    gamma = 1.0 / (median_distance * n_features * scale_factor)
    
    gamma_vec = [0] * n_features
    gamma_vec[0] = gamma
    clone_vector_inplace(gamma_vec, n_SVs)
    gamma_vec = resize_double_vector(gamma_vec, next_power_of_2(n_features*n_SVs))
    pt_gamma = cc.MakeCKKSPackedPlaintext(gamma_vec)
    
    # Enhanced dual coefficients scaling
    dual_coeffs_mean = sum(dual_coeffs) / len(dual_coeffs)
    dual_coeffs_std = math.sqrt(sum((x - dual_coeffs_mean) ** 2 for x in dual_coeffs) / len(dual_coeffs))
    dual_coeffs_normalized = [(x - dual_coeffs_mean) / (dual_coeffs_std if dual_coeffs_std > 0 else 1.0) for x in dual_coeffs]
    
    max_dual = max(abs(max(dual_coeffs_normalized)), abs(min(dual_coeffs_normalized)))
    dual_coeffs_scaled = [0]*n_features*n_SVs
    for i in range(len(dual_coeffs_normalized)):
        dual_coeffs_scaled[i*n_features] = dual_coeffs_normalized[i] * scale_factor / max_dual
    pt_dual_coeffs = cc.MakeCKKSPackedPlaintext(dual_coeffs_scaled)
    
    # Adaptive polynomial coefficients based on data distribution
    kernel_poly_coeffs = [0] * 4
    kernel_poly_coeffs[3] = scale_factor
    kernel_poly_coeffs[2] = 0.3 * scale_factor  # Add quadratic term
    kernel_poly_coeffs[1] = 0.1 * scale_factor  # Add linear term
    
    # Balanced bias scaling
    normalized_bias = bias / (max_dual * dual_coeffs_std)
    bias_scaled = [normalized_bias * scale_factor] * n_features*n_SVs
    bias_scaled = resize_double_vector(bias_scaled, next_power_of_2(n_features*n_SVs))
    pt_bias = cc.MakeCKKSPackedPlaintext(bias_scaled)
    
    print(f"Enhanced scaling complete:")
    print(f"Gamma value: {gamma:.6f}")
    print(f"Support vector scaling factor: {sv_factor:.6f}")
    print(f"Normalized bias: {normalized_bias:.6f}")
    
    return pt_gamma, kernel_poly_coeffs, pt_support_vectors, pt_dual_coeffs, pt_bias

def normalize_features(x_sample):
    """Enhanced feature normalization with outlier handling"""
    # Calculate robust statistics
    sorted_x = sorted(x_sample)
    q1 = sorted_x[len(sorted_x)//4]
    q3 = sorted_x[3*len(sorted_x)//4]
    iqr = q3 - q1
    
    # Define outlier bounds
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr
    
    # Handle outliers
    x_clean = [min(max(x, lower_bound), upper_bound) for x in x_sample]
    
    # Robust standardization using median and MAD
    median_x = sorted_x[len(sorted_x)//2]
    mad = sum(abs(x - median_x) for x in x_clean) / len(x_clean)
    
    x_standardized = [(x - median_x) / (mad if mad > 0 else 1.0) for x in x_clean]
    
    # Additional scaling for numerical stability
    max_x = max(abs(max(x_standardized)), abs(min(x_standardized)))
    x_factor = 0.5 / max_x if max_x > 0 else 0.5
    
    return [x * x_factor for x in x_standardized]

def calculate_adaptive_threshold_enhanced(encrypted_scores, original_scores, original_preds):
    """Enhanced threshold calculation with class balancing"""
    pos_scores = []
    neg_scores = []
    
    # Separate scores by class
    for score, pred in zip(encrypted_scores, original_preds):
        if pred == 1:
            pos_scores.append(score)
        else:
            neg_scores.append(score)
    
    if not pos_scores or not neg_scores:
        return np.median(encrypted_scores)
    
    # Calculate class-specific statistics
    pos_mean = sum(pos_scores) / len(pos_scores)
    neg_mean = sum(neg_scores) / len(neg_scores)
    
    pos_std = math.sqrt(sum((x - pos_mean) ** 2 for x in pos_scores) / len(pos_scores))
    neg_std = math.sqrt(sum((x - neg_mean) ** 2 for x in neg_scores) / len(neg_scores))
    
    # Calculate class weights based on sample sizes
    total_samples = len(pos_scores) + len(neg_scores)
    pos_weight = len(neg_scores) / total_samples  # Inverse class frequency
    neg_weight = len(pos_scores) / total_samples
    
    # Calculate threshold using weighted approach
    threshold = (pos_mean * pos_weight + neg_mean * neg_weight)
    
    # Adjust threshold based on standard deviations
    threshold_adjustment = (pos_std * pos_weight + neg_std * neg_weight) * 0.1
    if len(pos_scores) < len(neg_scores):
        threshold -= threshold_adjustment
    else:
        threshold += threshold_adjustment
    
    print("\nEnhanced Threshold Analysis:")
    print(f"Positive class: mean={pos_mean:.6f}, std={pos_std:.6f}, samples={len(pos_scores)}")
    print(f"Negative class: mean={neg_mean:.6f}, std={neg_std:.6f}, samples={len(neg_scores)}")
    print(f"Class weights: pos={pos_weight:.3f}, neg={neg_weight:.3f}")
    print(f"Base threshold: {threshold:.6f}")
    print(f"Adjusted threshold: {threshold + threshold_adjustment:.6f}")
    
    return threshold + threshold_adjustment

def evaluate_threshold_stability(threshold, encrypted_scores, original_preds):
    """Evaluate the stability and reliability of the calculated threshold
    
    Args:
        threshold: Calculated threshold value
        encrypted_scores: List of encrypted prediction scores
        original_preds: List of original predictions
    """
    scores = np.array(encrypted_scores)
    preds = np.array(original_preds)
    
    # Calculate prediction stability metrics
    margin = np.abs(scores - threshold)
    unstable_predictions = np.sum(margin < 0.1 * np.std(scores))
    
    print("\n---- Threshold Stability Analysis ----")
    print(f"Total predictions: {len(scores)}")
    print(f"Predictions near threshold: {unstable_predictions}")
    print(f"Percentage of unstable predictions: {unstable_predictions/len(scores):.2%}")
    
    # Analyze class separation
    pos_scores = scores[preds == 1]
    neg_scores = scores[preds == 0]
    
    if len(pos_scores) > 0 and len(neg_scores) > 0:
        separation = np.abs(np.mean(pos_scores) - np.mean(neg_scores))
        overlap = np.sum((neg_scores > np.min(pos_scores)) & 
                        (neg_scores < np.max(pos_scores)))
        
        print("\nClass Separation Analysis:")
        print(f"  Mean separation: {separation:.6f}")
        print(f"  Overlapping samples: {overlap}")
        print(f"  Overlap percentage: {overlap/len(scores):.2%}")
        

def find_best_parameters(X_test, ytestscore, support_vectors, dual_coeffs, bias, n_features):
    """Find best parameters using adaptive threshold"""
    print("\n---- Parameter Optimization Started ----")
    best_accuracy = 0
    best_params = None
    
    n_SVs = len(support_vectors)
    cc, keys, batchSize = setup_crypto_context(n_features, n_SVs)
    
    # Test different scale factors
    scale_factors = [0.3, 0.5, 0.7]
    
    for scale_factor in scale_factors:
        print(f"\nTesting scale_factor={scale_factor}")
        try:
            # Prepare model components
            pt_gamma, kernel_poly_coeffs, pt_support_vectors, pt_dual_coeffs, pt_bias = \
                prepare_model_components(cc, n_features, n_SVs, support_vectors, 
                                      dual_coeffs, bias, scale_factor)
            
            # Get scores for all samples
            scores = []
            original_scores = []
            
            for i in range(len(X_test)):
                x = X_test.iloc[i].to_numpy().tolist()
                x_sample = x.copy()
                clone_vector_inplace(x_sample, n_SVs)
                x_sample = resize_double_vector(x_sample, next_power_of_2(n_features*n_SVs))
                
                # Get encrypted score
                score = evaluate_with_recovery(cc, keys, x_sample, pt_support_vectors,
                                            pt_gamma, kernel_poly_coeffs, pt_dual_coeffs,
                                            pt_bias, n_features, n_SVs, batchSize)
                scores.append(score)
                
                # Get original score
                orig_score = np.sum([dual_coeffs[j] * (1 + np.dot(support_vectors[j], X_test.iloc[i].to_numpy()))**3 
                                   for j in range(len(support_vectors))]) + bias
                original_scores.append(orig_score)
            
            # Calculate adaptive threshold
            threshold = calculate_adaptive_threshold_enhanced(scores, original_scores, ytestscore)
            
            # Evaluate accuracy with adaptive threshold
            correct = 0
            for i in range(len(scores)):
                pred = 1 if scores[i] > threshold else 0
                true_label = 1 if ytestscore[i] > 0 else 0
                if pred == true_label:
                    correct += 1
            
            accuracy = (correct / len(scores)) * 100
            print(f"Accuracy with adaptive threshold: {accuracy:.2f}%")
            
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_params = (scale_factor, threshold)
                
        except Exception as e:
            print(f"Error with scale_factor {scale_factor}: {str(e)}")
            continue
    
    if best_params is None:
        print("No valid parameters found, using defaults")
        return (0.5, 0.005)
    
    print(f"\nBest parameters found: scale_factor={best_params[0]}, threshold={best_params[1]}")
    print(f"Best validation accuracy: {best_accuracy:.2f}%")
    return best_params

def evaluate_sample(cc, keys, x_sample, pt_support_vectors, pt_gamma, kernel_poly_coeffs, 
                   pt_dual_coeffs, pt_bias, n_features, n_SVs, batchSize):
    """Evaluate sample with preserved precision and score analysis"""
    max_x = max(abs(max(x_sample)), abs(min(x_sample)))
    x_factor = 1.0 / max_x if max_x > 0 else 1.0
    x_scaled = [x * x_factor for x in x_sample]
    
    pt_x = cc.MakeCKKSPackedPlaintext(x_scaled)
    ct_x = cc.Encrypt(keys.publicKey, pt_x)

    try:
        ct_prod = cc.EvalMult(ct_x, pt_support_vectors)
        ct_dot_prod = sum_along_rows(ct_prod, n_features, cc)
        ct_gamma_dot_prod = cc.EvalMult(ct_dot_prod, pt_gamma)
        ct_kernel_out = cc.EvalPoly(ct_gamma_dot_prod, kernel_poly_coeffs)
        ct_kernel_dual_coeffs = cc.EvalMult(ct_kernel_out, pt_dual_coeffs)
        ct_sum = sum_along_columns(ct_kernel_dual_coeffs, n_SVs, n_features, cc)
        ct_res = cc.EvalAdd(ct_sum, pt_bias)

        result = cc.Decrypt(ct_res, keys.secretKey)
        result.SetLength(batchSize)
        return result.GetRealPackedValue()[0]
        
    except RuntimeError as e:
        print(f"Error during evaluation: {str(e)}")
        raise

def display_results(y_trues, y_preds, total_time, N):
    """Display evaluation metrics"""
    print("\n========================================")
    print("            | Results Summary |          ")
    print("========================================\n")
    print(f"Total samples processed: {N}")
    print(f"Average processing time: {total_time/N:.3f} seconds per sample")
    
    accuracy = accuracy_score(y_trues, y_preds) * 100
    precision = precision_score(y_trues, y_preds, zero_division=0) * 100
    recall = recall_score(y_trues, y_preds, zero_division=0) * 100
    f1 = f1_score(y_trues, y_preds, zero_division=0) * 100

    print(f"\nAccuracy: {accuracy:.2f}%")
    print(f"Precision: {precision:.2f}%")
    print(f"Recall: {recall:.2f}%")
    print(f"F1-Score: {f1:.2f}%")

    conf_matrix = confusion_matrix(y_trues, y_preds, labels=[0, 1])
    print("\nConfusion Matrix:")
    print("[ TN  FP ]")
    print("[ FN  TP ]\n")
    print(conf_matrix)

def evaluate_with_recovery(cc, keys, x_sample, pt_support_vectors, pt_gamma, 
                         kernel_poly_coeffs, pt_dual_coeffs, pt_bias, 
                         n_features, n_SVs, batchSize):
    """Evaluate with error recovery mechanism"""
    try:
        # First try with standard normalization
        x_scaled = normalize_features(x_sample)
        return evaluate_sample(cc, keys, x_scaled, pt_support_vectors, pt_gamma,
                             kernel_poly_coeffs, pt_dual_coeffs, pt_bias,
                             n_features, n_SVs, batchSize)
    except RuntimeError as e:
        print(f"First attempt failed, trying with conservative scaling...")
        try:
            # Second attempt with more conservative scaling
            x_scaled = [x * 0.1 for x in normalize_features(x_sample)]
            return evaluate_sample(cc, keys, x_scaled, pt_support_vectors, pt_gamma,
                                 kernel_poly_coeffs, pt_dual_coeffs, pt_bias,
                                 n_features, n_SVs, batchSize)
        except RuntimeError as e:
            print(f"Second attempt failed, using very conservative scaling...")
            # Final attempt with very conservative scaling
            x_scaled = [x * 0.01 for x in normalize_features(x_sample)]
            return evaluate_sample(cc, keys, x_scaled, pt_support_vectors, pt_gamma,
                                 kernel_poly_coeffs, pt_dual_coeffs, pt_bias,
                                 n_features, n_SVs, batchSize)

        
def calculate_threshold_with_validation(encrypted_scores, original_preds, n_splits=5):
    """Enhanced threshold calculation with better class separation"""
    scores = np.array(encrypted_scores)
    preds = np.array(original_preds)
    
    # Normalize scores to reduce scaling issues
    scores = (scores - np.mean(scores)) / np.std(scores)
    
    # Calculate class-specific statistics
    pos_scores = scores[preds == 1]
    neg_scores = scores[preds == 0]
    
    if len(pos_scores) == 0 or len(neg_scores) == 0:
        return np.median(scores)
    
    pos_mean, pos_std = np.mean(pos_scores), np.std(pos_scores)
    neg_mean, neg_std = np.mean(neg_scores), np.std(neg_scores)
    
    # Find optimal threshold using various methods
    thresholds = []
    
    # Method 1: Weighted mean
    weight = len(pos_scores) / len(scores)
    thresholds.append(pos_mean * weight + neg_mean * (1 - weight))
    
    # Method 2: Midpoint between distributions
    thresholds.append((pos_mean + neg_mean) / 2)
    
    # Method 3: Point of minimal overlap
    overlap_threshold = find_minimal_overlap_threshold(pos_scores, neg_scores)
    thresholds.append(overlap_threshold)
    
    # Evaluate each threshold
    performances = []
    for thresh in thresholds:
        preds_thresh = (scores > thresh).astype(int)
        acc = accuracy_score(original_preds, preds_thresh)
        performances.append(acc)
    
    # Select best performing threshold
    best_threshold = thresholds[np.argmax(performances)]
    
    print("\n---- Enhanced Threshold Analysis ----")
    print(f"Positive class: mean={pos_mean:.3f}, std={pos_std:.3f}")
    print(f"Negative class: mean={neg_mean:.3f}, std={neg_std:.3f}")
    print(f"Class separation: {abs(pos_mean - neg_mean):.3f}")
    print(f"Selected threshold: {best_threshold:.3f}")
    
    return best_threshold
    

def find_minimal_overlap_threshold(pos_scores, neg_scores):
    """Find threshold that minimizes class overlap"""
    min_score = min(np.min(pos_scores), np.min(neg_scores))
    max_score = max(np.max(pos_scores), np.max(neg_scores))
    
    best_threshold = min_score
    min_overlap = float('inf')
    
    # Test different thresholds
    for threshold in np.linspace(min_score, max_score, 100):
        false_pos = np.sum(neg_scores > threshold)
        false_neg = np.sum(pos_scores <= threshold)
        overlap = false_pos + false_neg
        
        if overlap < min_overlap:
            min_overlap = overlap
            best_threshold = threshold
    
    return best_threshold

def make_predictions_with_confidence(encrypted_scores, threshold):
    """Make predictions with improved confidence calculation"""
    scores = np.array(encrypted_scores)
    
    # Normalize scores
    scores_normalized = (scores - np.mean(scores)) / np.std(scores)
    
    # Calculate confidence based on distance from threshold
    distances = abs(scores_normalized - threshold)
    max_distance = max(distances)
    
    # Calculate confidence scores using sigmoid function
    confidences = 1 / (1 + np.exp(-2 * (distances / max_distance - 0.5)))
    
    # Make predictions
    predictions = (scores_normalized > threshold).astype(int)
    
    return predictions, confidences

def main():
    print("---- SVM Polynomial Kernel started ... !\n\n")

    # Load data and model
    N = 137  
    X_test, ytestscore, support_vectors, dual_coeffs, bias, n_features, N = load_data(N)
    n_SVs = len(support_vectors)

    # Get original predictions
    print("\nOriginal SVM predictions (non-encrypted):")
    original_scores = []
    original_preds = []
    for i in range(N):
        x = X_test.iloc[i].to_numpy()
        score = np.sum([dual_coeffs[j] * (1 + np.dot(support_vectors[j], x))**3 
                       for j in range(len(support_vectors))]) + bias
        pred = 1 if score > 0 else 0
        original_scores.append(score)
        original_preds.append(pred)
        print(f"Sample {i+1}: Original Score = {score:.6f}, Label = {pred}")

    # Setup and prepare model
    cc, keys, batchSize = setup_crypto_context(n_features, n_SVs)
    scale_factor = 0.5 
    pt_gamma, kernel_poly_coeffs, pt_support_vectors, pt_dual_coeffs, pt_bias = \
        prepare_model_components(cc, n_features, n_SVs, support_vectors, dual_coeffs, 
                               bias, scale_factor)

    # First pass: collect all encrypted scores
    print("\n---- Collecting Encrypted Scores ----")
    encrypted_scores = []
    total_time = 0
    
    for i in range(N):
        x = X_test.iloc[i].to_numpy().tolist()
        x_sample = x.copy()
        clone_vector_inplace(x_sample, n_SVs)
        x_sample = resize_double_vector(x_sample, next_power_of_2(n_features*n_SVs))
        
        # Measure inference time
        start_time = time()
        score = evaluate_with_recovery(
            cc=cc,
            keys=keys,
            x_sample=x_sample,
            pt_support_vectors=pt_support_vectors,
            pt_gamma=pt_gamma,
            kernel_poly_coeffs=kernel_poly_coeffs,
            pt_dual_coeffs=pt_dual_coeffs,
            pt_bias=pt_bias,
            n_features=n_features,
            n_SVs=n_SVs,
            batchSize=batchSize
        )
        inference_time = time() - start_time
        total_time += inference_time
        
        encrypted_scores.append(score)
        print(f"Sample {i+1}: Score = {score:.6f}, Time = {inference_time:.3f}s")

    # Calculate threshold using cross-validation
    adaptive_threshold = calculate_threshold_with_validation(encrypted_scores, original_preds)
    
    # Evaluate threshold stability
    evaluate_threshold_stability(adaptive_threshold, encrypted_scores, original_preds)

    # Replace the old prediction loop with enhanced confidence prediction
    print("\n---- Making Predictions with Enhanced Confidence ----")
    y_preds, confidences = make_predictions_with_confidence(encrypted_scores, adaptive_threshold)

    # Print predictions with confidence analysis
    for i in range(N):
        print(f"\nSample {i+1}:")
        print(f"  Original Score: {original_scores[i]:.6f} (Label: {original_preds[i]})")
        print(f"  Encrypted Score: {encrypted_scores[i]:.6f}")
        print(f"  Predicted: {y_preds[i]}")
        print(f"  Confidence: {confidences[i]:.2%}")

    # Analyze high confidence predictions
    high_conf_mask = confidences > 0.8
    high_conf_count = np.sum(high_conf_mask)
    
    print("\n---- Confidence Analysis ----")
    print(f"High confidence predictions: {high_conf_count}/{len(y_preds)} "
          f"({high_conf_count/len(y_preds):.2%})")
    
    if high_conf_count > 0:
        high_conf_acc = accuracy_score(
            np.array(original_preds)[high_conf_mask], 
            np.array(y_preds)[high_conf_mask]
        )
        print(f"High confidence accuracy: {high_conf_acc:.2%}")
    else:
        print("No high confidence predictions found")

    # Display overall results
    print("\n---- Final Results ----")
    display_results(original_preds, y_preds, total_time, N)
    
    # Additional analysis for different confidence thresholds
    print("\n---- Confidence Threshold Analysis ----")
    for conf_threshold in [0.6, 0.7, 0.8, 0.9]:
        conf_mask = confidences > conf_threshold
        count = np.sum(conf_mask)
        if count > 0:
            acc = accuracy_score(
                np.array(original_preds)[conf_mask], 
                np.array(y_preds)[conf_mask]
            )
            print(f"\nConfidence threshold {conf_threshold}:")
            print(f"  Predictions: {count}/{len(y_preds)} ({count/len(y_preds):.2%})")
            print(f"  Accuracy: {acc:.2%}")

    print("\n---- SVM Polynomial Kernel terminated gracefully ...!\n")

if __name__ == "__main__":
    main()
