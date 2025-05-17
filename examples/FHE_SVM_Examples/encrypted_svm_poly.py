from openfhe import *
import numpy as np
import pandas as pd
from time import time
import math

def next_power_of_2(x):
    return 1 if x == 0 else 2**math.ceil(math.log2(x))

def resize_double_vector(data,new_size):
    # check if data is a scalar
    if isinstance(data, (int, float, complex)):
        data = [data]
    # If the new size is smaller than the current size,
    # we need to shorten the vector.
    if new_size < len(data):
        return data[:new_size]
    else:
        # If the new size is larger than the current size,
        # we need to add new entries and zero them out.
        for i in range(new_size-len(data)):
            data.append(0)
        return data
    
# cloning a vector m-1 times, and appending the clones to its end
def clone_vector_inplace(data,m):
    dataorig = data.copy()
    for i in range(m-1):
        data.extend(dataorig)
    return data

def total_sum(ct_in,row_size,cc):
    ct_out = ct_in
    for i in range(int(math.log2(row_size))):
        ct_temp = cc.EvalRotate(ct_out,2**i)
        ct_out = cc.EvalAdd(ct_out,ct_temp)
    return ct_out

def main():
    print("---- SVM Polynomial Kernel started ... !\n\n")

    # Load the data using pandas
    print("---- Loading Data and Model ----")
    X_test = pd.read_csv('data/credit_approval_test.csv')
    x = X_test.to_numpy().flatten().tolist()
    ytestscore = np.loadtxt("data/ytestscore_poly.txt").tolist()
    # Get number of features (n = 4)
    n = len(x)
    print("---- Data Loaded! ----")


    # Load the model
    gamma = 2
    degree = 3
    support_vectors = np.loadtxt("models/support_vectors.txt")
    n_SVs = len(support_vectors)
    print(f"Number of support vectors: {n_SVs}\n")
    print(f"Dimension of each support vector: {len(support_vectors[0])}\n")

    dual_coeffs = np.loadtxt("models/dual_coef.txt").flatten().tolist()
    bias = np.loadtxt("models/intercept_poly.txt").tolist()
    bias = resize_double_vector(bias,n)
    ytestscore = resize_double_vector(ytestscore,n)

    # Setup CryptoContext
    multDepth = 6
    scaleModSize = 50
    batchSize = n
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetBatchSize(next_power_of_2(batchSize*n_SVs))

    cc = GenCryptoContext(parameters)
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)

    print(f"CKKS is using ring dimension {cc.GetRingDimension()}\n")

    # Key Generation
    print("---- Key gen started ----\n")
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)
    # powers of two up to n
    cc.EvalRotateKeyGen(keys.secretKey,[0,1,2]) 
    print("---- Key gen done ----\n")

    # Encoding and encryption of inputs
    gamma_vec = [0] * n
    gamma_vec[0] = gamma
    print(f"n: {n}")
    clone_vector_inplace(gamma_vec,n_SVs)
    gamma_vec = resize_double_vector(gamma_vec,next_power_of_2(n*n_SVs))
    print(f"gamma_vec size: {len(gamma_vec)}")
    pt_gamma = cc.MakeCKKSPackedPlaintext(gamma_vec)

    # preparing polynomiakl coeffs
    kernel_poly_coeffs = [0]* (degree+1)
    kernel_poly_coeffs[degree] = 1

    # clone x, as many as support vectors
    clone_vector_inplace(x,n_SVs)
    x = resize_double_vector(x,next_power_of_2(n*n_SVs))
    pt_x = cc.MakeCKKSPackedPlaintext(x)

    # support vectors in 1 plaintext (flattened)
    flatened_support_vectors = support_vectors.flatten().tolist()
    flatened_support_vectors = resize_double_vector(flatened_support_vectors,next_power_of_2(n*n_SVs))
    pt_support_vectors = cc.MakeCKKSPackedPlaintext(flatened_support_vectors)

    # bias
    bias = resize_double_vector(bias,n*n_SVs)
    pt_bias = cc.MakeCKKSPackedPlaintext(bias)

    # dual coeffs
    dual_coeffs_vec = [0]*n*n_SVs
    for i in range(len(dual_coeffs)):
        dual_coeffs_vec[i*n] = dual_coeffs[i]
    pt_dual_coeffs = cc.MakeCKKSPackedPlaintext(dual_coeffs_vec)
    print("---- Data encoding done ----\n")

    # Encrypting the encoded vectors
    print("---- Encryption x started ----\n")
    ct_x = cc.Encrypt(keys.publicKey, pt_x)
    print("---- Data encryption done ----\n")

    # keep the model un-encrypted
    print("---- Evaluation started ----\n")
    t = time()
    
    # do the first vector here
    ct_prod = cc.EvalMult(ct_x,pt_support_vectors)
    ct_dot_prod = total_sum(ct_prod,n,cc)
    ct_gamma_dot_prod = cc.EvalMult(ct_dot_prod,pt_gamma)
    ct_kernel_out = cc.EvalPoly(ct_gamma_dot_prod,kernel_poly_coeffs)
    ct_kernel_dual_coeffs = cc.EvalMult(ct_kernel_out,pt_dual_coeffs)
    ct_sum = cc.EvalSum(ct_kernel_dual_coeffs,next_power_of_2(n*n_SVs))
    ct_res = cc.EvalAdd(ct_sum,pt_bias)
    timeEvalSVMTime = time() - t

    print("---- Evaluation done ----\n")
    print(f"Polynomial-SVM inference took {timeEvalSVMTime} ms\n")

    # Decryption and output

    result = cc.Decrypt(ct_res, keys.secretKey)
    result.SetLength(batchSize)
    print(f"Expected score = {ytestscore}")
    print(f"Predicted score (1st element) = {result}")
    print(f"Estimated precision in bits: {result.GetLogPrecision()}\n")

    print("---- SVM Polynomial Kernel terminated gracefully ...!\n")
                          







if __name__ == "__main__":
    main()