// Code from https://github.com/FedericoMazzone/openfhe-ml/tree/main
#include "openfhe.h"

using namespace lbcrypto;

#include <iostream>

/**
 * Compute the inner product between two (plaintext) vectors.
 * @param vector1 first input vector
 * @param vector2 second input vector
 * @return inner product value
 */
double innerProduct(
    std::vector<double> vector1,
    std::vector<double> vector2
)
{
    double inner_product = 0;

    for (size_t i = 0; i < vector1.size(); i++) {
        inner_product += vector1[i] * vector2[i];
    }

    return inner_product;
}


size_t nextPowerOf2(
    size_t n
)
{
    if (n == 0 || n == 1) return 1;
    else return 1 << ((int) std::log2(n - 1) + 1);
}

std::vector<std::vector<double>> resizeMatrix(
    std::vector<std::vector<double>> matrix,
    size_t numRows,
    size_t numCols
)
{
    for (auto &row : matrix) row.resize(numCols, 0);
    matrix.resize(numRows, std::vector<double>(numCols, 0));
    return matrix;
}


std::vector<double> flattenMatrix(
    std::vector<std::vector<double>> matrix,
    bool direction
)
{
    std::vector<double> res;
    if (direction)
        for (auto &row : matrix)
            res.insert(end(res), begin(row), end(row));
    else {
        for (size_t i = 0; i < matrix[0].size(); i++) 
            for (size_t j = 0; j < matrix.size(); j++)
                res.push_back(matrix[j][i]);
    }
    return res;
}


std::vector<double> scaleVector(
    const std::vector<float> &vector,
    const int scale
)
{
    std::vector<double> result;
    for (float v : vector)
        result.push_back(v * scale);
    return result;
}


std::vector<std::vector<double>> scaleMatrix(
    const std::vector<std::vector<float>> &matrix,
    const int scale
)
{
    std::vector<std::vector<double>> result;
    std::vector<double> row;
    for (std::vector<float> vector : matrix) {
        for (float v : vector)
            row.push_back(v * scale);
        result.push_back(row);
        row.clear();
    }
    return result;
}


size_t argmax(
    const std::vector<double> &vector
)
{
    size_t argmax = 0;
    double max = vector[argmax];
    for (size_t i = 0; i < vector.size(); i++) {
        if (vector[i] > max) {
            argmax = i;
            max = vector[i];
        }
    }
    return argmax;
}


double mod(
    int64_t value,
    const int64_t &modulus
)
{
    value = value % modulus;

    if (value > ((modulus % 2 == 0) ? (modulus >> 1) - 1 : (modulus >> 1)))
        value -= modulus;
    else if (value < - (modulus >> 1))
        value += modulus;

    return value;
}
std::vector<double> genRandVect(
    size_t length,
    int64_t maxValue, int64_t seconds
)
{
    std::srand(unsigned(std::time(0)+seconds));
    auto myrand = [maxValue] () {
        return (std::rand() % (maxValue << 1)) - maxValue;
    };
    std::vector<double> vector(length);
    std::generate(vector.begin(), vector.end(), myrand);
    return vector;
}

std::vector<std::vector<double>> transpose(
    std::vector<std::vector<double>> matrix
)
{
    std::vector<std::vector<double>> matrixT(
        matrix[0].size(),
        std::vector<double>(matrix.size())
    );
    for (size_t i = 0; i < matrix[0].size(); i++) 
        for (size_t j = 0; j < matrix.size(); j++)
            matrixT[i][j] = matrix[j][i];
    return matrixT;
}


std::vector<std::vector<int64_t>> genRandMatrix(
    size_t rows,
    size_t cols,
    int64_t maxValue
)
{
    std::srand(unsigned(std::time(nullptr)));
    auto myrand = [maxValue] () {
        return (std::rand() % (maxValue << 1)) - maxValue;
    };
    std::vector<std::vector<int64_t>> matrix(rows, std::vector<int64_t>(cols));
    for (size_t i = 0; i < rows; i++)
        std::generate(matrix[i].begin(), matrix[i].end(), myrand);
    return matrix;
}

std::vector<std::vector<double>> genRandMatrix(
    size_t rows,
    size_t cols,
    int64_t maxValue, int seconds
)
{
    std::srand(unsigned(std::time(0)+seconds));
    auto myrand = [maxValue] () {
        return (std::rand() % (maxValue << 1)) - maxValue;
    };
    std::vector<std::vector<double>> matrix(rows, std::vector<double>(cols));
    for (size_t i = 0; i < rows; i++)
        std::generate(matrix[i].begin(), matrix[i].end(), myrand);
    return matrix;
}


std::vector<double> vectorMatrixMult(
    std::vector<double> vector,
    std::vector<std::vector<double>> matrix
)
{
    std::vector<std::vector<double>> matrixT = transpose(matrix);
    std::vector<double> result;
    for (size_t i = 0; i < matrixT.size(); i++) {
        double innProd = innerProduct(vector, matrixT[i]);
        result.push_back(innProd);
    }
    return result;
}


/**
 * Compute the inner product between two encrypted vectors.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param vector1C first encrypted input vector
 * @param vector2C second encrypted input vector
 * @param vectorLength length of the vector (in plaintext)
 * @param masking whether you want the output ciphertext to contain only the
 * output value in the first position, and 0s in the other positions
 * @return encrypted inner product value
 */
Ciphertext<DCRTPoly> innerProductCC(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vector1C,
    Ciphertext<DCRTPoly> vector2C,
    size_t vectorLength,
    bool masking = false
)
{
    Ciphertext<DCRTPoly> v1v2C = cryptoContext->EvalMult(vector1C, vector2C);

    const std::vector<double> ZERO = {0};
    const Plaintext ZERO_PLAINTEXT = cryptoContext->MakeCKKSPackedPlaintext(ZERO);
    Ciphertext<DCRTPoly> innerProductC = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
    for (size_t i = 0; i < vectorLength; i++)
        innerProductC = cryptoContext->EvalAdd(innerProductC, cryptoContext->EvalRotate(v1v2C, i));
    
    if (masking) {
        const std::vector<double> ONE = {1};
        const Plaintext ONE_PLAINTEXT = cryptoContext->MakeCKKSPackedPlaintext(ONE);
        innerProductC = cryptoContext->EvalMult(innerProductC, ONE_PLAINTEXT);
    }

    return innerProductC;
}


/**
 * Compute the inner product between an encrypted vector and a plaintext vector.
 * The naive algorithm is used.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param vector1C first encrypted input vector
 * @param vector2 second (plaintext) input vector
 * @param masking whether you want the output ciphertext to contain only the
 * output value in the first position, and 0s in the other positions
 * @return encrypted inner product value
 */
Ciphertext<DCRTPoly> innerProductCP(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vector1C,
    std::vector<double> vector2,
    bool masking = false
)
{
    Plaintext vector2P  = cryptoContext->MakeCKKSPackedPlaintext(vector2);

    Ciphertext<DCRTPoly> v1v2C = cryptoContext->EvalMult(vector1C, vector2P);

    const std::vector<double> ZERO = {0};
    const Plaintext ZERO_PLAINTEXT = cryptoContext->MakeCKKSPackedPlaintext(ZERO);
    Ciphertext<DCRTPoly> innerProductC = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
    for (size_t i = 0; i < vector2.size(); i++)
        innerProductC = cryptoContext->EvalAdd(innerProductC, cryptoContext->EvalRotate(v1v2C, i));

    if (masking) {
        const std::vector<double> ONE = {1};
        const Plaintext ONE_PLAINTEXT = cryptoContext->MakeCKKSPackedPlaintext(ONE);
        innerProductC = cryptoContext->EvalMult(innerProductC, ONE_PLAINTEXT);
    }

    return innerProductC;
}


/**
 * Compute the inner product between an encrypted vector and a plaintext vector.
 * The recursive vector sum-up is used.
 * @param cryptoContext the crypto context
 * @param vector1C first encrypted input vector
 * @param vector2 second (plaintext) input vector
 * @param masking whether you want the output ciphertext to contain only the
 * output value in the first position, and 0s in the other positions
 * @return encrypted inner product value
 */
Ciphertext<DCRTPoly> innerProductFastCP(
    CryptoContext<DCRTPoly> cryptoContext,
    Ciphertext<DCRTPoly> vector1C,
    std::vector<double> vector2,
    bool masking = false
)
{
    Plaintext vector2P  = cryptoContext->MakeCKKSPackedPlaintext(vector2);

    Ciphertext<DCRTPoly> v1v2C = cryptoContext->EvalMult(vector1C, vector2P);

    for (size_t i = 0; i < log2(vector2.size()); i++)
        v1v2C = cryptoContext->EvalAdd(v1v2C, cryptoContext->EvalRotate(v1v2C, 1 << i));

    if (masking) {
        const std::vector<double> ONE = {1};
        const Plaintext ONE_PLAINTEXT = cryptoContext->MakeCKKSPackedPlaintext(ONE);
        v1v2C = cryptoContext->EvalMult(v1v2C, ONE_PLAINTEXT);
    }

    return v1v2C;
}


/**
 * Compute the product between an encrypted vector and a plaintext matrix.
 * The naive algorithm with the naive inner product implementation is used.
 * The output is automatically masked.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param vectorC encrypted input vector
 * @param matrix (plaintext) input matrix
 * @return encrypted vector-matrix product
 */
Ciphertext<DCRTPoly> vectorMatrixMultByInnProdCP(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vectorC,
    std::vector<std::vector<double>> matrix
)
{
    const std::vector<double> ZERO = {0};
    const Plaintext ZERO_PLAINTEXT = cryptoContext->MakeCKKSPackedPlaintext(ZERO);
    Ciphertext<DCRTPoly> result = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
    std::vector<std::vector<double>> matrixT = transpose(matrix);
    Ciphertext<DCRTPoly> innProdC;
    for (size_t i = 0; i < matrixT.size(); i++) {
        innProdC = innerProductCP(cryptoContext, publicKey, vectorC, matrixT[i], true);
        innProdC = cryptoContext->EvalRotate(innProdC, -i);
        result = cryptoContext->EvalAdd(result, innProdC);
    }
    return result;
}


/**
 * Compute the product between an encrypted vector and a plaintext matrix.
 * The naive algorithm with the recursive-sum inner product implementation is
 * used.
 * The output is automatically masked.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param vectorC encrypted input vector
 * @param matrix (plaintext) input matrix
 * @return encrypted vector-matrix product
 */
Ciphertext<DCRTPoly> vectorMatrixMultByInnProdFastCP(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vectorC,
    std::vector<std::vector<double>> matrix
)
{
    const std::vector<double> ZERO = {0};
    const Plaintext ZERO_PLAINTEXT = cryptoContext->MakeCKKSPackedPlaintext(ZERO);
    Ciphertext<DCRTPoly> result = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
    std::vector<std::vector<double>> matrixT = transpose(matrix);
    Ciphertext<DCRTPoly> innProdC;
    for (size_t i = 0; i < matrixT.size(); i++) {
        innProdC = innerProductFastCP(cryptoContext, vectorC, matrixT[i], true);
        innProdC = cryptoContext->EvalRotate(innProdC, -i);
        result = cryptoContext->EvalAdd(result, innProdC);
    }
    return result;
}


Ciphertext<DCRTPoly> vectorMatrixMultPackCP(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vectorC,
    std::vector<std::vector<double>> matrix,
    bool packing,
    int numRowsPrevMatrix,
    bool masking,
    bool transposing
)
{
   // Store original matrix size.
    size_t ogNumRows = matrix.size();
    size_t ogNumCols = matrix[0].size();

   //  Pad and flatten the matrix.
    size_t numRows = nextPowerOf2(ogNumRows);
    size_t numCols = packing ? nextPowerOf2(ogNumCols) : nextPowerOf2(numRowsPrevMatrix);
    matrix = resizeMatrix(matrix, numRows, numCols);
    std::vector<double> matrixFlat = flattenMatrix(matrix, !packing);
    Plaintext matrixFlatP = cryptoContext->MakeCKKSPackedPlaintext(matrixFlat);

  //  Pad and repeat the vector.
    for (size_t i = 0; i < log2(ogNumCols); i++)
        vectorC = cryptoContext->EvalAdd(vectorC, cryptoContext->EvalRotate(vectorC, -((packing ? numRows : 1) << i)));
    
  //  Multiply and sum (the result is stored in the first row of the matrix).
    Ciphertext<DCRTPoly> prod = cryptoContext->EvalMult(vectorC, matrixFlatP);
    for (size_t i = 0; i < log2(numRows); i++)
        prod = cryptoContext->EvalAdd(prod, cryptoContext->EvalRotate(prod, (packing ? 1 : numCols) << i));

 //   Mask out the result.
    if (!(packing && transposing) && masking) {
        std::vector<double> mask;
        if (packing) {
            for (size_t i = 0; i < numCols; i++)
                for (size_t j = 0; j < numRows; j++)
                    if (j == 0 && i < ogNumCols)
                        mask.push_back(1);
                    else
                        mask.push_back(0);
        } else {
            mask.insert(mask.end(), ogNumCols, 1);
        }
        Plaintext maskP = cryptoContext->MakeCKKSPackedPlaintext(mask);
        prod = cryptoContext->EvalMult(prod, maskP);
    }


    if (packing && transposing) {
        const std::vector<double> ZERO = {0};
        const Plaintext ZERO_PLAINTEXT = cryptoContext->MakeCKKSPackedPlaintext(ZERO);
        Ciphertext<DCRTPoly> res = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
        std::vector<double> mask = {1};
        Plaintext maskP;
        for (size_t i = 0; i < ogNumCols; i++) {
            maskP = cryptoContext->MakeCKKSPackedPlaintext(mask);
            res = cryptoContext->EvalAdd(
                    res,
                    cryptoContext->EvalMult(
                        cryptoContext->EvalRotate(
                            prod,
                            i * (numRows - 1)),
                        maskP));
            mask.insert(mask.begin(), 0);
        }
        prod = res;
    }

    return prod;
}