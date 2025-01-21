
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

std::vector<std::vector<int64_t>> transpose(   std::vector<std::vector<int64_t>> matrix);
int64_t innerProduct( std::vector<int64_t> vector1, std::vector<int64_t> vector2);
size_t nextPowerOf2(   size_t n);
std::vector<std::vector<int64_t>> resizeMatrix(
    std::vector<std::vector<int64_t>> matrix,
    size_t numRows,
    size_t numCols
);
std::vector<int64_t> flattenMatrix(
    std::vector<std::vector<int64_t>> matrix,
    bool direction
);
std::vector<int64_t> flattenMatrix(
    std::vector<std::vector<int64_t>> matrix,
    bool direction
);

std::vector<int64_t> genRandVect(
    size_t length,
    int64_t maxValue
)
{
    std::srand(unsigned(std::time(nullptr)));
    auto myrand = [maxValue] () {
        return (std::rand() % (maxValue << 1)) - maxValue;
    };
    std::vector<int64_t> vector(length);
    std::generate(vector.begin(), vector.end(), myrand);
    return vector;
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

std::vector<int64_t> vectorMatrixMult(
    std::vector<int64_t> vector,
    std::vector<std::vector<int64_t>> matrix
)
{
    std::vector<std::vector<int64_t>> matrixT = transpose(matrix);
    std::vector<int64_t> result;
    for (size_t i = 0; i < matrixT.size(); i++) {
        int64_t innProd = innerProduct(vector, matrixT[i]);
        result.push_back(innProd);
    }
    return result;
}

int64_t innerProduct(
    std::vector<int64_t> vector1,
    std::vector<int64_t> vector2
)
{
    int64_t inner_product = 0;
    for (size_t i = 0; i < vector1.size(); i++)
        inner_product += vector1[i] * vector2[i];
    return inner_product;
}



std::vector<std::vector<int64_t>> transpose(   std::vector<std::vector<int64_t>> matrix)
{
    std::vector<std::vector<int64_t>> matrixT(
        matrix[0].size(),
        std::vector<int64_t>(matrix.size())
    );
    for (size_t i = 0; i < matrix[0].size(); i++) 
        for (size_t j = 0; j < matrix.size(); j++)
            matrixT[i][j] = matrix[j][i];
    return matrixT;
}

Ciphertext<DCRTPoly> vectorMatrixMultPackCP(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vectorC,
    std::vector<std::vector<int64_t>> matrix,
    bool packing,
    int numRowsPrevMatrix,
    bool masking,
    bool transposing
)
{
    // Store original matrix size.
    size_t ogNumRows = matrix.size();
    size_t ogNumCols = matrix[0].size();

    // Pad and flatten the matrix.
    size_t numRows = nextPowerOf2(ogNumRows);
    size_t numCols = packing ? nextPowerOf2(ogNumCols) : nextPowerOf2(numRowsPrevMatrix);
    matrix = resizeMatrix(matrix, numRows, numCols);
    std::vector<int64_t> matrixFlat = flattenMatrix(matrix, !packing);
    Plaintext matrixFlatP = cryptoContext->MakePackedPlaintext(matrixFlat);

    // Pad and repeat the vector.
    for (size_t i = 0; i < log2(ogNumCols); i++)
        vectorC = cryptoContext->EvalAdd(vectorC, cryptoContext->EvalRotate(vectorC, -((packing ? numRows : 1) << i)));
    
    // Multiply and sum (the result is stored in the first row of the matrix).
    Ciphertext<DCRTPoly> prod = cryptoContext->EvalMult(vectorC, matrixFlatP);
    for (size_t i = 0; i < log2(numRows); i++)
        prod = cryptoContext->EvalAdd(prod, cryptoContext->EvalRotate(prod, (packing ? 1 : numCols) << i));

    // Mask out the result.
    if (!(packing && transposing) && masking) {
        std::vector<int64_t> mask;
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
        Plaintext maskP = cryptoContext->MakePackedPlaintext(mask);
        prod = cryptoContext->EvalMult(prod, maskP);
    }

    // Transpose the result.
    // TODO: improve transposition (easy if rows >= cols)
    if (packing && transposing) {
        const std::vector<int64_t> ZERO = {0};
        const Plaintext ZERO_PLAINTEXT = cryptoContext->MakePackedPlaintext(ZERO);
        Ciphertext<DCRTPoly> res = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
        std::vector<int64_t> mask = {1};
        Plaintext maskP;
        for (size_t i = 0; i < ogNumCols; i++) {
            maskP = cryptoContext->MakePackedPlaintext(mask);
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


size_t nextPowerOf2(
    size_t n
)
{
    if (n == 0 || n == 1) return 1;
    else return 1 << ((int) std::log2(n - 1) + 1);
}


std::vector<std::vector<int64_t>> resizeMatrix(
    std::vector<std::vector<int64_t>> matrix,
    size_t numRows,
    size_t numCols
)
{
    for (auto &row : matrix) row.resize(numCols, 0);
    matrix.resize(numRows, std::vector<int64_t>(numCols, 0));
    return matrix;
}


std::vector<int64_t> flattenMatrix(
    std::vector<std::vector<int64_t>> matrix,
    bool direction
)
{
    std::vector<int64_t> res;
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

int main(int argc, char *argv[]) {


 //   string s1="10.12 20.2 30.5 40.3 45.4 50.3 55.9 70.4 11.3 12.34 19.65 20.11 25.31";


 //   if (argc>1) {
 //   	s1= (argv[1]);

//	}

    // std::vector<std::vector<int64_t>> trainX, testX;
    // std::vector<int64_t> trainY, testY;

    // loadMNIST(trainX, trainY, testX, testY);

    // for (size_t i = 0; i < trainX.size(); i++) {
    //     std::cout << i << " ";
    //     for (auto value : trainX[i])
    //         std::cout << value;
    //     std::cout << trainY[i] << std::endl;
    // }

    // for (size_t i = 0; i < testX.size(); i++) {
    //     std::cout << i << " ";
    //     for (auto value : testX[i])
    //         std::cout << value;
    //     std::cout << testY[i] << std::endl;
    // }

    TimeVar t;
    double processingTime(0.0);
 
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(4);
    parameters.SetMaxRelinSkDeg(3);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    PlaintextModulus p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    int n = cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
    double q = cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble();
    std::cout << "Plaintext modulus (p) = " << p << std::endl;
    std::cout << "Polynomial degree (n) = " << n << std::endl;
    std::cout << "Ciphertext modulus bitsize (log2 q) = " << log2(q) << std::endl;

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    if (!keyPair.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    std::cout << "Generating rotation keys... ";
    std::vector<int32_t> indexList = {};
    // for (int i = -100; i <= 100; i++) indexList.push_back(i);
    for (int i = 0; i <= 20; i++) {
        indexList.push_back(1 << i);
        indexList.push_back(-(1 << i));
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList);
    std::cout << "DONE" << std::endl;

    std::cout << std::endl;

    //////////////////////////////////////////////////////////
    // Vector * matrix1 * matrix2
    ////////////////////////////////////////////////////////////

    // If you increase the matrix sizes, then remember to also generate more
    // rotations keys accordingly.
    const size_t n1 = 5;
    const size_t n2 = 3;
    const size_t n3 = 4;
    const int64_t MAX_VALUE = 10;
    
    std::vector<int64_t> vector = genRandVect(n1, MAX_VALUE);
    Plaintext vectorP  = cryptoContext->MakePackedPlaintext(vector);

    std::vector<std::vector<int64_t>> matrix1 = genRandMatrix(n1, n2, MAX_VALUE);

    
    std::cout << "vector  = " << vector << std::endl;
    std::cout << "matrix1 = " << matrix1 << std::endl;


    Ciphertext<DCRTPoly> vectorC = cryptoContext->Encrypt(keyPair.publicKey, vectorP);

    Ciphertext<DCRTPoly> resC;
    Plaintext res;
    std::vector<int64_t> resInt64, resInt64tmp;

    TIC(t);
    resInt64 = vectorMatrixMult(vector, matrix1);

    processingTime = TOC(t);
    std::cout << "vector  * matrix1 * matrix2                         = "
              << resInt64 << " (" << processingTime << " ms)" << std::endl;
    
    TIC(t);
    resC = vectorMatrixMultPackCP(cryptoContext, keyPair.publicKey, vectorC, matrix1, true, -1, true, false);

    processingTime = TOC(t);
    cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
    res->SetLength(n3);
    resInt64 = res->GetPackedValue();
    std::cout << "vectorC * matrix1 * matrix2 (by alternate packing)  = "
              << resInt64 << " (" << processingTime << " ms)" << std::endl;

    return 0;

}