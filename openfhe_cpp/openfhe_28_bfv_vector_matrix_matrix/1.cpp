

#include "openfhe.h"

using namespace lbcrypto;

#include <iostream>
int64_t innerProduct(
    std::vector<int64_t> vector1,
    std::vector<int64_t> vector2
);
std::vector<int64_t> genRandVect(
    size_t length,
    int64_t maxValue, int64_t seconds
);

Ciphertext<DCRTPoly> innerProductCC(
    CryptoContext <DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vector1C,
    Ciphertext<DCRTPoly> vector2C,
    size_t vectorLength,
    bool masking = false
);

Ciphertext<DCRTPoly> vectorMatrixMultByInnProdFastCP(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vectorC,
    std::vector<std::vector<int64_t>> matrix
);

std::vector<std::vector<int64_t>> genRandMatrix(
    size_t rows,
    size_t cols,
    int64_t maxValue, int64_t seconds
);

std::vector<int64_t> vectorMatrixMult(
    std::vector<int64_t> vector,
    std::vector<std::vector<int64_t>> matrix
);

Ciphertext<DCRTPoly> vectorMatrixMultByInnProdCP(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vectorC,
    std::vector<std::vector<int64_t>> matrix
);




int main(int argc, char* argv[]) {

    
int64_t max = 10;
int mod=65537;
      size_t n1 = 3;
      size_t n2 = 3;
     size_t n3 = 3;



    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> n1;
	}
    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> n2;
	}
    if (argc>3) {
    	std::istringstream iss(argv[3]);
    	iss >> n3;
	}
    if (argc>4) {
    	std::istringstream iss(argv[4]);
    	iss >> max;
	}
    if (argc>5) {
    	std::istringstream iss(argv[5]);
    	iss >> mod;
	}

 
CCParams<CryptoContextBFVRNS> parameters;
parameters.SetPlaintextModulus(mod);
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


cryptoContext->EvalMultKeysGen(keyPair.secretKey);


std::cout << "Generating rotation keys... ";
std::vector<int32_t> rotationKeys = {};
for (int i = -5; i <= 5; i++) rotationKeys.push_back(i);
cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotationKeys);

std::cout << "Done"<< std::endl << std::endl;


std::vector<int64_t> vector = genRandVect(n1, max,1);
Plaintext vectorP  = cryptoContext->MakePackedPlaintext(vector);

auto matrix1 = genRandMatrix(n1, n2, max,2);
auto matrix2 = genRandMatrix(n2, n3, max,3);
    
std::cout << "Vector (V1) = " << vector << std::endl;
std::cout << "Matrix (M1) = " << matrix1 << std::endl;
std::cout << "Matrix (M2) = " << matrix2 << std::endl;

Ciphertext<DCRTPoly> vectorC = cryptoContext->Encrypt(keyPair.publicKey, vectorP);

Ciphertext<DCRTPoly> resC;
Plaintext res;
std::vector<int64_t> resOutput, resOutputtmp;


 resOutput = vectorMatrixMult(vector, matrix1);
resOutput = vectorMatrixMult(resOutput, matrix2);

std::cout << "V1*M1*M2 (non homomorphic)  = " << resOutput << std::endl;

//resC = vectorMatrixMultByInnProdCP(cryptoContext, keyPair.publicKey, vectorC, matrix1);
//resC = vectorMatrixMultByInnProdCP(cryptoContext, keyPair.publicKey, resC, matrix2);
resC = vectorMatrixMultByInnProdFastCP(cryptoContext, keyPair.publicKey, vectorC, matrix1);
 resC = vectorMatrixMultByInnProdFastCP(cryptoContext, keyPair.publicKey, resC, matrix2);

cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
res->SetLength(n3);
resOutput = res->GetPackedValue();
std::cout << "V1*M1*M3 (by inner product)      = " << resOutput  << std::endl;
    



}