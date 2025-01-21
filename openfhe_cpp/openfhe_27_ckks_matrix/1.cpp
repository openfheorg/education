

#include "openfhe.h"

using namespace lbcrypto;

#include <iostream>

std::vector<double> genRandVect(
    size_t length,
    int64_t maxValue, int64_t seconds
);
std::vector<std::vector<double>> genRandMatrix(
    size_t rows,
    size_t cols,
    int64_t maxValue, int seconds
);

std::vector<double> vectorMatrixMult(
    std::vector<double> vector,
    std::vector<std::vector<double>> matrix
);



Ciphertext<DCRTPoly> vectorMatrixMultByInnProdCP(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vectorC,
    std::vector<std::vector<double>> matrix
);



int main(int argc, char* argv[]) {

    
int64_t max = 100;
int mod=40;
int ROWS=3;
int COLS=3;

    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> ROWS;
	}
    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> COLS;
	}
    if (argc>3) {
    	std::istringstream iss(argv[3]);
    	iss >> max;
	}
    if (argc>4) {
    	std::istringstream iss(argv[4]);
    	iss >> mod;
	}

 
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(mod);

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
for (int i = -ROWS*COLS; i <= ROWS*COLS; i++) rotationKeys.push_back(i);
cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotationKeys);
std::cout << "Done"<< std::endl << std::endl;

std::vector<double> vector = genRandVect(ROWS, max,0);
Plaintext vectorP  = cryptoContext->MakeCKKSPackedPlaintext(vector);

std::vector<std::vector<double>> matrix = genRandMatrix(ROWS, COLS, max,1);
    
std::cout << "Vector (V1) = " << vector << std::endl;
std::cout << "Matrix (M1) = " << matrix << std::endl;

Ciphertext<DCRTPoly> vectorC = cryptoContext->Encrypt(keyPair.publicKey, vectorP);

Ciphertext<DCRTPoly> resC;
Plaintext res;
std::vector<double> resOutput, resOutputtmp;

resOutput = vectorMatrixMult(vector, matrix);

std::cout << "V1*M1  = " << resOutput << std::endl;

resC = vectorMatrixMultByInnProdCP(cryptoContext, keyPair.publicKey, vectorC, matrix);

cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
res->SetLength(COLS);

std::cout << "vectorC * matrix (by inner product)      = " << res->GetCKKSPackedValue()  << std::endl;
    



}