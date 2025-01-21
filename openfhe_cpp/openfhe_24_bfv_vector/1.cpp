

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
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vector1C,
    Ciphertext<DCRTPoly> vector2C,
    size_t vectorLength,
    bool masking = false
);


int main(int argc, char* argv[]) {

    
int len = 4;
int64_t max = 100;
int mod=65537;

    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> len;
	}
        if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> max;
	}
            if (argc>3) {
    	std::istringstream iss(argv[3]);
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
for (int i = -len; i <= len; i++) rotationKeys.push_back(i);


cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotationKeys);
std::cout << "Completed" << std::endl;

std::cout << std::endl;

 
std::vector<int64_t> v1 = genRandVect(len,max,0);
Plaintext v1Plaintext  = cryptoContext->MakePackedPlaintext(v1);

std::vector<int64_t> v2 = genRandVect(len,max,1);
Plaintext v2Plaintext  = cryptoContext->MakePackedPlaintext(v2);

std::cout << "Vector 1 = " << v1 << std::endl;
std::cout << "Vector 2 = " << v2 << std::endl;

Ciphertext<DCRTPoly> v1C = cryptoContext->Encrypt(keyPair.publicKey, v1Plaintext);
Ciphertext<DCRTPoly> v2C = cryptoContext->Encrypt(keyPair.publicKey, v2Plaintext);

Ciphertext<DCRTPoly> resultCipher;
Plaintext result;


// Compute normally
int64_t resOutput = innerProduct(v1, v2);
std::cout << "Inner product: v1*v2 = " << resOutput << std::endl;

 resultCipher = innerProductCC(cryptoContext, keyPair.publicKey, v1C, v2C, v1.size());

 cryptoContext->Decrypt(keyPair.secretKey, resultCipher, &result);
 result->SetLength(1);
 resOutput = result->GetPackedValue()[0];

 std::cout << "Inner product: v1 (Cipher)*v2 (Cipher) =  = " << resOutput << std::endl;
}