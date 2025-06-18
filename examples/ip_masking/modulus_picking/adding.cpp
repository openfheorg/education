#include <openfhe.h>
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;
 
using namespace lbcrypto;

#include <sstream>




int main(int argc, char* argv[]) {
 

  uint64_t mod=2122221719;


    CCParams<CryptoContextBFVRNS> parameters;

    parameters.SetPlaintextModulus(mod);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetSecurityLevel(HEStd_128_classic);
   parameters.SetRingDim(16384/2);

 
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(LEVELEDSHE);

 
    KeyPair<DCRTPoly> keyPair;
 

    keyPair = cryptoContext->KeyGen();
 
    uint64_t x=5;
    uint64_t y=31;

    std::vector<int64_t>xval = {1};
	xval[0]=x;
    Plaintext xplaintext               = cryptoContext->MakePackedPlaintext(xval);

    std::vector<int64_t> yval = {1};
	yval[0]=y;
    Plaintext yplaintext               = cryptoContext->MakePackedPlaintext(yval);

    // Encrypt values
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, xplaintext);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, yplaintext);

    // Add ciphertext
    auto ciphertextMult     = cryptoContext->EvalAdd(ciphertext1, ciphertext2);

    // Decrypt result 
    Plaintext plaintextAddRes;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextAddRes);

    std::cout << "Modulus: : " << mod<< std::endl;

    std::cout << "\nx: " << xplaintext << std::endl;
    std::cout << "y: " << yplaintext << std::endl;


    // Output results
    std::cout << "\nResults" << std::endl;
    std::cout << "x+y= " << plaintextAddRes << std::endl;
 
    return 0;
}
