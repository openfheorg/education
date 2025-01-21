
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

int main(int argc, char *argv[]) {

int64_t x=0;
int64_t y=0;
string type="BFV";
uint64_t mod = 65537;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> x;
	}
        if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> y;
	}
    if (argc>3) {
    	type=argv[3];
	}
    if (argc>4) {
    	std::istringstream iss(argv[4]);
    	iss >> mod;
	}	


    CCParams<CryptoContextBFVRNS> parameters;

    if (type=="BGV") CCParams<CryptoContextBFVRNS> parameters;

    parameters.SetPlaintextModulus(mod);
    parameters.SetMultiplicativeDepth(2);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);


    KeyPair<DCRTPoly> keyPair;

    // Generate key pair
    keyPair = cryptoContext->KeyGen();


    std::vector<int64_t>xval = {1};
	xval[0]=x;
    Plaintext xplaintext               = cryptoContext->MakePackedPlaintext(xval);

    std::vector<int64_t> yval = {1};
	yval[0]=y;
    Plaintext yplaintext               = cryptoContext->MakePackedPlaintext(yval);

    // Encrypt values
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, xplaintext);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, yplaintext);

    // Multiply ciphertext
    auto ciphertextMult     = cryptoContext->EvalMult(ciphertext1, ciphertext2);
 
    // Decrypt result
    Plaintext plaintextMultRes;
    cryptoContext->Decrypt(keyPair.secretKey,ciphertextMult , &plaintextMultRes);

    std::cout << "Method: : " << type << std::endl;
    std::cout << "Modulus: : " << mod<< std::endl;

    std::cout << "\nx: " << xplaintext << std::endl;
    std::cout << "y: " << yplaintext << std::endl;


    // Output results
    std::cout << "\nResults" << std::endl;
    std::cout << "x*y= " << plaintextMultRes << std::endl;


    return 0;
}