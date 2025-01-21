
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

int main(int argc, char *argv[]) {


string type="BFV";
uint64_t mod = 65537;
int count=10;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> count;
	}

    if (argc>2) {
    	type=argv[2];
	}
    if (argc>3) {
    	std::istringstream iss(argv[3]);
    	iss >> mod;
	}	


    CCParams<CryptoContextBFVRNS> parameters;

    if (type=="BGV") CCParams<CryptoContextBGVRNS> parameters; 
    
    

    parameters.SetPlaintextModulus(mod);
    parameters.SetMultiplicativeDepth(2);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);


    KeyPair<DCRTPoly> keyPair;

    // Generate key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> xval(count, 0ULL);

    for (int i=0;i<count;i++) xval[i]=i;

    Plaintext xplaintext   = cryptoContext->MakePackedPlaintext(xval);

    // Encrypt values
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, xplaintext);

    // Square
    auto ciphertextMult     = cryptoContext->EvalSquare(ciphertext1);

    // Decrypt result 
    Plaintext plaintextAddRes;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextAddRes);

    std::cout << "Method: : " << type << std::endl;
    std::cout << "Parameters " << parameters << std::endl << std::endl;
    std::cout << "Ring dimension: " << cryptoContext->GetRingDimension() << "\n";
    std::cout << "Modulus: : " << mod<< std::endl;

    std::cout << "\nx: " << xplaintext << std::endl;


    // Output results
    std::cout << "\nResults" << std::endl;
    std::cout << "x^2= " << plaintextAddRes << std::endl;



    return 0;
}