
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>


int main(int argc, char *argv[]) {

    uint64_t q_mod=30;
    uint64_t mod = py;

    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> q_mod;
	}

     CCParams<CryptoContextBFVRNS> parameters;

    parameters.SetPlaintextModulus(mod);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetRingDim(8192);
    parameters.SetScalingModSize(q_mod); // Prime near 2^{q_mod}
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);

    KeyPair<DCRTPoly> keyPair;

    // Generate key pair
    keyPair = cryptoContext->KeyGen();

    DCRTPoly skElement = keyPair.secretKey->GetPrivateElement();
  	std::cout << "Secret Key Polynomial in EVAL Modulus: " << skElement << std::endl;

  	skElement.SetFormat(Format::COEFFICIENT);
  	std::cout << "Secret Key Polynomial in COEFF Modulus: " << skElement<< std::endl;



}
