
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iomanip>
#include <tuple>
#include <unistd.h>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"


#include <iostream>

int main(int argc, char *argv[]) {

    uint32_t multDepth = 1;
    uint32_t scaleModSize = 50;

    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >>scaleModSize;
	}

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    std::cout << "The key pair has been generated." << std::endl;

    auto str = Serial::SerializeToString(  keyPair.publicKey);

    cout << "Public Key (first 2,000 characters):\n" << str.substr(0,2000) << endl;

 /*  if (!Serial::SerializeToFile("./public_key_ckks.bin", keyPair.publicKey, SerType::BINARY)) {
        std::cerr << "Error serializing pk" << std::endl;
        return 1;
    }
   if (!Serial::SerializeToFile("./public_key_ckks.txt", keyPair.publicKey, SerType::JSON)) {
        std::cerr << "Error serializing pk" << std::endl;
        return 1;
    } */




 

    return(0);

  
}