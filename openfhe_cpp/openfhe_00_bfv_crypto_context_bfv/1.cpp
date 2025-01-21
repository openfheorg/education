
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

int64_t x=0;
int64_t y=0;
string type="BFV";
uint64_t mod = 65537;



    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> mod;
	}

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(mod);
    parameters.SetMultiplicativeDepth(2);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);


    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    std::cout << "The key pair has been generated." << std::endl;

    auto str = Serial::SerializeToString(  cryptoContext);

    cout << "Crypto Context (First 2,000 characters):\n" << str.substr(0,2000) << endl;

/*   if (!Serial::SerializeToFile("./cryptocontext.bin", cryptoContext, SerType::BINARY)) {
        std::cerr << "Error serializing pk" << std::endl;
        return 1;
    }
   if (!Serial::SerializeToFile("./cryptoContext.txt", cryptoContext, SerType::JSON)) {
        std::cerr << "Error serializing pk" << std::endl;
        return 1;
    }  */




 

    return(0);

  
}