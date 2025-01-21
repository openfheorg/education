
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

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



    auto str1 = Serial::SerializeToString(ciphertext1 );
    cout << "Ciphertext1 (first 2,000 characters):\n" << str1.substr(0,2000) << endl;
    auto str2 = Serial::SerializeToString(ciphertext2 );
    cout << "Ciphertext2 (first 2,000 characters):\n" << str2.substr(0,2000) << endl;


 /*  if (!Serial::SerializeToFile("./ciphertext_bfv.bin", ciphertext1, SerType::BINARY)) {
        std::cerr << "Error serializing pk" << std::endl;
        return 1;
    }
   if (!Serial::SerializeToFile("./ciphertext_bfv.txt", ciphertext1, SerType::JSON)) {
        std::cerr << "Error serializing pk" << std::endl;
        return 1;
    }  */


    return 0;
}