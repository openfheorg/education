

#include "openfhe.h"

using namespace lbcrypto;

#include <iostream>


int main(int argc, char* argv[]) {


    int i=10;
    int modulusbits=17;
      int plaintextbits= 10;

    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> modulusbits;
	}
    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> plaintextbits;
	}

    auto cc = BinFHEContext();


    cc.GenerateBinFHEContext(TOY, false, modulusbits, 0, GINX, false);
    // cc.GenerateBinFHEContext(TOY, false, modulusbits, 0, AP, false); for 


    uint32_t Q = 1 << modulusbits;
    uint32_t P      = 1<< plaintextbits;  // Maximum plaintext space

    auto sk = cc.KeyGen();

    std::cout << "Bootstrapping keys generation..." << std::endl;

    // Generate the bootstrapping keys 
    cc.BTKeyGen(sk);

    std::cout << " ... Done." << std::endl;

    std::cout << "Q= " << Q << std::endl;

    std::cout << "P= " << P << std::endl;
    std::cout << "Maximum plaintext space=" << cc.GetMaxPlaintextSpace().ConvertToInt()<< std::endl;


    for (int j=-5;j<=5;j++) {
        auto ct1 = cc.Encrypt(sk, j , FRESH, P, Q);

        auto resct = cc.EvalSign(ct1);

        LWEPlaintext result;
        cc.Decrypt(sk, resct, &result, 2);
        std::cout <<"Value: " << j << " Sign: " << result << std::endl;

    }
    

    return 0;



}