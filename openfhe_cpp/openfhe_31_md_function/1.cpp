

#include "openfhe.h"

using namespace lbcrypto;

#include <iomanip>
#include <iostream>


int main(int argc, char* argv[]) {


    int i=10;
    int modulusbits=12;
      int plaintextbits= 5;

    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> modulusbits;
	}


    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, true, modulusbits,0,BINFHE_METHOD::GINX);

    auto sk = cc.KeyGen();

    int Q=1<<modulusbits;
    std::cout << "Cipher modulus: " << Q << std::endl;

    std::cout << "Generating the bootstrapping keys..."; 

    // Bootstrapping keys (refresh and switching )
    cc.BTKeyGen(sk);

    std::cout << " Done" << std::endl;

   int p = cc.GetMaxPlaintextSpace().ConvertToInt()*2;  // Maximum plaintext space

    // Initialize Function f(x) = 2.x^2+x+1 % p
    auto fp = [](NativeInteger x, NativeInteger p1) -> NativeInteger {

        
            return ((2*x*x+x+1) % p1);
    };


    auto lut = cc.GenerateLUTviaFunction(fp, p);
    std::cout << "p=" << p << std::endl;
    std::cout << "Evaluate 2x^2+x+1 mod (" << p << ")" << std::endl;
      std::cout << std::setw(7) <<  "x" << std::setw(7) << "Eval" << std::setw(7) << "Result" << std::endl;


    for (int i = 0; i < p; i++) {
        auto ct1 = cc.Encrypt(sk, i % p, FRESH, p);
        auto ct_cube = cc.EvalFunc(ct1, lut);

        LWEPlaintext result;

        cc.Decrypt(sk, ct_cube, &result, p);

        std::cout << std::setw(7) <<  i << std::setw(7) << fp(i, p) << std::setw(7) << result << std::endl;

    }

    return 0;
}