
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

int main(int argc, char *argv[]) {


int64_t A=0, B=0, C=0, D=0;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> D;
	}

    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >>C;
	}	
        if (argc>3) {
    	std::istringstream iss(argv[3]);
    	iss >>B;
	}	
        if (argc>4) {
    	std::istringstream iss(argv[4]);
    	iss >>A;
	}	

    auto cc = BinFHEContext();

    // We can use TOY, MEDIUM, STD192, and STD256.
    cc.GenerateBinFHEContext(TOY);

    auto sk = cc.KeyGen();

    std::cout << "Creating bootstrapping keys..." << std::endl;

    cc.BTKeyGen(sk);

    std::cout << "Completed key generation." << std::endl;

    auto Abit = cc.Encrypt(sk, A);
    auto Bbit = cc.Encrypt(sk, B);
    auto Cbit = cc.Encrypt(sk, C);
    auto Dbit = cc.Encrypt(sk, D);


    auto Zenc = Dbit;
    auto Yenc = cc.EvalBinGate(XOR, Dbit, Cbit);
    auto Xenc =cc.EvalBinGate(XOR, Cbit, Bbit);
    auto Wenc = cc.EvalBinGate(XOR, Bbit, Abit);

    LWEPlaintext W,X,Y,Z;

    cc.Decrypt(sk, Zenc, &Z);
    cc.Decrypt(sk, Yenc, &Y);
    cc.Decrypt(sk, Xenc, &X);
    cc.Decrypt(sk, Wenc, &W);


    printf("(%d %d %d %d Gray Code=%d %d %d %d\n",D,C,B,A,Z,Y,X,W);

    return 0;


}
