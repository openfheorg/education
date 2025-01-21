
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>


LWECiphertext ANDGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(AND, a, b);
}
LWECiphertext NANDGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(NAND, a, b);
}
LWECiphertext ORGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(OR, a, b);
}
LWECiphertext NORGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(BINGATE::NOR, a, b);
}
LWECiphertext XORGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(XOR, a, b);
}
LWECiphertext NOTGATE(BinFHEContext cc, LWECiphertext  a) {
    return cc.EvalNOT(a);
}







int main(int argc, char *argv[]) {

     int64_t example=0;




    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> example;
	}







    auto cc = BinFHEContext();
    // We can use TOY, MEDIUM, STD192, and STD256.
    cc.GenerateBinFHEContext(TOY);

    auto sk = cc.KeyGen();

    std::cout << "Homomorphic four bit adder with carry out" << std::endl;
    std::cout << "Creating bootstrapping keys..." << std::endl;

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    std::cout << "Completed key generation." << std::endl;
    std::cout << "A B C | Z" << std::endl;
    std::cout << "------|--" << std::endl;


    for (int abit=0;abit<=1;abit++) {
        for (int bbit=0;bbit<=1;bbit++) { 
            for (int cbit=0;cbit<=1;cbit++) {

                auto a = cc.Encrypt(cc.GetPublicKey(), abit);
                auto b = cc.Encrypt(cc.GetPublicKey(), bbit);
                auto c = cc.Encrypt(cc.GetPublicKey(), cbit);

                LWECiphertext z;
                if (example==0) z=ORGATE(cc,ANDGATE(cc,a,b),c);
                else if (example==1) z=NOTGATE(cc,ORGATE(cc,ANDGATE(cc,a,b),c));
                else if (example==2) z=ANDGATE(cc,XORGATE(cc,a,b),c);
                else if (example==3) z=NORGATE(cc,NANDGATE(cc,a,b),c);
                else if (example==4) z=XORGATE(cc,ORGATE(cc,a,b),c);
                else if (example==5) z=NORGATE(cc,ANDGATE(cc,a,b),c);
                else if (example==6) z=NORGATE(cc,NANDGATE(cc,a,b),c);

                LWEPlaintext result;
                cc.Decrypt(sk, z, &result); 
                printf("%d %d %d | %d\n",abit,bbit,cbit,result); 
            }
        }
    }
    return 0;


}
