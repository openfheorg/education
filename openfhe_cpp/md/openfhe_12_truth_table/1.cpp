
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>
#include  <bitset>
#include <array>

LWECiphertext ANDGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(AND, a, b);
}
LWECiphertext NANDGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(NAND, a, b);
}
LWECiphertext ORGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(OR, a, b);
}
LWECiphertext XORGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(XOR, a, b);
}
LWECiphertext NOTGATE(BinFHEContext cc, LWECiphertext  a) {
    return cc.EvalNOT(a);
}







int main(int argc, char *argv[]) {

     int64_t val1=5;
     int64_t val2=3;



    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> val1;
	}
        if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> val2;
	}







    auto cc = BinFHEContext();
    // We can use TOY, MEDIUM, STD192, and STD256.
    cc.GenerateBinFHEContext(TOY);

    auto sk = cc.KeyGen();

    std::cout << "Homomorphic four bit adder with carry out" << std::endl;
    std::cout << "Creating bootstrapping keys..." << std::endl;

    cc.BTKeyGen(sk);

    std::cout << "Completed key generation." << std::endl;
    std::cout << "A B C Z" << std::endl;
    std::cout << "-------" << std::endl;


    for (int abit=0;abit<=1;abit++) {
        for (int bbit=0;bbit<=1;bbit++) { 
            for (int cbit=0;bitc<=1;cbit++) {

                auto a = cc.Encrypt(sk, abit);
                auto b = cc.Encrypt(sk, bbit);
                auto c = cc.Encrypt(sk, cbit);
                z=ORGATE(ANDGATE(a,b),a);
                LWEPlaintext result;
                cc.Decrypt(sk, z, &result);
                printf("%d %d %d %d\n",abit,bbit,cbit,result); 
            }
        }
    }
    return 0;


}
