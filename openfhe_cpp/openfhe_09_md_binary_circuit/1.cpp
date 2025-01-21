
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

int main(int argc, char *argv[]) {


int64_t b1=0, b2=0;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> b1;
	}

    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >>b2;
	}	

    auto cc = BinFHEContext();

    // We can use TOY, MEDIUM, STD192, and STD256.
    cc.GenerateBinFHEContext(TOY);

    auto sk = cc.KeyGen();

    std::cout << "Creating bootstrapping keys..." << std::endl;

    cc.BTKeyGen(sk);

    std::cout << "Completed key generation." << std::endl;

    auto bit1 = cc.Encrypt(sk, b1);
    auto bit2 = cc.Encrypt(sk, b2);

    cout << bit1 << endl;

    auto ctAND1 = cc.EvalBinGate(AND, bit1, bit2);
    auto bit2Not = cc.EvalNOT(bit2);
    auto ctAND2 = cc.EvalBinGate(AND, bit2Not, bit1);
    auto ctResult = cc.EvalBinGate(OR, ctAND1, ctAND2);

    LWEPlaintext result;

    cc.Decrypt(sk, ctResult, &result);

    printf("b1=%d\n",b1);
    printf("b2=%d\n",b2);
    printf("(b1 AND b2) OR ( b1 AND NOT(b2))\n");
    printf("(%d AND %d) OR ( %d AND NOT(%d))=%d\n",b1,b2,b1,b2,result);

    return 0;


}
