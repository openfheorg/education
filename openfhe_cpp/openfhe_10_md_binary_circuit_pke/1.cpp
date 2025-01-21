
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

int main(int argc, char *argv[]) {


int64_t a_0=0, a_1=0, b_0=0, b_1=0;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> a_0;
	}

    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >>a_1;
	}

    if (argc>3) {
    	std::istringstream iss(argv[3]);
    	iss >>b_0;
	}

    if (argc>4) {
    	std::istringstream iss(argv[4]);
    	iss >>b_1;
	}	




    auto cc = BinFHEContext();
    // We can use TOY, MEDIUM, STD192, and STD256.
    cc.GenerateBinFHEContext(TOY);

    // LARGE_DIM specifies the dimension of the output ciphertext

    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys... public keys" << std::endl;

    // Generate the bootstrapping keys (refresh, switching and public keys)
    cc.BTKeyGen(sk, PUB_ENCRYPT);




    auto a0 = cc.Encrypt(cc.GetPublicKey(), a_0);
    auto a1 = cc.Encrypt(cc.GetPublicKey(), a_1);

    auto b0 = cc.Encrypt(cc.GetPublicKey(), b_0);
    auto b1 = cc.Encrypt(cc.GetPublicKey(), b_1);



// Z = NOT(a1). b1 + NOT(a1).NOT(a0).b0 + NOT(a0).b1.b0


    auto not_a1 = cc.EvalNOT(a1);
    auto not_a0 = cc.EvalNOT(a0);
    auto not_a1_b1 = cc.EvalBinGate(AND, not_a1, b1);

    auto not_a1_a0 = cc.EvalBinGate(AND, not_a1, not_a0);
    auto not_a1_a0_b0 = cc.EvalBinGate(AND, not_a1_a0, b0);

    auto not_a0_b1 = cc.EvalBinGate(AND, not_a0, b1);
    auto not_a0_b1_b0 = cc.EvalBinGate(AND, not_a0_b1, b0);

    auto not_a1_a0_b0_or_not_a0_b1_b0 = cc.EvalBinGate(OR,  not_a1_b1, not_a1_a0_b0);
    auto ctResult = cc.EvalBinGate(OR, not_a1_a0_b0_or_not_a0_b1_b0, not_a0_b1_b0);


    LWEPlaintext result;

    cc.Decrypt(sk, ctResult, &result);


    printf("a0=%d a1=%d b0=%d b1=%d Result: %d\n",a_0,a_1,b_0,b_1,result);

    if (result==1) cout << "Bob is older than Alice" << endl;
    else cout << "Bob is not older than Alice" << endl;

    return 0;


}
