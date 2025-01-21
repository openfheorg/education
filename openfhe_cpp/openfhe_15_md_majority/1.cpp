
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

int main(int argc, char *argv[]) {


int64_t abit=0, bbit=0, cbit=0;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> abit;
	}

    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >>bbit;
	}

    if (argc>3) {
    	std::istringstream iss(argv[3]);
    	iss >>cbit;
	}


    auto cc = BinFHEContext();

    // We can use TOY, MEDIUM, STD192, and STD256.
    cc.GenerateBinFHEContext(TOY);

    auto sk = cc.KeyGen();

    std::cout << "Creating bootstrapping keys..." << std::endl;

    cc.BTKeyGen(sk);

    std::cout << "Completed key generation." << std::endl;

    auto a = cc.Encrypt(sk, abit);
    auto b = cc.Encrypt(sk, bbit);
    auto c = cc.Encrypt(sk, cbit);

    std::vector<LWECiphertext> bits;
    bits.push_back(a);
    bits.push_back(b);
    bits.push_back(c);

    auto ctMaj = cc.EvalBinGate(MAJORITY, bits);
    auto cMux = cc.EvalBinGate(CMUX, bits);

    LWEPlaintext resultMaj,resultMux;

    cc.Decrypt(sk, ctMaj, &resultMaj);
    cc.Decrypt(sk, cMux, &resultMux);

    cout << "\na= " << abit << ", b= " << bbit << ", c= " << cbit << endl;
    cout << "\nMajority: " << resultMaj << endl;
    cout << "MUX: " << resultMux << endl;


    return 0;


}
