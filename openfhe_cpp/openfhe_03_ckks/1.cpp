
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

int main(int argc, char *argv[]) {

    uint32_t multDepth = 1;
    uint32_t scaleModSize = 50;
    uint32_t batchSize=1;

    double x=1.1;
    double y=2.2;
 
    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> x;
	}
        if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >>y;
	}

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);


    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    std::cout << "CKKS scheme. Ring dimension: " << cc->GetRingDimension() << std::endl << std::endl;
   
    auto keys = cc->KeyGen();

    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<double> x1 = {x};
    std::vector<double> y1 = {y};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(y1);

    std::cout << "Input x1: " << ptxt1 << std::endl;
    std::cout << "Input y1: " << ptxt2 << std::endl;

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    //  Addition
    auto cAdd = cc->EvalAdd(c1, c2);
    //  Subtraction
    auto cSub = cc->EvalSub(c1, c2);
    // Multiplication
    auto cMul = cc->EvalMult(c1, c2);

    Plaintext result;
    std::cout.precision(8);
    std::cout << std::endl << "Results: " << std::endl;
    cc->Decrypt(keys.secretKey, cAdd, &result);
    result->SetLength(batchSize);
    std::cout << "x+y=" << result << std::endl;


    cc->Decrypt(keys.secretKey, cSub, &result);
    result->SetLength(batchSize);
    std::cout << "x-y=" <<  result << std::endl;


    cc->Decrypt(keys.secretKey, cMul, &result);
    result->SetLength(batchSize);
    std::cout << "x*y=" << result  << std::endl;
 

    return 0;
}