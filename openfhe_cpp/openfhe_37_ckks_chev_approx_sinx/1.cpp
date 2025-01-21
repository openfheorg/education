
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>


int main(int argc, char *argv[]) {


    double range=8, step=0.25;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> range;
	}
    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> step;
	}



    std::cout << "Homomorphic Sin(x)/x"<< std::endl;
    std::cout <<"Range=" << range << std::endl;

  

    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);

    usint scalingModSize = 50;
    usint firstModSize   = 60;

    parameters.SetScalingModSize(scalingModSize);
    parameters.SetFirstModSize(firstModSize);

    uint32_t polyDegree = 50;
    uint32_t multDepth = 11;

    parameters.SetMultiplicativeDepth(multDepth);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    double xval=0;
     std::vector<double> x;
     for (float i=0;i<range;i++) {
        x.push_back(xval);
        xval+=step;
     }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    ;


    Plaintext x_plaintext  = cc->MakeCKKSPackedPlaintext(x,1, 0, nullptr, range);
    auto x_ciphertext      = cc->Encrypt(keyPair.publicKey, x_plaintext);


    double lowerBound = 1;
    double upperBound = 20;


    auto sinx=cc->EvalSin(x_ciphertext, lowerBound, upperBound, polyDegree);
    auto inv_x=cc->EvalDivide(x_ciphertext, lowerBound, upperBound, polyDegree);
    auto y_cipher=cc->EvalMult(sinx,inv_x);


    Plaintext y;
    cc->Decrypt(keyPair.secretKey, y_cipher, &y);


    y->SetLength(range);
    cout.precision(4);
    std::cout << "x   Homomorphic  Actual" << std::endl;

    for (int i=0;i<range;i++)
        std::cout << x[i] << "\t" << y->GetRealPackedValue()[i] << "\t" << std::sin(x[i])/x[i] << std::endl;



}

/* For EvalChebyshevFunction we required a number multiplications and which are dependent on input polynomial degree. For this we use the following table:
3-5 	4
6-13 	5
14-27 	6
28-59 	7
60-119 	8
120-247 	9
248-495 	10
496-1007 	11
1008-2031 	12 */

