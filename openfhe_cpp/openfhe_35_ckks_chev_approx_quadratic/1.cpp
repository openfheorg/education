
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>


int main(int argc, char *argv[]) {


    double aval=1,bval=-2,cval=-3;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> aval;
	}
    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> bval;
	}
    if (argc>3) {
    	std::istringstream iss(argv[3]);
    	iss >> cval;
	}


    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);

    usint scalingModSize = 50;
    usint firstModSize   = 60;

    parameters.SetScalingModSize(scalingModSize);
    parameters.SetFirstModSize(firstModSize);

    uint32_t polyDegree = 50;
    uint32_t multDepth = 10;

    parameters.SetMultiplicativeDepth(multDepth);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

     std::vector<double> a;
    a.push_back(aval);

    std::vector<double> b;
    b.push_back(bval);

    std::vector<double> c;
    c.push_back(cval);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    ;
    size_t encodedLength = 1;

    Plaintext a_plaintext  = cc->MakeCKKSPackedPlaintext(a,1, 0, nullptr, 1);
    auto a_ciphertext      = cc->Encrypt(keyPair.publicKey, a_plaintext);
    Plaintext b_plaintext  = cc->MakeCKKSPackedPlaintext(b,1, 0, nullptr, 1);
    auto b_ciphertext      = cc->Encrypt(keyPair.publicKey, b_plaintext);
    Plaintext c_plaintext  = cc->MakeCKKSPackedPlaintext(c,1, 0, nullptr, 1);
    auto c_ciphertext      = cc->Encrypt(keyPair.publicKey, c_plaintext);

    double lowerBound = 1;
    double upperBound = 20;




    auto b_square = cc->EvalMult(b_ciphertext,b_ciphertext);

    auto two_a = cc->EvalMult(2,a_ciphertext);
    auto four_a = cc->EvalMult(4,a_ciphertext);
    auto four_a_c  = cc->EvalMult(four_a,c_ciphertext);

    auto res = cc->EvalSub(b_square,four_a_c);

    // x = (-b+sqrt(b*b-4ac))/2a
    auto sqrt_b_4_ac = cc->EvalChebyshevFunction([](double x) -> double { return std::sqrt(x); }, res, lowerBound, upperBound, polyDegree);


    auto minus_b = cc->EvalNegate(b_ciphertext);


    auto num1  = cc->EvalAdd(minus_b,sqrt_b_4_ac); // b+sqrt(b^2-4ac)
    auto num2  = cc->EvalSub(minus_b,sqrt_b_4_ac); // b-sqrt(b^2-4ac)


    auto inv_two_a=cc->EvalDivide(two_a, lowerBound, upperBound, polyDegree);


    auto root1_cipher=cc->EvalMult(num1,inv_two_a);
    auto root2_cipher=cc->EvalMult(num2,inv_two_a);

    Plaintext root1,root2;
    cc->Decrypt(keyPair.secretKey, root1_cipher, &root1);
    cc->Decrypt(keyPair.secretKey, root2_cipher, &root2);

    root1->SetLength(encodedLength);
    root2->SetLength(encodedLength);


    std::cout << "Homomorphic Quadractic Equation Solver"<< std::endl;
    std::cout << aval << "x^2 + (" << bval << ")x+(" << cval << ")"<< std::endl << std::endl;

    std::cout << "Root 1: " << root1->GetRealPackedValue() << std::endl;
    std::cout << "Root 2: " << root2->GetRealPackedValue() << std::endl;


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

