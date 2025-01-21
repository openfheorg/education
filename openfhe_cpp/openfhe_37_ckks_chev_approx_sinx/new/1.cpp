
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>


int main(int argc, char *argv[]) {


    int maxval=360;
    int opt=0;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> maxval;
	}
    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> opt;
	}



     std::cout << "Logarithm evaluation" << std::endl;
    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);
    usint scalingModSize = 59;
    usint firstModSize   = 60;
    parameters.SetScalingModSize(scalingModSize);
    parameters.SetFirstModSize(firstModSize);


    uint32_t polyDegree = 100; 
   uint32_t multDepth = 10; // See table


    parameters.SetMultiplicativeDepth(multDepth);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE); // Needed for  Chebyshev approximation.

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey); // Multiple keys required for Chebyshev approximations


     std::vector<double> a; 
    a.push_back(1.1);

    std::vector<double> b; 
    b.push_back(-3.1);

    std::vector<double> c; 
    c.push_back(0.1);
    
    


    size_t encodedLength = maxval;
    Plaintext a_plaintext  = cc->MakeCKKSPackedPlaintext(a);
    auto a_ciphertext      = cc->Encrypt(keyPair.publicKey, a_plaintext);
    
    Plaintext b_plaintext  = cc->MakeCKKSPackedPlaintext(b);
    auto b_ciphertext      = cc->Encrypt(keyPair.publicKey, b_plaintext);
    
    Plaintext c_plaintext  = cc->MakeCKKSPackedPlaintext(c);
    auto c_ciphertext      = cc->Encrypt(keyPair.publicKey, c_plaintext);

    double lowerBound = 0; 
    double upperBound = 100;

    Ciphertext<lbcrypto::DCRTPoly> result;

    cout << "Here 1 " << std::endl;

    auto b_square = cc->EvalMult(b_ciphertext,b_ciphertext);

    auto two_a = cc->EvalMult(2,a_ciphertext);
    auto four_a = cc->EvalMult(4,a_ciphertext);
    auto four_a_c  = cc->EvalMult(four_a,c_ciphertext);

    auto res = cc->EvalSub(b_square,four_a_c);
    cout << "Here 2 " << std::endl;

    // x = (-b+sqrt(b*b-4ac))/2a

   //  result = cc->EvalChebyshevFunction([](double x) -> double { return std::sqrt(x); }, ciphertext, lowerBound, upperBound, polyDegree);

    auto sqrt_b_4_ac = cc->EvalChebyshevFunction([](double x) -> double { return std::sqrt(x); }, res, lowerBound, upperBound, polyDegree);
    
    cout << "Here 3 " << std::endl;

    auto minus_b = cc->EvalNegate(b_ciphertext);

        cout << "Here 4 " << std::endl;
    auto num  = cc->EvalAdd(minus_b,sqrt_b_4_ac);
        cout << "Here 5 " << std::endl;

    auto inv_two_a=cc->EvalDivide(two_a,-100,100,polyDegree);
        cout << "Here 6 " << std::endl;

    Plaintext plaintextDec1;
    cc->Decrypt(keyPair.secretKey, inv_two_a, &plaintextDec1);
 //   plaintextDec->SetLength(maxval);


    std::vector<std::complex<double>> finalResult1 = plaintextDec1->GetCKKSPackedValue();
    std::cout.precision(4);

    std::cout <<  "     " <<  finalResult1[0] << std::endl;



    auto y=cc->EvalMult(num,inv_two_a);

    cout << "Here 7 " << std::endl;

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, y, &plaintextDec);
 //   plaintextDec->SetLength(maxval);


    std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();
    std::cout.precision(4);

    std::cout <<  "     " <<  finalResult << std::endl;


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

