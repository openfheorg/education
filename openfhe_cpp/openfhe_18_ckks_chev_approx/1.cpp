
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>


int main(int argc, char *argv[]) {


    int maxval=10;
    int opt=1;


    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> maxval;
	}
    if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> opt;
	}



     std::cout << "Function evaluation" << std::endl;
    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);
    usint scalingModSize = 50;
    usint firstModSize   = 60;
    parameters.SetScalingModSize(scalingModSize);
    parameters.SetFirstModSize(firstModSize);


    uint32_t polyDegree = 50; 
   uint32_t multDepth = 7; // See table


    parameters.SetMultiplicativeDepth(multDepth);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE); // Needed for  Chebyshev approximation.

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey); // Multiple keys required for Chebyshev approximations


     std::vector<double> input; 

    for (int i=1;i<=maxval;i++) {
        input.push_back(i);
    }


    size_t encodedLength = maxval;
    Plaintext plaintext  = cc->MakeCKKSPackedPlaintext(input);
    auto ciphertext      = cc->Encrypt(keyPair.publicKey, plaintext);

    double lowerBound = 0; 
    double upperBound = maxval+1;

    //Using the lambda function of log10(x)
    Ciphertext<lbcrypto::DCRTPoly> result;
    
    if (opt==0) { 
        result = cc->EvalChebyshevFunction([](double x) -> double { return std::log10(x); }, ciphertext, lowerBound, upperBound, polyDegree);
        std::cout <<" x    log10(x)\n----------" << std::endl;
    }
   else if (opt==1) { 
    result = cc->EvalChebyshevFunction([](double x) -> double { return std::log2(x); }, ciphertext, lowerBound, upperBound, polyDegree);
     std::cout <<" x    log2(x)\n----------" << std::endl;
   }
   else if (opt==2) { 
    result = cc->EvalChebyshevFunction([](double x) -> double { return std::log(x); }, ciphertext, lowerBound, upperBound, polyDegree);
       std::cout <<" x    ln(x)\n----------" << std::endl;
   }
      else if (opt==3) { 
        result = cc->EvalChebyshevFunction([](double x) -> double { return std::exp(x); }, ciphertext, lowerBound, upperBound, polyDegree);
       std::cout <<" x    exp(x)\n----------" << std::endl;
   }
   else if (opt==4) { 
        result = cc->EvalChebyshevFunction([](double x) -> double { return std::exp2(x); }, ciphertext, lowerBound, upperBound, polyDegree);
       std::cout <<" x    2^x\n----------" << std::endl;
   }
      else if (opt==5) { 
        result = cc->EvalChebyshevFunction([](double x) -> double { return std::sqrt(x); }, ciphertext, lowerBound, upperBound, polyDegree);
       std::cout <<" x    sqrt(x)\n----------" << std::endl;
   }


    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
    plaintextDec->SetLength(maxval);


    std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();
    std::cout.precision(4);

    for (int i=1;i<=maxval;i++) 
        std::cout << i<<  "     " <<  std::real(finalResult[i-1]) << std::endl;


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

