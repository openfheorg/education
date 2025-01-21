
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>


int main(int argc, char *argv[]) {


    double aval=5,bval=4,cval=6,dval=4,eval=3,fval=8;


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
        if (argc>4) {
    	std::istringstream iss(argv[4]);
    	iss >> dval;
	}
    if (argc>5) {
    	std::istringstream iss(argv[5]);
    	iss >> eval;
	}
    if (argc>6) {
    	std::istringstream iss(argv[6]);
    	iss >> fval;
	}

    std::cout << "Homomorphic Linear Equation Solver"<< std::endl;
    std::cout << aval << "x + " << bval << "y=" << cval << std::endl;
    std::cout << dval << "x + " << eval << "y=" << fval << std::endl;
  

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

     std::vector<double> a;a.push_back(aval);
    std::vector<double> b;b.push_back(bval);
    std::vector<double> c;c.push_back(cval);
    std::vector<double> d;d.push_back(dval);
    std::vector<double> e;e.push_back(eval);
    std::vector<double> f;f.push_back(fval);
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    ;
    size_t encodedLength = 1;

    Plaintext a_plaintext  = cc->MakeCKKSPackedPlaintext(a,1, 0, nullptr, 1);
    auto a_ciphertext      = cc->Encrypt(keyPair.publicKey, a_plaintext);
    Plaintext b_plaintext  = cc->MakeCKKSPackedPlaintext(b,1, 0, nullptr, 1);
    auto b_ciphertext      = cc->Encrypt(keyPair.publicKey, b_plaintext);
    Plaintext c_plaintext  = cc->MakeCKKSPackedPlaintext(c,1, 0, nullptr, 1);
    auto c_ciphertext      = cc->Encrypt(keyPair.publicKey, c_plaintext);
    Plaintext d_plaintext  = cc->MakeCKKSPackedPlaintext(d,1, 0, nullptr, 1);
    auto d_ciphertext      = cc->Encrypt(keyPair.publicKey, d_plaintext);
    Plaintext e_plaintext  = cc->MakeCKKSPackedPlaintext(e,1, 0, nullptr, 1);
    auto e_ciphertext      = cc->Encrypt(keyPair.publicKey, e_plaintext);
    Plaintext f_plaintext  = cc->MakeCKKSPackedPlaintext(f,1, 0, nullptr, 1);
    auto f_ciphertext      = cc->Encrypt(keyPair.publicKey, f_plaintext);

    double lowerBound = 1;
    double upperBound = 20;




    auto cd = cc->EvalMult(c_ciphertext,d_ciphertext);
    auto fa = cc->EvalMult(f_ciphertext,a_ciphertext);
    auto bd = cc->EvalMult(b_ciphertext,d_ciphertext);
    auto ea = cc->EvalMult(e_ciphertext,a_ciphertext);
    auto y_cipher_num = cc->EvalSub(cd,fa);
    auto y_cipher_dem = cc->EvalSub(bd,ea);
    auto y_cipher_dem_inv = cc->EvalDivide(y_cipher_dem,lowerBound, upperBound, polyDegree);
    auto y_cipher=cc->EvalMult(y_cipher_num,y_cipher_dem_inv);


    auto by = cc->EvalMult(b_ciphertext,y_cipher);
    auto x_cipher_num = cc->EvalSub(c_ciphertext,by);
    auto a_inv = cc->EvalDivide(a_ciphertext,lowerBound, upperBound, polyDegree);
    auto x_cipher=cc->EvalMult(x_cipher_num,a_inv);

    Plaintext x,y;
    cc->Decrypt(keyPair.secretKey, y_cipher, &y);
    cc->Decrypt(keyPair.secretKey, x_cipher, &x);


    x->SetLength(encodedLength);
    y->SetLength(encodedLength);


 
    std::cout << "\nx: " << x->GetRealPackedValue() << std::endl;
    std::cout << "y: " << y->GetRealPackedValue() << std::endl;



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

