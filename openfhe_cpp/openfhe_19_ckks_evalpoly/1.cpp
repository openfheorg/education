
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>

std::string ReadAndRemoveFirstTokenFromString (const char &separator, std::string& line) // faster than stringstream, at least for reading first element
 {
     auto found=line.find(separator);
     if (found==std::string::npos)
        {   string hold=line;
            line.clear();
            return hold;
        }
     else
     {
         std::string out=line.substr(0,found);
         line=line.substr(found+1,line.size());
         while (line[0]==' ') line=line.substr(1,line.size());
         if (out=="") out="-999999.0";
         return out;
     }
 }
vector<double> split(string a)
{

   std::vector <double> number;
   while(a.size()>0)
    {
     string num=ReadAndRemoveFirstTokenFromString(' ', a);
     if ((num=="\0") || (num.empty())) number.emplace_back(-999999.0);
     else number.emplace_back(stod(num));
     }
   return number;
}

int main(int argc, char *argv[]) {


    string s1="0.5 0.7 0.9";
    string s2="0.15 0.75 0 1";

    if (argc>1) {
    	s1= (argv[1]);

	}

    if (argc>2) {
    	s2=(argv[2]);

	}

    auto input= split(s1);
    auto coefficients1= split(s2);

    std::cout << "\n Poly Evaluation \n" << std::endl;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(5);
    parameters.SetScalingModSize(40);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    size_t encodedLength = input.size();

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);

    auto keyPair = cc->KeyGen();

    std::cout << "Generating evaluation key.";
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

    auto result = cc->EvalPoly(ciphertext1, coefficients1);


    Plaintext plaintextDec;

    cc->Decrypt(keyPair.secretKey, result, &plaintextDec);

    plaintextDec->SetLength(encodedLength);

 
    std::cout << "Input values: " << plaintext1 << std::endl;

    std::cout << "Coefficients: " << coefficients1 << std::endl;
    std::cout << "Results: :" << plaintextDec << std::endl;



    return 0;

}



