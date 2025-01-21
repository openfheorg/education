
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
         if (out=="") out="-999999.9";
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


    string s1="10.12 20.2 30.5 40.3 45.4 50.3 55.9 70.4 11.3 12.34 19.65 20.11 25.31";


    if (argc>1) {
    	s1= (argv[1]);

	}


    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(40);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);


    KeyPair<DCRTPoly> kp = cc->KeyGen();

    std::vector<int32_t> indexList = {-2,-1,0,1,2, 3, 4, 5, 6, 7}; // Need keys for all the shifts

    cc->EvalRotateKeyGen(kp.secretKey, indexList);

    auto dataInput = split(s1);


    Plaintext inArray = cc->MakeCKKSPackedPlaintext(dataInput);

    auto ciphertext = cc->Encrypt(kp.publicKey, inArray);

    for (int32_t i = -2; i <= 7; i++) {
        auto permutedCiphertext = cc->EvalRotate(ciphertext, i);

        Plaintext resArray;

        cc->Decrypt(kp.secretKey, permutedCiphertext, &resArray);

        resArray->SetLength(dataInput.size());

        std::cout << "Rotated array - at index " << i << ": " << *resArray << std::endl;
    }
}