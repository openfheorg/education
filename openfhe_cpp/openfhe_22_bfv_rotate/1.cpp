
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
         if (out=="") out="-999999";
         return out;
     }
 }
vector<int64_t> split(string a)
{

   std::vector <int64_t> number;
   while(a.size()>0)
    {
     string num=ReadAndRemoveFirstTokenFromString(' ', a);
     if ((num=="\0") || (num.empty())) number.emplace_back(-999999.0);
     else number.emplace_back(stoi(num));
     }
   return number;
}

int main(int argc, char *argv[]) {


    string s1="10 20 30 40 45 50 55 70 11 12 19 20 25";


    if (argc>1) {
    	s1= (argv[1]);

	}


     CCParams<CryptoContextBFVRNS> parameters;

    parameters.SetPlaintextModulus(65537);
    parameters.SetMaxRelinSkDeg(3);
    parameters.SetBatchSize(8);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    int32_t n = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;

    KeyPair<DCRTPoly> kp = cc->KeyGen();

    std::vector<int32_t> indexList = {-2,-1,0,1,2, 3, 4, 5, 6, 7}; // Need keys for all the shifts

    cc->EvalRotateKeyGen(kp.secretKey, indexList);

    auto vectorOfInts = split(s1);


    Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

    auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

    for (int32_t i = -2; i <= 7; i++) {
        auto permutedCiphertext = cc->EvalRotate(ciphertext, i);

        Plaintext intArrayNew;

        cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

        intArrayNew->SetLength(vectorOfInts.size());

        std::cout << "Rotated array - at index " << i << ": " << *intArrayNew << std::endl;
    }
}