
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




    string s1="10.1 20.5 30.1 1.2";

    if (argc>1) {
    	s1= (argv[1]);

	}

    CCParams<CryptoContextCKKSRNS> parameters;
    std::vector<double> dataInput = split(s1);


    parameters.SetBatchSize(16);

    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(59);
    parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);

    parameters.SetRingDim(16384);

    parameters.SetPREMode(INDCPA);
    parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);

    auto cc = GenCryptoContext(parameters);

    cc->Enable(PKE);  
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(PRE);


    auto aliceKey = cc->KeyGen();
 

    auto plaintext = cc->MakeCKKSPackedPlaintext(dataInput);
        plaintext->SetLength(s1.size());


    auto ciphertext1 = cc->Encrypt(aliceKey.publicKey, plaintext);


    Plaintext plaintextDec1;

    cc->Decrypt(aliceKey.secretKey, ciphertext1, &plaintextDec1);



    Plaintext plaintextDec;


    auto bobKey = cc->KeyGen();

    auto reencryptionKey = cc->ReKeyGen(aliceKey.secretKey, bobKey.publicKey);


    auto reEncryptedCT = cc->ReEncrypt(ciphertext1, reencryptionKey);  


    cc->Decrypt(bobKey.secretKey, reEncryptedCT, &plaintextDec);

    plaintextDec1->SetLength(dataInput.size());
    plaintextDec->SetLength(dataInput.size());


    cout << "Decrypted data before proxy encryption: " << plaintextDec1 << endl;
    cout<< "Decrypted data after proxy encryption: " << plaintextDec << endl;

    return 0;
}