
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <vector>
#include <algorithm>


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





    string s1="10 20 30";
    string s2="10 20 30";

    if (argc>1) {
    	s1= (argv[1]);

	}

    if (argc>2) {
    	s2=(argv[2]);

	}

    auto v1= split(s1);
    auto v2= split(s2);

    cout << v1 << endl;
        cout << v2 << endl;

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(20);
    parameters.SetSecurityLevel(lbcrypto::HEStd_NotSet);
    parameters.SetRingDim(1 << 7);
    uint32_t batchSize = parameters.GetRingDim() / 2;

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;
    cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    Plaintext plaintext1 = cc->MakePackedPlaintext(v1);
    auto ct1             = cc->Encrypt(keys.publicKey, plaintext1);

    Plaintext plaintext2 = cc->MakePackedPlaintext(v2);
    auto ct2            = cc->Encrypt(keys.publicKey, plaintext2);

    auto finalResult     = cc->EvalInnerProduct(ct1, ct2, batchSize);
    lbcrypto::Plaintext res;
    cc->Decrypt(keys.secretKey, finalResult, &res);
    res->SetLength(v1.size());
    auto final = res-> GetPackedValue()[0];

        std::cout <<  "v1=" << s1 << std::endl;
            std::cout <<  "v2=" << s2 << std::endl;
    std::cout <<  "Inner Product Result: " << final << std::endl;
    std::cout << "Expected value: " << inner_product(v1.begin(), v1.end(), v2.begin(), 0) << std::endl;

 

    return 0;
}