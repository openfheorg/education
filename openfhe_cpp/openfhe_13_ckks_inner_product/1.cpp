
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



    lbcrypto::SecurityLevel securityLevel = lbcrypto::HEStd_NotSet;
    uint32_t dcrtBits                     = 59;
    uint32_t ringDim                      = 1 << 8;
    uint32_t batchSize                    = ringDim / 2;
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> parameters;
    uint32_t multDepth = 10;

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

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetRingDim(ringDim);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;
    cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(v1);
    auto ct1             = cc->Encrypt(keys.publicKey, plaintext1);

    Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(v2);
    auto ct2            = cc->Encrypt(keys.publicKey, plaintext2);

    auto finalResult     = cc->EvalInnerProduct(ct1, ct2, batchSize);
    lbcrypto::Plaintext res;
    cc->Decrypt(keys.secretKey, finalResult, &res);
    res->SetLength(v1.size());
    auto final = res->GetCKKSPackedValue()[0].real();

        std::cout <<  "v1=" << s1 << std::endl;
            std::cout <<  "v2=" << s2 << std::endl;
    std::cout <<  "Inner Product Result: " << final << std::endl;
    std::cout << "Expected value: " << inner_product(v1.begin(), v1.end(), v2.begin(), 0) << std::endl;

 

    return 0;
}