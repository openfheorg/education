

#include <openfhe.h>
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;

using namespace lbcrypto;

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

int main(int argc, char* argv[]) {

int mod=65537;

    string s1="10 20 30";
    string s2="10 20 30";


    if (argc>1) {
    	s1= (argv[1]);

	}

    if (argc>2) {
    	s2=(argv[2]);

	}

    std::vector<double> v1= split(s1);
    auto v2= split(s2);

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(40);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

PlaintextModulus p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
int n = cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
double q = cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble();
std::cout << "Plaintext modulus (p) = " << p << std::endl;
std::cout << "Polynomial degree (n) = " << n << std::endl;
std::cout << "Ciphertext modulus bitsize (log2 q) = " << log2(q) << std::endl;

KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();


cryptoContext->EvalMultKeysGen(keyPair.secretKey);
cryptoContext->EvalSumKeyGen(keyPair.secretKey);

 

Plaintext v1Plaintext  = cryptoContext->MakeCKKSPackedPlaintext(v1);

Plaintext pt_weights  = cryptoContext->MakeCKKSPackedPlaintext(v2);


std::cout << "Vector 1 (Cipher) = " << v1 << std::endl;
std::cout << "Vector 2 (Plaintext) = " << v2 << std::endl;


Ciphertext<DCRTPoly> ct_x = cryptoContext->Encrypt(keyPair.publicKey, v1Plaintext);


Ciphertext<DCRTPoly> resultCipher;
Plaintext result;


 auto ct_res =  cryptoContext->EvalInnerProduct(ct_x, pt_weights,v1.size());


 cryptoContext->Decrypt(keyPair.secretKey,  ct_res, &result);
 result->SetLength(1);

auto resOutput = result->GetCKKSPackedValue()[0].real();

 std::cout << "Inner product: v1 (Cipher)*v2 (Plain) =  = " << resOutput << std::endl;
}