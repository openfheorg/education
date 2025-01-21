
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


    string s1="10.1 20.5 30.1";
    string s2="10.2 20.6 30.2";
    string s3="10.3 20.4 33.3";

    if (argc>1) {
    	s1= (argv[1]);
	}

    if (argc>2) {
    	s2=(argv[2]);
	}

    if (argc>3) { 
    	s3=(argv[3]);
	}





    usint batchSize = 16;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(3);
    parameters.SetScalingModSize(59);





    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);


    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    KeyPair<DCRTPoly> bob;
    KeyPair<DCRTPoly> alice;
    KeyPair<DCRTPoly> carol;

    KeyPair<DCRTPoly> kpMultiparty;


    std::cout << "Generated keys for Bob, Alice and Carol" << std::endl;


    bob = cc->KeyGen();
    alice = cc->MultipartyKeyGen(bob.publicKey);
    carol = cc->MultipartyKeyGen(alice.publicKey);

    std::vector<double> data1 = split(s1);
    std::vector<double> data2 = split(s2);
    std::vector<double> data3 = split(s3);

    Plaintext d1 = cc->MakeCKKSPackedPlaintext(data1);
    Plaintext d2 = cc->MakeCKKSPackedPlaintext(data2);
    Plaintext d3 = cc->MakeCKKSPackedPlaintext(data3);


    Ciphertext<DCRTPoly> ciphertext1;
    Ciphertext<DCRTPoly> ciphertext2;
    Ciphertext<DCRTPoly> ciphertext3;

    ciphertext1 = cc->Encrypt(carol.publicKey, d1);
    ciphertext2 = cc->Encrypt(carol.publicKey, d2);
    ciphertext3 = cc->Encrypt(carol.publicKey , d3);


    Ciphertext<DCRTPoly> cttAdd12;
    Ciphertext<DCRTPoly> ctAdd123;

    cttAdd12  = cc->EvalAdd(ciphertext1, ciphertext2);
    ctAdd123 = cc->EvalAdd( cttAdd12, ciphertext3);

/// Decrypt ata with Bob, Alice and Carol

    Plaintext plaintextAddNew1;
    Plaintext plaintextAddNew2;
    Plaintext plaintextAddNew3;

    DCRTPoly partialPlaintext1;
    DCRTPoly partialPlaintext2;
    DCRTPoly partialPlaintext3;

    Plaintext plaintextMultipartyNew;

    const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams = bob.secretKey->GetCryptoParameters();
    const std::shared_ptr<typename DCRTPoly::Params> elementParams     = cryptoParams->GetElementParams();


    auto ciphertextBob = cc->MultipartyDecryptLead({ ctAdd123}, bob.secretKey);
    auto ciphertextAlice = cc->MultipartyDecryptMain({ ctAdd123}, alice.secretKey);
  
    auto ciphertextCarol = cc->MultipartyDecryptMain({ ctAdd123}, carol.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextBob[0]);
    partialCiphertextVec.push_back(ciphertextAlice[0]); 
    partialCiphertextVec.push_back(ciphertextCarol[0]);

    // partial decryptions are combined together
    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

    std::cout << "\n Original Plaintext: \n" << std::endl;
    std::cout << data1 << std::endl;
    std::cout << data2 << std::endl;
    std::cout << data3 << std::endl;

    plaintextMultipartyNew->SetLength(d1->GetLength());

    std::cout << "\n Trent recovers the plaintext: \n" << std::endl;
    std::cout << plaintextMultipartyNew << std::endl;

    std::cout << "\n";

    return 0;


}
