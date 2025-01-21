

#include "openfhe.h"

using namespace lbcrypto;

#include <iomanip>
#include <iostream>
using namespace std;

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

template <typename T>
std::vector<std::complex<double>> toComplexDoubleVec(const std::vector<T>& v) {
    std::vector<std::complex<double>> vec(v.size());
    std::transform(v.begin(), v.end(), vec.begin(), [](T elem) { return std::complex<double>(elem, 0); });

    return vec;
}

int main(int argc, char* argv[]) {


    int i=10;
    int modulusbits=12;
      int plaintextbits= 5;

    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> modulusbits;
      
	}


        auto Slots=32;
        auto sharing="shamir";
         int BATCH = 16;

        string s1="10.12 20.2 30.5 40.3 45.4 5.3 50.9 70.4 1.3 15.34 19.65 20.11 25.31";
        string s2="11.12 22.2 33.5 41.3 46.4 51.3 51.9 71.4 12.3 17.34 19.65 20.11 25.31";
        string s3="12.12 23.2 33.5 44.3 47.4 54.3 54.9 73.4 13.3 19.34 19.65 20.11 25.31";


    if (argc>1) {
    	s1= (argv[1]);

	}

    if (argc>1) {
    	s2= (argv[1]);

	}

    if (argc>1) {
    	s3= (argv[1]);

	}
        

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(59);


    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);
    


        const usint N = 3;  // number of parties
        const usint THRESH = 2;

        //  Key Generation Operation

        // Round 1 (party Bob)
        KeyPair<DCRTPoly> kp_Bob = cc->KeyGen();
        auto kp_Bobsmap          = cc->ShareKeys(kp_Bob.secretKey, N, THRESH, 1,"shamir");

        // Generate evalmult key part for Bob
        auto evalMultKey = cc->KeySwitchGen(kp_Bob.secretKey, kp_Bob.secretKey);

        // Generate evalsum key part for Bob
        cc->EvalSumKeyGen(kp_Bob.secretKey);
        auto evalSumKeys =
            std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp_Bob.secretKey->GetKeyTag()));

        // Round 2 (Alice)
        KeyPair<DCRTPoly> kp_Alice = cc->MultipartyKeyGen(kp_Bob.publicKey);

        auto kp_Alicesmap       = cc->ShareKeys(kp_Alice.secretKey, N, THRESH, 2, "shamir");
        auto evalMultKey2  = cc->MultiKeySwitchGen(kp_Alice.secretKey, kp_Alice.secretKey, evalMultKey);
        auto evalMultAB    = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp_Alice.publicKey->GetKeyTag());
        auto evalSumKeysB  = cc->MultiEvalSumKeyGen(kp_Alice.secretKey, evalSumKeys, kp_Alice.publicKey->GetKeyTag());
        auto evalSumKeysAB = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp_Alice.publicKey->GetKeyTag());

        KeyPair<DCRTPoly> kp_Carol = cc->MultipartyKeyGen(kp_Alice.publicKey);

        auto kp_Carolsmap         = cc->ShareKeys(kp_Carol.secretKey, N, THRESH, 3, "shamir");
        auto evalMultKey3    = cc->MultiKeySwitchGen(kp_Carol.secretKey, kp_Carol.secretKey, evalMultAB);
        auto evalMultABC     = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp_Carol.publicKey->GetKeyTag());
        auto evalMultCABC    = cc->MultiMultEvalKey(kp_Carol.secretKey, evalMultABC, kp_Carol.publicKey->GetKeyTag());
        auto evalSumKeysC    = cc->MultiEvalSumKeyGen(kp_Carol.secretKey, evalSumKeysB, kp_Carol.publicKey->GetKeyTag());
        auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysC, evalSumKeysAB, kp_Carol.publicKey->GetKeyTag());

        cc->InsertEvalSumKey(evalSumKeysJoin);

        auto evalMultBABC  = cc->MultiMultEvalKey(kp_Alice.secretKey, evalMultABC, kp_Carol.publicKey->GetKeyTag());
        auto evalMultBCABC = cc->MultiAddEvalMultKeys(evalMultCABC, evalMultBABC, evalMultCABC->GetKeyTag());
        auto evalMultAABC  = cc->MultiMultEvalKey(kp_Bob.secretKey, evalMultABC, kp_Carol.publicKey->GetKeyTag());
        auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAABC, evalMultBCABC, evalMultAABC->GetKeyTag());

        cc->InsertEvalMultKey({evalMultFinal});

      // Data encoding

        std::vector<double> vector1 = split(s1);
        std::vector<double> vector2 = split(s2);
        std::vector<double> vector3 = split(s3);

        // Expected results
        size_t encodedLength = vector1.size();
        std::vector<double> sumInput(encodedLength);
        std::vector<double> multInput(encodedLength);


        for (size_t i = 0; i < encodedLength; i++) {
            sumInput[i]  = vector1[i] + vector2[i] + vector3[i];
            multInput[i] = vector1[i] * vector3[i];
        }
        ///////////////////////


        Plaintext plaintext1;
        Plaintext plaintext2;
        Plaintext plaintext3;
        Plaintext plaintextevaladd;
        Plaintext plaintextevalmult;


            plaintext1 = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(vector1), 1, 0, nullptr, Slots);
            plaintext2 = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(vector2), 1, 0, nullptr, Slots);
            plaintext3 = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(vector3), 1, 0, nullptr, Slots);
            plaintextevaladd = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(sumInput), 1, 0, nullptr, Slots);
            plaintextevalmult =
                cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(multInput), 1, 0, nullptr, Slots);

       /// Encrypt plaintext


        Ciphertext<DCRTPoly> ciphertext1 = cc->Encrypt(kp_Carol.publicKey, plaintext1);
        Ciphertext<DCRTPoly> ciphertext2 = cc->Encrypt(kp_Carol.publicKey, plaintext2);
        Ciphertext<DCRTPoly> ciphertext3 = cc->Encrypt(kp_Carol.publicKey, plaintext3);

        /// Homomorphic operations

        Ciphertext<DCRTPoly> ciphertextAdd12  = cc->EvalAdd(ciphertext1, ciphertext2);
        Ciphertext<DCRTPoly> ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

        auto ciphertextMult    = cc->EvalMult(ciphertext1, ciphertext3);
        auto ciphertextEvalSum = cc->EvalSum(ciphertext3, BATCH);

       // Decrypt after homomorphic

        // Aborts - recovering Bob secret key from the shares assuming Bob dropped out
        PrivateKey<DCRTPoly> kp_Bob_recovered_sk = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
        cc->RecoverSharedKey(kp_Bob_recovered_sk, kp_Bobsmap, N, THRESH, sharing);

        // Distributed decryption

        // partial decryption by Bob
        auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextAdd123}, kp_Bob_recovered_sk);

        // partial decryption by Alice
        auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextAdd123}, kp_Alice.secretKey);

        // partial decryption by Carol
        auto ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextAdd123}, kp_Carol.secretKey);

        std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
        partialCiphertextVec.push_back(ciphertextPartial1[0]);
        partialCiphertextVec.push_back(ciphertextPartial2[0]);
        partialCiphertextVec.push_back(ciphertextPartial3[0]);

        // Two partial decryptions are combined
        Plaintext plaintextMultipartyNew;
        cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

        plaintextMultipartyNew->SetLength(plaintext1->GetLength());

        Plaintext plaintextMultipartyMult;
        ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextMult}, kp_Bob_recovered_sk);
        ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextMult}, kp_Alice.secretKey);
        ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextMult}, kp_Carol.secretKey);

        std::vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
        partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
        partialCiphertextVecMult.push_back(ciphertextPartial2[0]);
        partialCiphertextVecMult.push_back(ciphertextPartial3[0]);

        cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);

        plaintextMultipartyMult->SetLength(plaintext1->GetLength());


        std::cout <<  "Multiparty computation" << std::endl;
        std::cout << "Vector 1: " << vector1 << std::endl;
        std::cout << "Vector 2: " << vector2 << std::endl;
        std::cout << "Vector 3: " << vector3 << std::endl;

         std::cout <<   "\nMultiparty: addition" << std::endl;
        std::cout << "Expected: " << plaintextevaladd->GetCKKSPackedValue() << std::endl;
           std::cout << "Multiparty: " << plaintextMultipartyNew->GetCKKSPackedValue() << std::endl;     

        std::cout << "\nMultiparty: multiplication"  << std::endl;
        std::cout << "Expected: " << plaintextevalmult->GetCKKSPackedValue() << std::endl;
           std::cout << "Multiparty: " << plaintextMultipartyMult->GetCKKSPackedValue() << std::endl;     



}