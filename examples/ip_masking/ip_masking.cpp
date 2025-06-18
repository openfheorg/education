#include <openfhe.h>
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;
 
using namespace lbcrypto;

#include <sstream>
#define MAX_IP 100

unsigned long hex2dec(string hex)
{
    unsigned long result = 0;
    for (int i=0; i<hex.length(); i++) {
        if (hex[i]>=48 && hex[i]<=57)
        {
            result += (hex[i]-48)*pow(16,hex.length()-i-1);
        } else if (hex[i]>=65 && hex[i]<=70) {
            result += (hex[i]-55)*pow(16,hex.length( )-i-1);
        } else if (hex[i]>=97 && hex[i]<=102) {
            result += (hex[i]-87)*pow(16,hex.length()-i-1);
        }
    }
    return result;
}

string ipToStr2(uint32_t ip)
{
    stringstream ipStr;
    ipStr << (ip & 0xff) << ".";
    ipStr << ((ip >>8) & 0xff) << ".";
    ipStr << ((ip >>16) & 0xff) << ".";
    ipStr << ((ip >>24) & 0xff);
    return ipStr.str();
}
// https://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa
uint32_t convert( const std::string& ipv4Str )
{
    std::istringstream iss( ipv4Str );
    uint32_t ipv4 = 0;
    for( uint32_t i = 0; i < 4; ++i ) {
        uint32_t part;
        iss >> part;
        if ( iss.fail() || part > 255 ) {
            throw std::runtime_error( "Invalid IP address - Expected [0, 255]" );
        }
        // LSHIFT and OR all parts together with the first part as the MSB
        ipv4 |= part << ( 8 * ( 3 - i ) );
 
        // Check for delimiter except on last iteration
        if ( i != 3 ) {
            char delimiter;
            iss >> delimiter;
            if ( iss.fail() || delimiter != '.' ) {
                throw std::runtime_error( "Invalid IP address - Expected '.' delimiter" );
            }
        }
    }
    return ipv4;
}



int main(int argc, char* argv[]) {
 

  uint64_t mod=7137673217;


    CCParams<CryptoContextBFVRNS> parameters;

    parameters.SetPlaintextModulus(mod);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(16384);
   parameters.SetRingDim(16384/2);

 

    //  [plaintext modulus] * 4 * [ring dimension].
 
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
 //   cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

 
    KeyPair<DCRTPoly> keyPair;
 

    keyPair = cryptoContext->KeyGen();
 


 

    uint32_t network_address[MAX_IP];
    for (int i=0;i<MAX_IP;i++){
        network_address[i] = ((rand() & 0x7fffu)<<17 | (rand() & 0x7fffu)<<2 ) | (rand() & 0x7fffu)>>13;
        cout << ipToStr2(network_address[i]) << " ";
    }


    uint32_t ip_to_find=convert("2.3.4.5");
    ip_to_find=network_address[0];
    uint32_t subnet_mask=0xffffff00; 




// Encrypt ip to find
 uint32_t ipval = ip_to_find & subnet_mask;
 std::vector<int64_t>xval = {1};
 xval[0]=ipval;
 Plaintext xplaintext               = cryptoContext->MakePackedPlaintext(xval);
 auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, xplaintext);


lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext2[MAX_IP];

std::cout << "\nSetting up ciphertext values" << std::endl;

clock_t start = clock();

 for (int i=0;i<MAX_IP;i++) {
    uint32_t network = network_address[i] & subnet_mask;

    std::vector<int64_t> yval = {1};
	yval[0]=network;
    Plaintext yplaintext               = cryptoContext->MakePackedPlaintext(yval);

    ciphertext2[i] = cryptoContext->Encrypt(keyPair.publicKey, yplaintext);
    
 }

 auto end = clock();
 auto time = (double) (end-start) / CLOCKS_PER_SEC * 1000.0;
 std::cout << "\nTime to encrypt: " << time/1000 << " s" << std::endl;

 std::cout << "\nSetting up subtraction values" << std::endl;
 
  start = clock();

 for (int i=0;i<MAX_IP;i++) {

    auto ciphertextMult     = cryptoContext->EvalSub(ciphertext1, ciphertext2[i]);

    Plaintext plaintextAddRes;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextAddRes);


    plaintextAddRes->SetLength(1);
    auto res = plaintextAddRes->GetPackedValue();


    if (res[0]==0) {
        std::cout << "IP address is in subnet" << std::endl;
        std::cout << "Index: " << i << std::endl;
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextAddRes);
        std::cout << "Index: " << ipToStr2(plaintextAddRes->GetPackedValue()[0]) << std::endl;
    }

 }

  end = clock();
 time = (double) (end-start) / CLOCKS_PER_SEC * 1000.0;
std::cout << "\nTime to search: " << time/1000 << " s" << std::endl;

 
    return 0;
}
