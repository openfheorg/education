#include <openfhe.h>
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;
 
using namespace lbcrypto;

#include <sstream>

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
 
uint64_t mod=35184372744193;
 
    string ip1="2.3.4.5";
    string network_address="2.3.4.7";
    uint32_t subnet_mask=0xffffff00; 
 
    if (argc>1) {
    	ip1= (argv[1]);
 
	}
    if (argc>2) {
    	network_address= (argv[2]);
 
	}
    if (argc>3) {
    	 subnet_mask =hex2dec(argv[3]) ;
    
	}


 clock_t start = clock();

    uint32_t ipval = convert(ip1)  & subnet_mask;
    uint32_t network = (convert(network_address) ) & subnet_mask;
 
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(mod);
    parameters.SetMultiplicativeDepth(0);
 
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

 
    KeyPair<DCRTPoly> keyPair;
 
    // Generate key pair
    keyPair = cryptoContext->KeyGen();

clock_t end = clock();
double time = (double) (end-start) / CLOCKS_PER_SEC * 1000.0;
std::cout << "\nTime" << time << " ms" << std::endl;

start = clock();

    std::vector<int64_t>xval = {1};
	xval[0]=ipval;
    Plaintext xplaintext               = cryptoContext->MakePackedPlaintext(xval);
 
    std::vector<int64_t> yval = {1};
	yval[0]=network;
    Plaintext yplaintext               = cryptoContext->MakePackedPlaintext(yval);
 
    // Encrypt values
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, xplaintext);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, yplaintext);

end = clock();
time = (double) (end-start) / CLOCKS_PER_SEC * 1000.0;
std::cout << "\nTime to encrypt" << time << " ms" << std::endl;

start = clock(); 
    // Add ciphertext
    auto ciphertextMult     = cryptoContext->EvalSub(ciphertext1, ciphertext2);


    // Decrypt result 
    Plaintext plaintextAddRes;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextAddRes);

end = clock();
time = (double) (end-start) / CLOCKS_PER_SEC * 1000.0;
std::cout << "\nTime to encrypt" << time << " ms" << std::endl;
 
    std::cout << "Modulus: : " << mod<< std::endl;
 
    std::cout << "\nIP1: " << xplaintext << std::endl;
    std::cout << "IP2: " << yplaintext << std::endl;

 
    // Output results
    std::cout << "\nDifference" << std::endl;

    plaintextAddRes->SetLength(1);
    auto res = plaintextAddRes->GetPackedValue();
    std::cout << "Subnet test= " << res[0] << std::endl;

    if (res[0]==0) std::cout << "IP address is in subnet" << std::endl;
    else std::cout << "IP address is not in the subnet" << std::endl;

 
    return 0;
}
