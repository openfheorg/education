

# Masking IP addresses
The paper is [here](https://www.overleaf.com/2391376879yhtknhgchcmr#8a6d0f) and the PDF  version of the paper is [here](https://github.com/LastingAsset/Innovation/blob/main/ip_masking/Privacy_aware_White_and_Black_List_Searching_for_Fraud_Analysis.pdf).

## Outline
In many areas of cybersecurity, we require access to Personally Identifiable Information (PII), such as names, postal addresses and email addresses. Unfortunately, this can lead to data breaches, especially in relation to data compliance regulations such as GDPR. An Internet Protocol (IP) address is an identifier that is assigned to a networked device to enable it to communicate over networks that use IP. Thus, in applications which are privacy-aware, we may aim to hide the IP address while aiming to determine if the address comes from a blacklist. One solution to this is to use homomorphic encryption to match an encrypted version of an IP address to a blacklisted network list. This matching allows us to encrypt the IP address and match it to an encrypted version of a blacklist. In this paper, we use the OpenFHE library \cite{OpenFHE} to encrypt network addresses with the BFV homomorphic encryption scheme. In order to assess the performance overhead of BFV, we implement a matching method using the OpenFHE library and compare it against partial homomorphic schemes, including Paillier, Damgard-Jurik, Okamoto-Uchiyama, Naccache-Stern and Benaloh. The main findings are that the BFV method compares favourably against the partial homomorphic 


## Introduction
Data regulations such as GDPR demand greater control of Personally Identifiable Information (PII). In many areas of cybersecurity, we provide linkages between entities and their associated IP address and where revealing an IP address can often identify a person or organisation that is involved in an investigation. With this, we could define a blacklist of networks that we need to identify if specific source IP address is included. One of the best ways to preserve privacy is with the use of homomorphic encryption, where we can encrypt both the target IP address and the blacklist and match them without revealing any additional information. 

Homomorphic encryption allows us to take the plaintexts $m_1$ and $m_2$ encrypt them using a secret key $k$, and perform operations such that:


$$
    \mathsf{Enc}_k(m_1 \circ m_2) = \mathsf{Enc}_k(m_1) \circ \mathsf{Enc}_k(m_2)  
$$

where $\circ$ could potentially be any operator, such as add, multiply, logical and, or logical or. With symmetric key encryption, we use the same key to decrypt as we do to encrypt. Overall, in analysing the IP matching problem, we need to either conduct bitwise homomorphic encryption or use a homomorphic subtraction method. 

In the past, partial homomorphic methods (PHE) have been used within privacy-aware methods for network analysis. This includes Tusa \emph{et al.}, who used the Paillier method to implement privacy-aware routing  \cite{tusa2023homomorphic}. These methods often have fairly good performance levels, but they do not implement a full range of mathematical operations and thus often fail to scale on a large-scale basis, especially where the full range of operations is required. 

This paper thus provides a new method for the usage of fully homomorphic encryption to match IP addresses to a blacklist of network addresses without revealing the IP address or the blacklist.  


## Fully Homomomorphic Encryption

Homomorphic encryption is a method of encryption which supports operations over encrypted data. In 1978, Rivest, Adleman, and Dertouzos \cite{rivest1978data} were the first to explore the possibilities of using the natural homomorphic properties of the RSA public key encryption scheme. The RSA scheme only supports the evaluation of arithmetic multiplication over ciphertexts. RSA is an example of Partial Homomorphic Encryption (PHE), which is a scheme that supports the evaluation of only a single type of operation on ciphertexts. Fully Homomorphic Encryption (FHE) can support every operation.  Since Gentry defined the first FHE method \cite{homenc} in 2009, there have been four main generations of homomorphic encryption:


* 1st generation: Gentry’s method uses integers and lattices. \cite{van2010fully} including the DGHV method.
* 2nd generation. Brakerski, Gentry and Vaikuntanathan’s (BGV) and Brakerski/ Fan-Vercauteren (BFV) use a Ring Learning With Errors approach \cite{brakerski2014efficient}.  The methods are similar to each other and have only a small difference between them.
* 3rd generation: These include DM (also known as FHEW) and CGGI (also known as TFHE) and support the integration of  Boolean circuits for small integers. 
* 4th generation: CKKS (Cheon, Kim, Kim, Song) and which uses floating-point numbers \cite{cheon2017homomorphic}.


### Public key or symmetric key
Homomorphic encryption can be implemented either with a symmetric key or an asymmetric (public) key. With symmetric key encryption, we use the same key to encrypt as we do to decrypt, whereas, with an asymmetric method, we use a public key to encrypt and a private key to decrypt.  In Figure \ref{fig:asym}, we use asymmetric encryption with a public key ($pk$) and a private key ($sk$). With this, Bob, Alice and Peggy will encrypt their data using the public key to produce ciphertext, and then we can operate on the ciphertext using arithmetic operations. The result can then be revealed by decrypting with the associated private key. We can also use symmetric key encryption, where the data is encrypted with a secret key, and which is then used to decrypt the data. In this case, the data processor (Trent) should not have access to the secret key, as they could decrypt the data from the providers.

![Asymmetric encryption (public key)](figures/hom_asymmetric.png)

## Coding

```C++
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
```



