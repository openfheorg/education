# Picking the modulus value

The dream of near perfect data security is on the way, and at its core is the use of lattice based cryptography. This will bring new methods of public key encryption, and which are quantum robust. Examples of this are Kyber (for Key Exchange and Public Key Encryption) and Dilithium (for digital signatures). But, the rise of lattice-based cryptography will bring great opportunities for homomorphic encryption (HE). With this, we can process with encrypted values, such as:

$$
Enc(a) \circ Enc(b) = Enc(a \circ b)
$$

and where $$\circ$$ can be any arithmetic operator. The three main methods that are proposed are BFV, BGV and CKKS. With BFV and BGV, we can perform homomorphic encryption with integer values. Within OpenFHE, we have a cryptocontext, and which defines the size of the ring that we use. Overall, we have a plaintext modulus, and which will define the number of bits that are processed within the plaintext. If we process the ciphertext text, and use more than the bits set, we will overflow the result.

For this, we need to look at two core parameters:

* Plaintext modulus (p): This defines a prime number for the coefficients.
* Polynomial modulus (m): This defines the degree of the irreducible polynomial $$x^m+1$$. For example, if $$m$$ is 5, we have an irreducible polynomial of $$x^5+1$$.

If we had an $$m$$ of 5, the polynomial will have a form of:

$$
x^4+x^3+x^2+x+1
$$

and were x⁴ will be the highest degree of the polynomial. For p, we will define the maximum value for the coefficients of the polynomial factors. For example, if we have p=11, then:

$$
61x^3+12x \pmod {11}
$$

which equals:

$$
6x^3+x
$$

## Picking the modulus

In the following program, we use OpenFHE to homomorphically encrypt two values with a public key, and then homorphically add them, and then decrypt with the private key to produce the result [here]:

```C++
#include <openfhe.h>
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;
 
using namespace lbcrypto;

#include <sstream>



int main(int argc, char* argv[]) {

  uint64_t mod=1656225793;


    CCParams<CryptoContextBFVRNS> parameters;

    parameters.SetPlaintextModulus(mod);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetSecurityLevel(HEStd_128_classic);
   parameters.SetRingDim(16384/2);

 
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(LEVELEDSHE);

 
    KeyPair<DCRTPoly> keyPair;

    keyPair = cryptoContext->KeyGen();
 
    uint32_t x=5;
    uint32_t y=31;

    std::vector<int64_t>xval = {1};
 xval[0]=x;
    Plaintext xplaintext               = cryptoContext->MakePackedPlaintext(xval);

    std::vector<int64_t> yval = {1};
 yval[0]=y;
    Plaintext yplaintext               = cryptoContext->MakePackedPlaintext(yval);

    // Encrypt values
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, xplaintext);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, yplaintext);

    // Add ciphertext
    auto ciphertextMult     = cryptoContext->EvalAdd(ciphertext1, ciphertext2);

    // Decrypt result 
    Plaintext plaintextAddRes;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextAddRes);

    std::cout << "Modulus: : " << mod<< std::endl;

    std::cout << "\nx: " << xplaintext << std::endl;
    std::cout << "y: " << yplaintext << std::endl;


    // Output results
    std::cout << "\nResults" << std::endl;
    std::cout << "x+y= " << plaintextAddRes << std::endl;
 
    return 0;
}
```

A sample run gives:

```
Modulus: : 1656225793

x: ( 5 ... )
y: ( 31 ... )

Results
x+y= ( 36 ... )
```

In this case we use a modulus value of 1,656,225,793, but can we use any prime number? Well, the answer is no. Let’s try a 32-bit modulus of 2,122,221,719. When we run now, we get and exception of:

```
tnat::NativeIntegerT<long long unsigned int> >(): Please provide a 
primeModulus(q) and a cyclotomic number(m) satisfying the condition: 
(q-1)/m is an integer. The values of primeModulus = 2122221719 and m = 16384 
do not satisfy this condition
```

We can see that the value does not work, and where we need a 32-bit prime number where:

```
Mod((q-1),16384) == 0
```

If we try 1,656,225,793, we get:

```
>>> (1656225793-1)%16384
0

And 2,122,221,719:

>>> (2122221719-1)%16384
2198
```

So, how do we find prime numbers that work? Well, let’s search with Golang:

```Golang
package main

import (
 "crypto/rand"
 "fmt"
 "math"
 "math/big"
 "os"
 "strconv"

)

func main() {

 bits := 32


 argCount := len(os.Args[1:])

 if argCount > 0 {
  bits, _ = strconv.Atoi(os.Args[1])
 }

 if bits < 3 {
  fmt.Printf("We need at least three bits")
 }

 var p *big.Int
 checks := int(math.Max(float64(bits)/16, 8))
 for {

  p, _ = rand.Prime(rand.Reader, int(bits)-1)  


  if p.ProbablyPrime(checks)  {
   flag:=new(big.Int).Sub(p,big.NewInt(1))
   res:=new(big.Int).Mod(flag,big.NewInt(16384))

   if (res.Cmp(big.NewInt(0)) == 0) {
    fmt.Printf("%s\n", p)  

   }
  }
 }



}
```

If we try for 32-bit values, we get:

```
1690730497
1760051201
1655996417
1672314881
2037497857
1861681153
2125643777
2010382337
2138816513
1779957761
1967620097
1799012353
1874870273
1657602049
1805418497
1886846977
1652948993
1765982209
1627340801
1818099713
2010529793
1894023169
...
```

And, that is how you find out the plaintext modulus.
