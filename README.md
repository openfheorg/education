# Homomorphic Encryption
This outlines a range of homomorphic encryption methods.  The demos of OpenFHE is [here](https://asecuritysite.com/openfhe/).

## OpenFHE
The site contains:

* open_cpp. This outlines C++ code for the OpenFHE library, and uses CKKS, BGV, BFV and MD. The examples are [here](https://github.com/billbuchanan/homomorphic_encryption/tree/main/openfhe_cpp).
* open_main. This outlines the main SEAL code for the OpenFHE SEAL library. The examples are [here](https://github.com/billbuchanan/homomorphic_encryption/tree/main/openfhe_main).

## Theory
With homomorphic encryption, we can operate on encrypted data. Overall, we could have three values (x, y and z), and then encrypt with a public key (pk). We can then perform a homomorphic addition. The result can then be decrypted using the associated private key:

 <p><img src="https://asecuritysite.com/public/homomorphic_01.png" width="800px" /></p>

Overall, we have seen four generations of homomorphic encryption:

* 1st generation: Gentry’s method uses integers and lattices including the DGHV method [1].
* 2nd generation. Brakerski, Gentry and Vaikuntanathan’s (BGV) work in 2014 for FHE using Learning With Errors [4].
* 3rd generation: Lattice-based methods as defined by Brakerski and Vaikuntanathan (BFV) [2,3].
* 4th generation: CKKS (Cheon, Kim, Kim, Song) and which uses floating-point numbers [5].

A presentation on related content is [here](https://youtu.be/eBF-Vnb7KiY?si=4cMDPraffB07Piey).

## Reference
[1] Van Dijk, M., Gentry, C., Halevi, S., & Vaikuntanathan, V. (2010). Fully homomorphic encryption over the integers. In Advances in Cryptology–EUROCRYPT 2010: 29th Annual International Conference on the Theory and Applications of Cryptographic Techniques, French Riviera, May 30–June 3, 2010. Proceedings 29 (pp. 24–43). Springer Berlin Heidelberg.

[2] Zvika Brakerski. Fully homomorphic encryption without modulus switching from classical gapsvp. In Annual Cryptology Conference, pages 868–886. Springer, 2012.

[3] Junfeng Fan and Frederik Vercauteren. Somewhat practical fully homomorphic encryption. 2012. https://eprint.iacr.org/2012/144.

[4] Brakerski, Z., Gentry, C., & Vaikuntanathan, V. (2014). (Leveled) fully homomorphic encryption without bootstrapping. ACM Transactions on Computation Theory (TOCT), 6(3), 1–36.

[5] Cheon, J. H., Kim, A., Kim, M., & Song, Y. (2017). Homomorphic encryption for arithmetic of approximate numbers. In Advances in Cryptology–ASIACRYPT 2017: 23rd International Conference on the Theory and Applications of Cryptology and Information Security, Hong Kong, China, December 3–7, 2017, Proceedings, Part I 23 (pp. 409–437). Springer International Publishing. 

