from lightphe import LightPHE
import sys
import io
import pytest

algorithms = [
  "RSA",
  "ElGamal",
  "Exponential-ElGamal",
  "Paillier",
  "Damgard-Jurik",
  "Okamoto-Uchiyama",
  "Benaloh",
  "Naccache-Stern",
  "Goldwasser-Micali",
  "EllipticCurve-ElGamal"
]

import time


hom_type="RSA"
a = 4294967294
b =  4294967292


if (len(sys.argv)>1):
        hom_type=str(sys.argv[1])

if (len(sys.argv)>2):
        a=int(sys.argv[2])

if (len(sys.argv)>3):
        b=int(sys.argv[3])

print(f"Method: {hom_type}")
print(f"a: {a}")
print(f"b: {b}\n")

import time
from timeit import timeit


print("Key gen")
t= time.time()
for i in range(0,100):
	cs = LightPHE(algorithm_name = hom_type)
t1 = time.time() - t 

print("Encrypt")
t= time.time()
for i in range(0,100):
	a1 = cs.encrypt(a)
	b1 = cs.encrypt(-b)
t2 = time.time() - t 


print("Decrypt")
print(f"\n== Try addition for {hom_type}==\n")
try:
	t= time.time()
	for i in range(0,100):
		c=a1+b1
		dec=cs.decrypt(c)
	t3 = time.time() - t 


	print(f"Cipher: {c}")
	print(f"{a}+{b} = {dec}")
except:
	print(f"\nAddition not possible for {hom_type}\n")


print(t1/100*1000,t2/100*1000,t3/100*1000)
