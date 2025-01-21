
#include <openfhe.h>

using namespace lbcrypto;
using namespace std;

#include <iostream>
#include <sstream>
#include <cstdint>
#include  <bitset>
#include <array>

LWECiphertext ANDGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(AND, a, b);
}
LWECiphertext NANDGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(NAND, a, b);
}
LWECiphertext ORGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(OR, a, b);
}
LWECiphertext XORGATE(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b) {
    return cc.EvalBinGate(XOR, a, b);
}
LWECiphertext NOTGATE(BinFHEContext cc, LWECiphertext  a) {
    return cc.EvalNOT(a);
}



tuple <LWECiphertext,LWECiphertext>  HA(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b ){
	auto sum=XORGATE(cc,a,b);
	auto carryout=ANDGATE(cc,a,b);
	return make_tuple(sum,carryout);
}
tuple <LWECiphertext,LWECiphertext> FA(BinFHEContext cc, LWECiphertext  a,LWECiphertext  b, LWECiphertext  cin ) {
   LWECiphertext sum1,sum,c1,c2;

    tie(sum1,c1)=HA(cc,a,b);
    tie(sum,c2)=HA(cc,sum1,cin);
   auto carryout=ORGATE(cc,c1,c2);
   return make_tuple(sum,carryout);

}

array<int,4>  tobits(int a) {

    array<int, 4>  arr1;
    arr1[0]=a&1;
    arr1[1]=(a&2)>> 1;
    arr1[2]=(a&4)>> 2;
    arr1[3]=(a&8)>>3;
    return (arr1);

}





int main(int argc, char *argv[]) {

     int64_t val1=5;
     int64_t val2=3;



    if (argc>1) {
    	std::istringstream iss(argv[1]);
    	iss >> val1;
	}
        if (argc>2) {
    	std::istringstream iss(argv[2]);
    	iss >> val2;
	}







    auto cc = BinFHEContext();
    // We can use TOY, MEDIUM, STD192, and STD256.
    cc.GenerateBinFHEContext(TOY);

    auto sk = cc.KeyGen();

    std::cout << "Homomorphic four bit adder with carry out" << std::endl;
    std::cout << "Creating bootstrapping keys..." << std::endl;

    cc.BTKeyGen(sk);

    std::cout << "Completed key generation." << std::endl;


    auto bin1 = tobits(val1);
    auto bin2= tobits(val2);

    cout <<"Val1="<< val1 << " Binary: "<< bin1[3] << bin1[2] << bin1[1] << bin1[0] << endl;
    cout <<"Val2="<< val2 << " Binary: "<< bin2[3] << bin2[2] << bin2[1] << bin2[0] << endl;
    
    auto bin1_0 = cc.Encrypt(sk, bin1[0]);
     auto bin1_1 = cc.Encrypt(sk, bin1[1]);
   auto bin1_2 = cc.Encrypt(sk, bin1[2]);
    auto bin1_3 = cc.Encrypt(sk, bin1[3]);

        auto bin2_0 = cc.Encrypt(sk, bin2[0]);
     auto bin2_1 = cc.Encrypt(sk, bin2[1]);
   auto bin2_2 = cc.Encrypt(sk, bin2[2]);
    auto bin2_3 = cc.Encrypt(sk, bin2[3]);

        auto c_carryin = cc.Encrypt(sk, 0);


LWECiphertext c_sum1,c_carryout,c_sum2,c_sum3,c_sum4;

    tie(c_sum1,c_carryout)=FA(cc,bin1_0,bin2_0,c_carryin );
    tie(c_sum2,c_carryout)=FA(cc,bin1_1,bin2_1,c_carryout );
    tie(c_sum3,c_carryout)=FA(cc,bin1_2,bin2_2,c_carryout );
    tie(c_sum4,c_carryout)=FA(cc,bin1_3,bin2_3,c_carryout );





    LWEPlaintext result1,result2,result3,result4,result5;

    cc.Decrypt(sk, c_sum1, &result1);
        cc.Decrypt(sk, c_sum2, &result2);
            cc.Decrypt(sk, c_sum3, &result3);
                cc.Decrypt(sk, c_sum4, &result4);
                                cc.Decrypt(sk, c_carryout, &result5);



    printf("a=%d, b=%d\n",val1,val2);  
    printf("Carry out=%d Result=%d%d%d%d\n",result5,result4,result3,result2,result1);



    return 0;


}
