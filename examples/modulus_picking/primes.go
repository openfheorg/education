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