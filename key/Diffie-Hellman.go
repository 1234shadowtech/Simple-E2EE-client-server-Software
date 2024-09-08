package k

import (
	"math/big"
)

var public_prime = big.NewInt(23)
var public_genrator = big.NewInt(5)

func encrypt_key(public_prime *big.Int, public_genrator *big.Int) (*big.Int, *big.Int) {
	private_key := big.NewInt(6)
	encoded_key_A := new(big.Int).Exp(public_genrator, private_key, public_prime)
	return encoded_key_A, private_key

}

func secret_key(n *big.Int, private_key *big.Int) *big.Int {
	master_key := new(big.Int).Exp(n, private_key, public_prime)
	return master_key
}
