package crypting

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func decrypt_message(key, cipher_text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipher_text) < aes.BlockSize {
		return nil, fmt.Errorf("cipher text too short")
	}
	initial_vector := cipher_text[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, initial_vector)
	mode.CryptBlocks(cipher_text, cipher_text)
	return cipher_text, nil

}
