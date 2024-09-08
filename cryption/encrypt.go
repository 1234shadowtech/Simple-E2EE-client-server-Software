package crypting

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func encrypt_message(key, text []byte) ([]byte, error) {
	cipher_block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipher_text := make([]byte, aes.BlockSize+len(text))
	initial_vector := cipher_text[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, initial_vector); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(cipher_block, initial_vector)
	mode.CryptBlocks(cipher_text[aes.BlockSize:], text)

	return cipher_text, nil

}
