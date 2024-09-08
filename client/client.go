package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
)

var sessionKey []byte

// a public prime key and a generator is specified

// 2048-bit prime number for  security
var prime, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

var generator = big.NewInt(2)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080") // connecting to a local server as specified
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	// Perform key exchange
	publicKey, privateKey := generateKeyPair()

	// Receive server's public key
	serverPublicKey, _ := bufio.NewReader(conn).ReadString('\n')
	serverPublicKeyBig := new(big.Int)
	serverPublicKeyBig.SetString(strings.TrimSpace(serverPublicKey), 10)

	// Send our public key to server
	fmt.Fprintf(conn, "%s\n", publicKey.String())
	fmt.Print("client public key", publicKey)

	// Compute shared secret
	sharedSecret := computeSharedSecret(serverPublicKeyBig, privateKey)
	fmt.Print("recieved secret key", sharedSecret)
	sessionKey = deriveKey(sharedSecret.Bytes())
	fmt.Print("the session key after commputation is ", sessionKey)

	// Send encrypted name
	fmt.Print("Enter your name: ")
	name, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	name = strings.TrimSpace(name)
	encryptedName, _ := encrypt(sessionKey, []byte(name))
	base64EncodedName := base64.StdEncoding.EncodeToString(encryptedName)
	fmt.Fprintf(conn, "%s\n", base64EncodedName)

	go receiveMessages(conn)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		message := scanner.Text()
		if message == "/quit" {
			return
		}
		encrypted, _ := encrypt(sessionKey, []byte(message))
		base64Encoded := base64.StdEncoding.EncodeToString(encrypted)
		fmt.Fprintf(conn, "%s\n", base64Encoded)
	}
}

func receiveMessages(conn net.Conn) {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		base64Encoded := scanner.Text()
		encrypted, _ := base64.StdEncoding.DecodeString(base64Encoded)
		decrypted, err := decrypt(sessionKey, encrypted)
		if err != nil {
			fmt.Println("Error decrypting message:", err)
			continue
		}
		fmt.Println(string(decrypted))
	}
}

func generateKeyPair() (*big.Int, *big.Int) {
	privateKey, _ := rand.Int(rand.Reader, prime)
	publicKey := new(big.Int).Exp(generator, privateKey, prime)
	return publicKey, privateKey
}

func computeSharedSecret(publicKey, privateKey *big.Int) *big.Int {
	return new(big.Int).Exp(publicKey, privateKey, prime)
}

func deriveKey(sharedSecret []byte) []byte {
	hash := sha256.Sum256(sharedSecret)
	return hash[:]
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return unpad(ciphertext)
}

func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:(length - unpadding)], nil
}
