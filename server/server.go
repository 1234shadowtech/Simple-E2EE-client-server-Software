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
	"strings"
	"sync"
)

type client struct {
	conn       net.Conn
	name       string
	publicKey  *big.Int
	privateKey *big.Int
	sessionKey []byte
}

var (
	clients   = make(map[net.Conn]*client)
	clientsMu sync.Mutex
)

// Using a 2048-bit prime number for better security
var prime, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

var generator = big.NewInt(2)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listener.Close()

	fmt.Println("E2EE Chat server running on :8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	c := &client{conn: conn}

	// Perform key exchange once connected with the client
	c.publicKey, c.privateKey = generateKeyPair()

	// Send public key to client
	fmt.Fprintf(conn, "%s\n", c.publicKey.String())

	// Receive client's public key
	clientPublicKey, _ := bufio.NewReader(conn).ReadString('\n')
	clientPublicKeyBig := new(big.Int)
	clientPublicKeyBig.SetString(strings.TrimSpace(clientPublicKey), 10)
	fmt.Print("recieved client key is", clientPublicKeyBig)

	// Compute shared secret
	sharedSecret := computeSharedSecret(clientPublicKeyBig, c.privateKey)

	c.sessionKey = deriveKey(sharedSecret.Bytes())

	// Get client name
	encryptedName, _ := bufio.NewReader(conn).ReadString('\n')
	decodedName, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(encryptedName))
	decryptedName, _ := decrypt(c.sessionKey, decodedName)
	c.name = string(decryptedName)

	clientsMu.Lock()
	clients[conn] = c
	clientsMu.Unlock()

	broadcastEncrypted(fmt.Sprintf("%s has joined the chat", c.name)) //once a client joins they are enlisted

	scanner := bufio.NewScanner(conn) //scanning for any message from the client
	for scanner.Scan() {
		message := scanner.Text()
		if message != "" {
			decodedMessage, _ := base64.StdEncoding.DecodeString(message)
			decrypted, _ := decrypt(c.sessionKey, decodedMessage)
			broadcastEncrypted(fmt.Sprintf("%s: %s", c.name, string(decrypted))) //a clients message is broadcasted to all the connected clients
		}
	}

	clientsMu.Lock()
	delete(clients, conn)
	clientsMu.Unlock()
	broadcastEncrypted(fmt.Sprintf("%s has left the chat", c.name)) //once a client leave
}

func broadcastEncrypted(message string) {
	fmt.Println(message) // Server-side logging
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for conn, c := range clients {
		encrypted, err := encrypt(c.sessionKey, []byte(message))
		if err != nil {
			fmt.Printf("Error encrypting message for %s: %v\n", c.name, err)
			continue
		}
		base64Encoded := base64.StdEncoding.EncodeToString(encrypted)
		_, err = fmt.Fprintf(conn, "%s\n", base64Encoded)
		if err != nil {
			fmt.Printf("Error sending message to %s: %v\n", c.name, err)
			delete(clients, conn)
			conn.Close()
		}
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
