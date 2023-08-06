package main

import (
	"fmt"

	"github.com/mtdrewski/go-abe/cpabe"
)

// Example usage
func main() {

	//Step 1 - Setup public key and master secret key
	pk, msk := cpabe.Setup()
	//Step 2 - Encrypt the message based on the given accessPolicy and public key
	message := "Hello, World"
	accessPolicy := "attr1"
	cipherText := cpabe.Encrypt(pk, []byte(message), accessPolicy)

	//Step 3 - Based on the setup keys, given set of attributes user has, generate private key identified with this set
	attributes := []string{"attr1", "attr2", "attr3"}
	userPrivateKey := cpabe.KeyGen(pk, msk, attributes)

	//Step 4 - Decrypt the message based on generated private key
	decryptedMessage := cpabe.Decrypt(cipherText, userPrivateKey, pk)
	fmt.Println(decryptedMessage.Equals(pk.Pairing.NewGT().SetFromHash([]byte(message))))
}
