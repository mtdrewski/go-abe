package main

import (
	"fmt"

	"github.com/mtdrewski/go-abe/cpabe"
)

// Example usage
func main() {

	//Step 1 - Setup public key and master secret key
	pk, msk := cpabe.Setup()

	//Step 2 - Based on public key and given set of attributes user has, generate key identifying with this set
	attributes := []string{"attr1", "attr2", "attr3"}
	userPrivateKey := cpabe.KeyGen(pk, msk, attributes)
	fmt.Println(userPrivateKey)

	//Step 3 - Encrypt the message based on the given accessPolicy and public key
	message := 123
	accessPolicy := "attr1 attr2"
	cipherText := cpabe.Encrypt(pk, message, accessPolicy)
	fmt.Println(cipherText.RootNode, "and", cipherText)
}
