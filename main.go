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

	accessPolicy := cpabe.AccesPolicy{
		ElemType: cpabe.AndNode,
		Children: []cpabe.AccesPolicy{
			{
				ElemType:  cpabe.LeafNode,
				Attribute: "attr1",
			},
			{
				ElemType:  cpabe.LeafNode,
				Attribute: "attr2",
			},
			{
				ElemType: cpabe.OrNode,
				Children: []cpabe.AccesPolicy{
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr3",
					},
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr5",
					},
				},
			},
		},
	}

	cipherText := cpabe.Encrypt(pk, []byte(message), accessPolicy)

	//Step 3 - Based on the setup keys, given set of attributes user has, generate private key identified with this set
	attributes := []string{"attr1", "attr2", "attr3", "attr4"}
	userPrivateKey := cpabe.KeyGen(pk, msk, attributes)

	//Step 4 - Decrypt the message based on generated private key
	decryptedMessageHash := cpabe.Decrypt(cipherText, userPrivateKey, pk)
	fmt.Println(decryptedMessageHash.Equals(pk.Pairing.NewGT().SetFromHash([]byte(message))))
}
