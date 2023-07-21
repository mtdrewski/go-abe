package main

import (
	"fmt"

	"github.com/mtdrewski/go-abe/cpabe"
)

func main() {

	// Example usage
	pk, msk := cpabe.Setup()

	attributes := []string{"attr1", "attr2", "attr3"}
	userPrivateKey := cpabe.KeyGen(pk, msk, attributes)
	fmt.Println(userPrivateKey)

	// message := "Hello, World!"
	// accessPolicy := "attr1,attr2"

}
