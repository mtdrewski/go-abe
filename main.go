package main

import (
	"os"

	"github.com/mtdrewski/go-abe/cpabe"
)

func main() {

	switch operation := os.Args[1]; operation {
	case "setup":
		pk, msk := cpabe.Setup()
		cpabe.ExportPublicKey(pk, "out/utils/public_key")
		cpabe.ExportMasterSecretKey(msk, "out/utils/master_secret_key")
	case "keygen":
		pk := cpabe.ImportPublicKey("out/utils/public_key")
		msk := cpabe.ImportMasterSecretKey("out/utils/master_secret_key", pk.Pairing)
		attributes := cpabe.ImportAttributes("in/utils/attributes")
		userPrivateKey := cpabe.KeyGen(pk, msk, attributes)
		cpabe.ExportUserPrivateKey(userPrivateKey, "out/utils/user_private_key")
	case "encrypt":
		pk := cpabe.ImportPublicKey("out/utils/public_key")
		accessPolicy := cpabe.ImportAccessPolicy("in/utils/access_policy")
		M := cpabe.EncryptFile("in/files/input_file.txt", "out/files/encrypted_input.bin", pk.Pairing)
		cipherText := cpabe.Encrypt(pk, M, &accessPolicy)
		cpabe.ExportCipherText(cipherText, "out/utils/ciphertext")
	case "decrypt":
		pk := cpabe.ImportPublicKey("out/utils/public_key")
		userPrivateKey := cpabe.ImportUserPrivateKey("out/utils/user_private_key", pk.Pairing)
		cipherText := cpabe.ImportCiphertext("out/utils/ciphertext", pk.Pairing)
		M := cpabe.Decrypt(cipherText, userPrivateKey, pk)
		cpabe.DecryptFile("out/files/encrypted_input.bin", "out/files/decrypted_file.txt", M)
	}
}
