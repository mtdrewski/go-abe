package cpabe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"log"
	"os"

	"github.com/Nik-U/pbc"
)

type PublicKeyExport struct {
	Params   string
	G        []byte
	H        []byte
	F        []byte
	EggAlpha []byte
}

type MasterSecretKeyExport struct {
	Beta   []byte
	Galpha []byte
}

type UserPrivateKeyExport struct {
	Attributes []string
	D          []byte
	Dj         map[string][][]byte
}

type NodeExport struct {
	Type       NodeType
	Attribute  string
	Children   []*NodeExport
	Index      []byte
	Polynomial [][]byte
	LeafCy     [2][]byte //\forall y\in Y C_y =g^(q_y(0)), C'_y = H(att(y))^(q_y(0))
}

type CipherTextExport struct {
	RootNode *NodeExport
	Ctilda   []byte
	C        []byte
}

func ExportPublicKey(pk PublicKey, path string) {
	pke := PublicKeyExport{
		Params:   pk.Params.String(),
		G:        pk.G.Bytes(),
		H:        pk.H.Bytes(),
		F:        pk.F.Bytes(),
		EggAlpha: pk.EggAlpha.Bytes(),
	}
	file_pk, _ := json.MarshalIndent(pke, "", " ")
	_ = os.WriteFile(path, file_pk, 0644)
}

func ExportMasterSecretKey(msk MasterSecretKey, path string) {
	mske := MasterSecretKeyExport{
		Beta:   msk.Beta.Bytes(),
		Galpha: msk.Galpha.Bytes(),
	}
	file_msk, _ := json.MarshalIndent(mske, "", " ")
	_ = os.WriteFile(path, file_msk, 0644)
}

func ExportUserPrivateKey(upk UserPrivateKey, path string) {

	Dj_export := make(map[string][][]byte, len(upk.Attributes))

	for key, element := range upk.Dj {
		Dj_export[key] = make([][]byte, 2)
		Dj_export[key][0] = element[0].Bytes()
		Dj_export[key][1] = element[1].Bytes()
	}

	upke := UserPrivateKeyExport{
		Attributes: upk.Attributes,
		D:          upk.D.Bytes(),
		Dj:         Dj_export,
	}
	json_upke, _ := json.MarshalIndent(upke, "", " ")
	_ = os.WriteFile(path, json_upke, 0644)
}

func ExportCipherText(cipher CipherText, path string) {

	rootExport := iterateOverTreeExport(cipher.RootNode)
	cte := CipherTextExport{
		RootNode: rootExport,
		Ctilda:   cipher.Ctilda.Bytes(),
		C:        cipher.C.Bytes(),
	}
	file_cipherexport, _ := json.MarshalIndent(cte, "", " ")
	_ = os.WriteFile(path, file_cipherexport, 0644)
}

func iterateOverTreeExport(node *Node) *NodeExport {

	polynomial := make([][]byte, len(node.Polynomial))
	for i, poly := range node.Polynomial {
		polynomial[i] = poly.Bytes()
	}

	if node.Type == LeafNode {
		return &NodeExport{
			Type:       LeafNode,
			Attribute:  node.Attribute,
			Index:      node.Index.Bytes(),
			Polynomial: polynomial,
			LeafCy:     [2][]byte{node.LeafCy[0].Bytes(), node.LeafCy[1].Bytes()},
		}
	}
	children := make([]*NodeExport, len(node.Children))
	for i, child := range node.Children {
		children[i] = iterateOverTreeExport(child)
	}

	return &NodeExport{
		Type:       node.Type,
		Attribute:  node.Attribute,
		Children:   children,
		Index:      node.Index.Bytes(),
		Polynomial: polynomial,
	}
}

func ImportPublicKey(path string) PublicKey {
	pke := PublicKeyExport{}

	file, _ := os.ReadFile(path)
	_ = json.Unmarshal([]byte(file), &pke)

	params, _ := pbc.NewParamsFromString(pke.Params)
	pairing, _ := pbc.NewPairingFromString(pke.Params)
	return PublicKey{
		Params:   params,
		Pairing:  pairing,
		G:        pairing.NewG1().SetBytes(pke.G),
		H:        pairing.NewG1().SetBytes(pke.H),
		F:        pairing.NewG1().SetBytes(pke.F),
		EggAlpha: pairing.NewGT().SetBytes(pke.EggAlpha),
	}
}

func ImportMasterSecretKey(path string, pairing *pbc.Pairing) MasterSecretKey {
	mske := MasterSecretKeyExport{}
	file, _ := os.ReadFile(path)
	_ = json.Unmarshal([]byte(file), &mske)

	return MasterSecretKey{
		Beta:   pairing.NewZr().SetBytes(mske.Beta),
		Galpha: pairing.NewG1().SetBytes(mske.Galpha),
	}
}

func ImportUserPrivateKey(path string, pairing *pbc.Pairing) UserPrivateKey {
	upke := UserPrivateKeyExport{}
	file, _ := os.ReadFile(path)
	_ = json.Unmarshal([]byte(file), &upke)

	Dj := make(map[string][]*pbc.Element, len(upke.Dj))
	for key, elem := range upke.Dj {
		Dj[key] = make([]*pbc.Element, 2)
		Dj[key][0] = pairing.NewG1().SetBytes(elem[0])
		Dj[key][1] = pairing.NewG1().SetBytes(elem[1])
	}

	return UserPrivateKey{
		Attributes: upke.Attributes,
		D:          pairing.NewG1().SetBytes(upke.D),
		Dj:         Dj,
	}
}

func ImportCiphertext(path string, pairing *pbc.Pairing) CipherText {
	cite := CipherTextExport{}
	file, _ := os.ReadFile(path)
	_ = json.Unmarshal([]byte(file), &cite)
	root := iterateOverTreeImport(cite.RootNode, pairing)
	return CipherText{
		RootNode: root,
		Ctilda:   pairing.NewGT().SetBytes(cite.Ctilda),
		C:        pairing.NewG1().SetBytes(cite.C),
	}
}

func iterateOverTreeImport(node *NodeExport, pairing *pbc.Pairing) *Node {

	polynomial := make([]*pbc.Element, len(node.Polynomial))
	for i, poly := range node.Polynomial {
		polynomial[i] = pairing.NewZr().SetBytes(poly)
	}

	if node.Type == LeafNode {
		return &Node{
			Type:       LeafNode,
			Attribute:  node.Attribute,
			Index:      pairing.NewZr().SetBytes(node.Index),
			Polynomial: polynomial,
			LeafCy:     [2]*pbc.Element{pairing.NewG1().SetBytes(node.LeafCy[0]), pairing.NewG1().SetBytes(node.LeafCy[1])},
		}
	}
	children := make([]*Node, len(node.Children))
	for i, child := range node.Children {
		children[i] = iterateOverTreeImport(child, pairing)
	}

	return &Node{
		Type:       node.Type,
		Attribute:  node.Attribute,
		Children:   children,
		Index:      pairing.NewZr().SetBytes(node.Index),
		Polynomial: polynomial,
	}
}

func ImportAttributes(path string) []string {
	attributes := []string{}
	file, _ := os.ReadFile(path)
	_ = json.Unmarshal([]byte(file), &attributes)
	return attributes
}

func ImportAccessPolicy(path string) AccesPolicy {
	accessPolicy := AccesPolicy{}
	file, _ := os.ReadFile(path)
	_ = json.Unmarshal([]byte(file), &accessPolicy)

	return accessPolicy
}

func EncryptFile(input_path string, output_path string, pairing *pbc.Pairing) *pbc.Element {
	plainText, _ := os.ReadFile(input_path)
	M := pairing.NewGT().SetFromHash(plainText)
	block, _ := aes.NewCipher(M.Bytes()[:16])
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)
	os.WriteFile(output_path, cipherText, 0777)
	return M
}

func DecryptFile(input_path string, output_path string, M *pbc.Element) {

	cipherText, _ := os.ReadFile(input_path)
	block, _ := aes.NewCipher(M.Bytes()[:16])
	gcm, _ := cipher.NewGCM(block)
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("decrypt file err: %v", err.Error())
	}
	os.WriteFile(output_path, plainText, 0777)
}
