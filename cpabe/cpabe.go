package cpabe

import (
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"strings"

	"github.com/Nik-U/pbc"
)

// Structure to represent the public key
type PublicKey struct {
	Pairing  *pbc.Pairing
	G        *pbc.Element
	H        *pbc.Element
	F        *pbc.Element
	EggAlpha *pbc.Element
}

// Structure to represent the master secret key
type MasterSecretKey struct {
	Beta   *pbc.Element
	Galpha *pbc.Element
}

// Structure to represent the user's private key
type UserPrivateKey struct {
	Attributes []string
	D          *pbc.Element
	Dj         map[string][]*pbc.Element
}

type NodeType string

const (
	AndNode  NodeType = "AndNode"
	OrNode   NodeType = "OrNode"
	LeafNode NodeType = "LeafNode"
)

type Node struct {
	Type       NodeType
	Attribute  string
	Children   []*Node
	Index      *pbc.Element
	Polynomial []*pbc.Element
	LeafCy     [2]*pbc.Element
}

type CipherText struct {
	RootNode *Node
	Ctilda   *pbc.Element
	C        *pbc.Element
}

// Generate public and master secret keys
func Setup() (PublicKey, MasterSecretKey) {

	pairing := pbc.GenerateA(160, 512).NewPairing()
	g := pairing.NewG1().Rand()

	alpha := pairing.NewZr().Rand()
	beta := pairing.NewZr().Rand()
	betaInvert := pairing.NewZr().Invert(beta)

	//h = g^beta
	h := pairing.NewG1().PowZn(g, beta)
	//f = g^(1/beta)
	f := pairing.NewG1().PowZn(g, betaInvert)

	//eggAlpha = e(g,g)^alpha
	eggAlpha := pairing.NewGT().PowZn(pairing.NewGT().Pair(g, g), alpha)

	//gAlpha = g^alpha
	gAlpha := pairing.NewG1().PowZn(g, alpha)

	pk := PublicKey{
		Pairing:  pairing,
		G:        g,
		H:        h,
		F:        f,
		EggAlpha: eggAlpha,
	}

	msk := MasterSecretKey{
		Beta:   beta,
		Galpha: gAlpha,
	}
	return pk, msk
}

// Generate a private key for a user with the specified attributes
func KeyGen(pk PublicKey, msk MasterSecretKey, attributes []string) UserPrivateKey {

	r := pk.Pairing.NewZr().Rand()
	Dj := make(map[string][]*pbc.Element, len(attributes))

	for _, attr := range attributes {
		Dj[attr] = make([]*pbc.Element, 2)
		rj := pk.Pairing.NewZr().Rand()
		attrHash := pk.Pairing.NewG1().SetFromStringHash(attr, crypto.SHA256.New())
		//Dj[i][0] = D_j = g^r*H(attrHash)^r
		Dj[attr][0] = pk.Pairing.NewG1().Mul(
			pk.Pairing.NewG1().PowZn(pk.G, r),
			pk.Pairing.NewG1().PowZn(attrHash, r))
		//Dj[i][1] = D_j' = g^rj
		Dj[attr][1] = pk.Pairing.NewG1().PowZn(pk.G, rj)
	}

	// g^(alpha+r)
	gAlphaR := pk.Pairing.NewG1().Mul(msk.Galpha, pk.Pairing.NewG1().PowZn(pk.G, r))
	return UserPrivateKey{
		Attributes: attributes,
		D:          pk.Pairing.NewG1().PowZn(gAlphaR, pk.Pairing.NewZr().Invert(msk.Beta)), //g^(alpha+r)/beta
		Dj:         Dj,
	}
}

func Encrypt(pk PublicKey, message int, accesPolicy string) CipherText {

	rootNode := accesPolicyToAccessTree(accesPolicy, pk.Pairing)
	s := pk.Pairing.NewZr().Rand()

	if rootNode.Type == AndNode {
		rootNode.Polynomial = make([]*pbc.Element, len(rootNode.Children))
		rootNode.Polynomial[0] = s
		for i := 1; i < len(rootNode.Children); i++ {
			rootNode.Polynomial[i] = pk.Pairing.NewZr().Rand()
		}

		for _, childNode := range rootNode.Children {
			if childNode.Type == LeafNode {
				childNode.Polynomial = make([]*pbc.Element, 1)
				childNode.Polynomial[0] = computePolynomialAtX(rootNode.Polynomial, childNode.Index, pk.Pairing)
				childNode.LeafCy[0] = pk.Pairing.NewG1().PowZn(pk.G, childNode.Polynomial[0])
				childNode.LeafCy[1] = pk.Pairing.NewG1().PowZn(
					pk.Pairing.NewG1().SetFromStringHash(childNode.Attribute, crypto.SHA256.New()),
					childNode.Polynomial[0])
			} else {
				fmt.Println("oops, not implemented yet!")
			}
		}
	} else {
		fmt.Println("oops, not implemented yet!")
	}

	return CipherText{
		RootNode: rootNode,
		Ctilda: pk.Pairing.NewGT().MulInt32(
			pk.Pairing.NewGT().PowZn(pk.EggAlpha, s),
			int32(message)),
		C: pk.Pairing.NewG1().PowZn(pk.H, s),
	}
}

func accesPolicyToAccessTree(accesPolicy string, pairing *pbc.Pairing) *Node {

	children := make([]*Node, len(strings.Split(accesPolicy, " ")))
	for i, attr := range strings.Split(accesPolicy, " ") {
		children[i] = &Node{
			Type:      LeafNode,
			Attribute: attr,
			Index:     pairing.NewZr().SetInt32(int32(i + 1)),
		}
	}

	return &Node{
		Type:     AndNode,
		Children: children,
		Index:    pairing.NewZr().SetInt32(1),
	}
}

func computePolynomialAtX(polynomial []*pbc.Element, x *pbc.Element, pairing *pbc.Pairing) *pbc.Element {

	val := polynomial[0]
	for i := 1; i < len(polynomial); i++ {
		val = pairing.NewZr().Add(val,
			pairing.NewZr().Mul(polynomial[i],
				pairing.NewZr().PowZn(x, pairing.NewZr().SetInt32(int32(i)))))
	}
	return val
}

func Decrypt(cipthertext CipherText, userPrivateKey UserPrivateKey) int {
	//	result := runDecryptRecursively(cipthertext, userPrivateKey, cipthertext.RootNode)

	return 0
}

/*
func runDecryptRecursively(cipthertext CipherText, userPrivateKey UserPrivateKey, node *Node) *pbc.Element {
	pairing := userPrivateKey.D.Pairing()
	if node.Type == LeafNode {
		numerator := pairing.NewGT().Pair()
		denominator :=
	}
	childResult := runDecryptRecursively(cipthertext, userPrivateKey, node.Children[0])
	return childResult

}
*/
