package cpabe

import (
	_ "crypto/sha256"
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
	LeafCy     [2]*pbc.Element //\forall y\in Y C_y =g^(q_y(0)), C'_y = H(att(y))^(q_y(0))
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

	//h = g^beta
	h := pairing.NewG1().PowZn(g, beta)
	//f = g^(1/beta)
	f := pairing.NewG1().PowZn(g, pairing.NewZr().Invert(beta))

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

func Encrypt(pk PublicKey, messageHash []byte, accesPolicy string) CipherText {

	rootNode := accesPolicyToAccessTree(pk, accesPolicy)
	encryptNode(pk, rootNode, nil)

	M := pk.Pairing.NewGT().SetFromHash(messageHash)
	return CipherText{
		RootNode: rootNode,
		Ctilda:   pk.Pairing.NewGT().Mul(M, pk.Pairing.NewGT().PowZn(pk.EggAlpha, rootNode.Polynomial[0])),
		C:        pk.Pairing.NewG1().PowZn(pk.H, rootNode.Polynomial[0]),
	}
}

func accesPolicyToAccessTree(pk PublicKey, accesPolicy string) *Node {

	children := make([]*Node, len(strings.Split(accesPolicy, " ")))
	for i, attr := range strings.Split(accesPolicy, " ") {
		children[i] = &Node{
			Type:      LeafNode,
			Attribute: attr,
			Index:     pk.Pairing.NewZr().SetInt32(int32(i + 1)),
		}
	}

	return &Node{
		Type:     AndNode,
		Children: children,
		Index:    pk.Pairing.NewZr().SetInt32(1),
	}
}

func encryptNode(pk PublicKey, node *Node, parent *Node) {
	if parent == nil { //rootNode
		s := pk.Pairing.NewZr().Rand()
		node.Polynomial = make([]*pbc.Element, len(node.Children))
		node.Polynomial[0] = s
		for i := 1; i < len(node.Children); i++ {
			node.Polynomial[i] = pk.Pairing.NewZr().Rand()
		}
	}
	if node.Type == LeafNode {
		node.Polynomial = make([]*pbc.Element, 1)
		node.Polynomial[0] = computePolynomialAtX(pk, parent.Polynomial, node.Index)
		node.LeafCy[0] = pk.Pairing.NewG1().PowZn(pk.G, node.Polynomial[0])
		node.LeafCy[1] = pk.Pairing.NewG1().PowZn(
			pk.Pairing.NewG1().SetFromHash([]byte(node.Attribute)),
			node.Polynomial[0])
	} else {
		for _, childNode := range node.Children {
			encryptNode(pk, childNode, node)
		}
	}
}

func computePolynomialAtX(pk PublicKey, polynomial []*pbc.Element, x *pbc.Element) *pbc.Element {

	val := polynomial[0]
	for i := 1; i < len(polynomial); i++ {
		xpowi := pk.Pairing.NewZr().PowZn(x, pk.Pairing.NewZr().SetInt32(int32(i)))
		val = pk.Pairing.NewZr().Add(val, pk.Pairing.NewZr().Mul(polynomial[i], xpowi))
	}
	return val
}

// Generate a private key for a user with the specified attributes
func KeyGen(pk PublicKey, msk MasterSecretKey, attributes []string) UserPrivateKey {

	r := pk.Pairing.NewZr().Rand()
	Dj := make(map[string][]*pbc.Element, len(attributes))

	for _, attr := range attributes {
		Dj[attr] = make([]*pbc.Element, 2)
		rj := pk.Pairing.NewZr().Rand()
		attrHash := pk.Pairing.NewG1().SetFromHash([]byte(attr))
		//Dj[i][0] = D_j = g^r*H(attrHash)^r
		Dj[attr][0] = pk.Pairing.NewG1().Mul(
			pk.Pairing.NewG1().PowZn(pk.G, r),
			pk.Pairing.NewG1().PowZn(attrHash, rj))
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

func Decrypt(cipthertext CipherText, userPrivateKey UserPrivateKey, pk PublicKey) *pbc.Element {
	A := runDecryptRecursively(cipthertext, userPrivateKey, cipthertext.RootNode) //TODO: Does not return A=eggrs
	pairing := userPrivateKey.D.Pairing()

	partOne := pairing.NewGT().Pair(cipthertext.C, userPrivateKey.D)
	partTwo := pairing.NewGT().Div(partOne, A)
	message := pairing.NewGT().Div(cipthertext.Ctilda, partTwo)
	return message
}

func runDecryptRecursively(cipthertext CipherText, userPrivateKey UserPrivateKey, node *Node) *pbc.Element {
	pairing := userPrivateKey.D.Pairing()
	if node.Type == LeafNode {
		Di, exists := userPrivateKey.Dj[node.Attribute]
		if exists {
			numerator := pairing.NewGT().Pair(Di[0], node.LeafCy[0])
			denominator := pairing.NewGT().Pair(Di[1], node.LeafCy[1])
			return pairing.NewGT().Div(numerator, denominator)
		} else {
			return pairing.NewGT().Rand() //attribute is not in the set
		}
	}
	childResult := runDecryptRecursively(cipthertext, userPrivateKey, node.Children[0])
	return childResult
}
