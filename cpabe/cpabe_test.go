package cpabe_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/mtdrewski/go-abe/cpabe"
)

func TestSetup(t *testing.T) {
	pk, msk := cpabe.Setup()

	//test if h == g^Beta
	gBeta := pk.Pairing.NewG1().PowZn(pk.G, msk.Beta)
	if !pk.H.Equals(gBeta) {
		t.Errorf("%d is not equal %d", pk.H, gBeta)
	}

	//test if f^b=g
	fBeta := pk.Pairing.NewG1().PowZn(pk.F, msk.Beta)
	if !pk.G.Equals(fBeta) {
		t.Errorf("%d is not equal %d", pk.G, fBeta)
	}

	//test e(g^alpha,g) == e(g,g)^alpha
	eggAlpha := pk.Pairing.NewGT().Pair(msk.Galpha, pk.G)
	if !eggAlpha.Equals(pk.EggAlpha) {
		t.Errorf("%d is not equal %d", eggAlpha, pk.EggAlpha)
	}
}

func TestExamples(t *testing.T) {
	exampleTestCase := []struct {
		name             string
		accessPolicy     cpabe.AccesPolicy
		userAttributes   []string
		canAccessMessage bool
	}{
		{
			name: "test1",
			accessPolicy: cpabe.AccesPolicy{
				ElemType: cpabe.AndNode,
				Children: []*cpabe.AccesPolicy{
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
						Children: []*cpabe.AccesPolicy{
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
			},
			userAttributes:   []string{"attr1", "attr2", "attr3", "attr4"},
			canAccessMessage: true,
		},
		{
			name: "test2",
			accessPolicy: cpabe.AccesPolicy{
				ElemType: cpabe.AndNode,
				Children: []*cpabe.AccesPolicy{
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr1",
					},
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr2",
					},
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr3",
					},
				},
			},
			userAttributes:   []string{"attr1", "attr2", "attr3", "attr4"},
			canAccessMessage: true,
		},
		{
			name: "test3",
			accessPolicy: cpabe.AccesPolicy{
				ElemType: cpabe.AndNode,
				Children: []*cpabe.AccesPolicy{
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr1",
					},
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr2",
					},
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr3",
					},
				},
			},
			userAttributes:   []string{"attr1"},
			canAccessMessage: false,
		},
		{
			name: "test4",
			accessPolicy: cpabe.AccesPolicy{
				ElemType: cpabe.OrNode,
				Children: []*cpabe.AccesPolicy{
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr1",
					},
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr2",
					},
					{
						ElemType:  cpabe.LeafNode,
						Attribute: "attr3",
					},
				},
			},
			userAttributes:   []string{"attr5"},
			canAccessMessage: false,
		},
	}
	for _, tt := range exampleTestCase {
		pk, msk := cpabe.Setup()
		cipherText := cpabe.Encrypt(pk, []byte(tt.name), &tt.accessPolicy)
		userPrivateKey := cpabe.KeyGen(pk, msk, tt.userAttributes)
		decryptedMessageHash := cpabe.Decrypt(cipherText, userPrivateKey, pk)

		if decryptedMessageHash.Equals(pk.Pairing.NewGT().SetFromHash([]byte(tt.name))) != tt.canAccessMessage {
			t.Errorf("%s failed", tt.name)
		}
	}
}

func TestBinaryTree(t *testing.T) {

	for depth := 1; depth < 7; depth++ {
		message := "Binary tree"
		pk, msk := cpabe.Setup()
		accessTree := createBinaryAccessTree(depth, 1)
		cipherText := cpabe.Encrypt(pk, []byte(message), accessTree)
		attributes := []string{}

		powerParam := int(math.Pow(2, float64(depth)))
		for i := powerParam; i < powerParam*2; i++ {
			attributes = append(attributes, "attr"+strconv.Itoa(i))
		}
		userPrivateKey := cpabe.KeyGen(pk, msk, attributes)
		decryptedMessageHash := cpabe.Decrypt(cipherText, userPrivateKey, pk)

		if !decryptedMessageHash.Equals(pk.Pairing.NewGT().SetFromHash([]byte(message))) {
			t.Errorf("Test fail with depth %d", depth)
		}
	}
}

func createBinaryAccessTree(depth int, index int) *cpabe.AccesPolicy {
	if depth == 0 {
		return &cpabe.AccesPolicy{
			ElemType:  cpabe.LeafNode,
			Attribute: "attr" + strconv.Itoa(index),
		}
	}
	leftNode := createBinaryAccessTree(depth-1, index*2)
	rightNode := createBinaryAccessTree(depth-1, index*2+1)
	return &cpabe.AccesPolicy{
		ElemType: cpabe.AndNode,
		Children: []*cpabe.AccesPolicy{leftNode, rightNode},
	}
}
