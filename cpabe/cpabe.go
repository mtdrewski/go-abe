package cpabe

import (
	"crypto"
	_ "crypto/sha256"

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
type PrivateKey struct {
	D  *pbc.Element
	Dj [][]*pbc.Element
}

// Structure to represent the ciphertext
type Ciphertext struct {
	C *pbc.Element
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
func KeyGen(pk PublicKey, msk MasterSecretKey, attributes []string) PrivateKey {

	r := pk.Pairing.NewZr().Rand()
	Dj := make([][]*pbc.Element, len(attributes))
	for i, attr := range attributes {
		Dj[i] = make([]*pbc.Element, 2)
		rj := pk.Pairing.NewZr().Rand()
		attrHash := pk.Pairing.NewG1().SetFromStringHash(attr, crypto.SHA256.New())
		Dj[i][0] = pk.Pairing.NewG1().Mul(
			pk.Pairing.NewG1().PowZn(pk.G, r),
			pk.Pairing.NewG1().PowZn(attrHash, r))
		Dj[i][1] = pk.Pairing.NewG1().PowZn(pk.G, rj)
	}

	return PrivateKey{
		D:  r,
		Dj: Dj,
	}
}
